//! Stateless Codex App Server stdio/JSONL adapter.
//!
//! The adapter translates the bounded provider wire into the provider-neutral
//! A-01 contracts.  It never starts a child, owns canonical state, creates an
//! authority envelope, or treats a provider terminal message as task finish.
//! Physical execution is exclusively delegated to the P-03 [`ProcessExecutor`]
//! supplied by the caller.

use std::sync::Arc;

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentAttempt, AgentLaunchRequest, AgentResult, AgentWorkUnitBrief,
    AssistantDeltaObservation, AttemptId, AttemptState, AuthorityEnvelope, CONTRACT_VERSION,
    CancelReason, CancellationState, ClockReading, ContinuityKind, EffectCeiling, ErrorObservation,
    EventCursor, EventId, ExecutionOutcome, ExecutionStartedObservation, ExecutionUnit,
    HOST_EVENT_CONTRACT_VERSION, HOST_EVENT_DIGEST_ALGORITHM, HostEventDeliveryDisposition,
    HostEventNormalizationReceipt, HostEventPrivacyClass, LowercaseSha256, NativeSession,
    NormalizationCoverage, NormalizedHostEventEnvelope, NormalizedHostEventPayload,
    PhysicalRouteObservationReceipt, ProviderExecutionBinding, ProviderObservationLineage,
    ProviderTerminalObservation, ProviderTerminalStatus, QualifiedSourceDigest, QuotaKnowledge,
    RawSourceRecord, ReasoningSummaryObservation, RestrictedRawSourceHandle, ResultDisposition,
    RouteContinuationLocator, RouteFingerprint, RouteObservationState, SessionId,
    SessionLifecycleObservation, SessionLifecycleTransition, ToolInvocationObservation,
    ToolOutcomeClass, ToolOutcomeObservation, UnsupportedDisposition, UnsupportedEventObservation,
    UnsupportedEventReason, UsageReceipt, WorkLeaseId,
};
use eliot_process::{
    CancellationReceipt, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutor, ProcessRequest, ProcessStartReceipt,
};
use eliot_source_assurance::{
    AdmissionExpectation, AdmissionOutcome, SourceAssurance, SourceAssuranceError,
};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

pub mod catalogue;
pub mod preflight;

pub const CODEX_ADAPTER_ID: &str = "eliot-agent-codex";
pub const CODEX_HOST_FAMILY: &str = "codex";
pub const CODEX_PROTOCOL_TRANSPORT: &str = "app-server+stdio/jsonl";
pub const CODEX_WIRE_SCHEMA_VERSION: &str = "codex-app-server-stable-jsonl/v2";
pub const CODEX_ROUTE_CLASS: &str = "codex-app-server";
pub const MAX_JSONL_LINE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVENT_BYTES: usize = 256 * 1024;

/// Adapter identity bound by [`normalize_codex_event`]. Callers never supply
/// their own producer identity.
pub const CODEX_NORMALIZER_IDENTITY: &str = CODEX_ADAPTER_ID;
/// Adapter contract version bound by [`normalize_codex_event`]. Callers never
/// supply their own producer version.
pub const CODEX_NORMALIZER_VERSION: &str = CODEX_WIRE_SCHEMA_VERSION;

/// Adapter failures preserve the boundary that rejected the call.  Provider
/// response bodies are intentionally not included in errors.
#[derive(Debug, Error)]
pub enum CodexAdapterError {
    #[error("A-01 contract rejected the Codex binding: {0}")]
    Contract(#[from] eliot_agent_api::ContractError),
    #[error("P-03 process contract rejected the Codex binding: {0}")]
    ProcessContract(#[from] eliot_process::ContractError),
    #[error("P-03 executor failed: {0}")]
    Process(#[from] ProcessExecutionError),
    #[error("Q-01 source admission rejected the Codex binding: {0}")]
    Source(#[from] SourceAssuranceError),
    #[error("Q-01 source was not admitted: {0}")]
    SourceNotAdmitted(String),
    #[error("Codex JSONL is malformed: {0}")]
    MalformedWire(&'static str),
    #[error("Codex JSONL line exceeds the adapter limit")]
    WireTooLarge,
    #[error("Codex response does not correlate to request {expected}")]
    ResponseCorrelation { expected: String },
    #[error("Codex response contains both result and error")]
    AmbiguousResponse,
    #[error("Codex route fingerprint is not exact for this adapter")]
    RouteMismatch,
    #[error("Codex session binding is stale or belongs to another attempt")]
    SessionMismatch,
    #[error("Codex state fence is stale")]
    StaleFence,
    #[error("Codex process request has already been consumed")]
    ProcessAlreadyStarted,
    #[error("Codex output is partial; outcome remains unknown")]
    PartialOutput,
    #[error("Codex output has no admissible semantic result")]
    MissingResult,
    #[error("Codex result is already terminal")]
    TerminalAttempt,
    #[error("Codex preflight is incomplete: initialize→initialized→model/list required")]
    PreflightIncomplete,
    #[error("Codex wire is stale or legacy: {0}")]
    StaleWire(&'static str),
    #[error("Codex catalogue is stale or expired")]
    CatalogueStale,
    #[error("Codex catalogue binding mismatch: {0}")]
    CatalogueMismatch(&'static str),
    #[error("Codex model is not present in the bound catalogue snapshot")]
    ModelNotInCatalogue,
    #[error("Codex host-event normalization input is invalid: {0}")]
    InvalidInput(&'static str),
}

/// Exact route constructor.  The resulting value is still the A-01 route
/// projection; no vendor SDK type escapes this crate.
#[allow(clippy::too_many_arguments)]
pub fn codex_route(
    runtime_hash: LowercaseSha256,
    adapter_hash: LowercaseSha256,
    provider: impl Into<String>,
    model: impl Into<String>,
    auth_billing: impl Into<String>,
    serializer_hash: LowercaseSha256,
    tool_semantics_hash: LowercaseSha256,
    reasoning_mode: impl Into<String>,
    continuation_behavior: impl Into<String>,
    feature_flags_hash: LowercaseSha256,
) -> RouteFingerprint {
    RouteFingerprint {
        host_family: CODEX_HOST_FAMILY.into(),
        adapter: CODEX_ADAPTER_ID.into(),
        protocol_transport: CODEX_PROTOCOL_TRANSPORT.into(),
        runtime_hash,
        adapter_hash,
        provider: provider.into(),
        model: model.into(),
        auth_billing: auth_billing.into(),
        serializer_hash,
        tool_semantics_hash,
        reasoning_mode: reasoning_mode.into(),
        continuation_behavior: continuation_behavior.into(),
        feature_flags_hash,
    }
}

fn validate_codex_route(route: &RouteFingerprint) -> Result<(), CodexAdapterError> {
    route.validate()?;
    if route.host_family != CODEX_HOST_FAMILY
        || route.adapter != CODEX_ADAPTER_ID
        || route.protocol_transport != CODEX_PROTOCOL_TRANSPORT
    {
        return Err(CodexAdapterError::RouteMismatch);
    }
    Ok(())
}

/// Exact external session identity.  A session is an observation bound to an
/// attempt; it is not the durable attempt identity and cannot mint authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexSessionBinding {
    pub session_id: SessionId,
    pub thread_id: String,
    pub runtime_hash: LowercaseSha256,
    pub working_directory: String,
}

impl CodexSessionBinding {
    pub fn validate(&self, route: &RouteFingerprint) -> Result<(), CodexAdapterError> {
        validate_codex_route(route)?;
        for value in [&self.thread_id, &self.working_directory] {
            if value.trim().is_empty() {
                return Err(CodexAdapterError::SessionMismatch);
            }
        }
        if self.runtime_hash != route.runtime_hash {
            return Err(CodexAdapterError::SessionMismatch);
        }
        Ok(())
    }
}

/// Input to the admission/attach boundary.  All authority and source proof is
/// supplied by the caller; the adapter only narrows and validates it.
#[derive(Debug)]
pub struct CodexAttachInput {
    pub launch: AgentLaunchRequest,
    pub authority: AuthorityEnvelope,
    pub route: RouteFingerprint,
    pub session: CodexSessionBinding,
    pub process_request: ProcessRequest,
    pub source_assurance: SourceAssurance,
    pub source_expectation: AdmissionExpectation,
}

/// Immutable receipt proving the exact inputs accepted by `attach`.
#[derive(Debug)]
pub struct CodexAttachReceipt {
    launch: AgentLaunchRequest,
    authority: AuthorityEnvelope,
    route: RouteFingerprint,
    session: CodexSessionBinding,
    process_request: Option<ProcessRequest>,
    operation_id: eliot_process::OperationId,
    generation: eliot_process::Generation,
    invocation_digest: String,
    permit_digest: String,
    source_digest: String,
}

impl CodexAttachReceipt {
    pub fn launch(&self) -> &AgentLaunchRequest {
        &self.launch
    }
    pub fn authority(&self) -> &AuthorityEnvelope {
        &self.authority
    }
    pub fn route(&self) -> &RouteFingerprint {
        &self.route
    }
    pub fn session(&self) -> &CodexSessionBinding {
        &self.session
    }
    pub fn process_request(&self) -> Option<&ProcessRequest> {
        self.process_request.as_ref()
    }
    pub fn operation_id(&self) -> &eliot_process::OperationId {
        &self.operation_id
    }
    pub fn generation(&self) -> eliot_process::Generation {
        self.generation
    }
    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }
    pub fn permit_digest(&self) -> &str {
        &self.permit_digest
    }
    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }
}

/// Bind an admitted Q-01 source and exact route without launching anything.
pub fn attach(input: CodexAttachInput) -> Result<CodexAttachReceipt, CodexAdapterError> {
    input.launch.validate()?;
    input.authority.validate()?;
    validate_codex_route(&input.route)?;
    input.session.validate(&input.route)?;
    input.process_request.validate()?;
    if input.process_request.working_directory() != input.session.working_directory {
        return Err(CodexAdapterError::SessionMismatch);
    }
    if !input
        .launch
        .allowed_route_classes
        .iter()
        .any(|class| class == CODEX_ROUTE_CLASS || class == &input.route.adapter)
    {
        return Err(CodexAdapterError::RouteMismatch);
    }
    ensure_narrower(
        &input.authority.effect_ceiling,
        &input.launch.effect_ceiling,
    )?;
    for unit in &input.launch.work_units {
        ensure_narrower(&input.authority.effect_ceiling, &unit.effect_ceiling)?;
    }
    let outcome = input.source_assurance.admit(&input.source_expectation)?;
    let source_digest = match outcome {
        AdmissionOutcome::Admitted { assurance_digest } => assurance_digest,
        other => return Err(CodexAdapterError::SourceNotAdmitted(format!("{other:?}"))),
    };
    let operation_id = input.process_request.operation_id().clone();
    let generation = input.process_request.generation();
    let invocation_digest = input.process_request.invocation_digest().to_owned();
    let permit_digest = input.process_request.permit_digest().to_owned();
    Ok(CodexAttachReceipt {
        launch: input.launch,
        authority: input.authority,
        route: input.route,
        session: input.session,
        process_request: Some(input.process_request),
        operation_id,
        generation,
        invocation_digest,
        permit_digest,
        source_digest,
    })
}

fn ensure_narrower(actual: &EffectCeiling, upper: &EffectCeiling) -> Result<(), CodexAdapterError> {
    actual.validate()?;
    upper.validate()?;
    if actual.scope_ref != upper.scope_ref
        || actual.max_external_effects > upper.max_external_effects
        || !actual.allowed.is_subset(&upper.allowed)
    {
        return Err(CodexAdapterError::Contract(
            eliot_agent_api::ContractError::InsufficientAuthority,
        ));
    }
    Ok(())
}

/// Stateless adapter facade.  The executor is injected and therefore remains
/// P-03's lifecycle owner; this type stores no mutable session/attempt state.
pub struct CodexAdapter<E> {
    executor: Arc<E>,
}

impl<E> CodexAdapter<E> {
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }

    /// Adapter-shaped entrypoint kept separate from the P-03 execution
    /// methods so callers cannot accidentally treat attach as launch.
    pub fn attach(input: CodexAttachInput) -> Result<CodexAttachReceipt, CodexAdapterError> {
        attach(input)
    }
}

impl<E: ProcessExecutor + 'static> CodexAdapter<E> {
    /// Launch one admitted process through P-03, checking the returned receipt
    /// against the exact operation and generation in the attached request.
    pub async fn launch(
        &self,
        attached: &mut CodexAttachReceipt,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<CodexLaunchReceipt, CodexAdapterError> {
        let process_request = attached
            .process_request
            .take()
            .ok_or(CodexAdapterError::ProcessAlreadyStarted)?;
        let start = self.executor.start(process_request, sink).await?;
        if start.operation_id() != attached.operation_id()
            || start.accepted_generation() != attached.generation()
        {
            return Err(CodexAdapterError::StaleFence);
        }
        Ok(CodexLaunchReceipt {
            attempt_id: AttemptId::new(attached.launch.id.as_str())
                .map_err(|_| CodexAdapterError::MalformedWire("attempt_id"))?,
            process: start,
            route: attached.route.clone(),
            session: attached.session.clone(),
        })
    }

    pub async fn cancel(
        &self,
        attached: &CodexAttachReceipt,
        reason: CancelReason,
    ) -> Result<CodexCancelReceipt, CodexAdapterError> {
        let process = self
            .executor
            .cancel(attached.operation_id().clone())
            .await?;
        Ok(CodexCancelReceipt {
            attempt_id: AttemptId::new(attached.launch.id.as_str())
                .map_err(|_| CodexAdapterError::MalformedWire("attempt_id"))?,
            reason,
            process,
        })
    }

    pub async fn reconcile_unknown(
        &self,
        attached: &CodexAttachReceipt,
    ) -> Result<ProcessEvidence, CodexAdapterError> {
        Ok(self
            .executor
            .reconcile(attached.operation_id().clone())
            .await?)
    }
}

/// Receipt returned after P-03 accepted a launch.
#[derive(Clone, Debug)]
pub struct CodexLaunchReceipt {
    pub attempt_id: AttemptId,
    pub process: ProcessStartReceipt,
    pub route: RouteFingerprint,
    pub session: CodexSessionBinding,
}

#[derive(Clone, Debug)]
pub struct CodexCancelReceipt {
    pub attempt_id: AttemptId,
    pub reason: CancelReason,
    pub process: CancellationReceipt,
}

/// Create the provider-neutral attempt projection.  No provider message is
/// needed: the attempt is durable before the external process is observed.
pub fn begin_attempt(
    attached: &CodexAttachReceipt,
    lease: WorkLeaseId,
    attempt_id: AttemptId,
    continuity: ContinuityKind,
) -> Result<AgentAttempt, CodexAdapterError> {
    begin_attempt_with_gate(attached, None, lease, attempt_id, continuity)
}

/// Per-attempt binding that requires a ready preflight gate with a validated
/// `ModelCatalogueSnapshot` identity. The bound model must exactly match
/// `attached.route.model` and the snapshot must be current.
pub fn begin_attempt_with_gate(
    attached: &CodexAttachReceipt,
    gate: Option<&crate::preflight::CodexPreflightGate>,
    lease: WorkLeaseId,
    attempt_id: AttemptId,
    continuity: ContinuityKind,
) -> Result<AgentAttempt, CodexAdapterError> {
    if let Some(gate) = gate {
        gate.require_ready()?;
        let bound_model = gate
            .bound_model_id()
            .ok_or(CodexAdapterError::ModelNotInCatalogue)?;
        if bound_model != attached.route.model {
            return Err(CodexAdapterError::CatalogueMismatch(
                "bound model does not match route",
            ));
        }
    }
    let work_unit: AgentWorkUnitBrief = attached
        .launch
        .work_units
        .first()
        .cloned()
        .ok_or(CodexAdapterError::MissingResult)?;
    let mut attempt = AgentAttempt {
        id: attempt_id,
        launch_request_id: attached.launch.id.clone(),
        task_id: attached.launch.task_id.clone(),
        parent_attempt: attached.launch.parent_attempt.clone(),
        work_unit: work_unit.clone(),
        session: Some(attached.session.session_id.clone()),
        lease,
        state: AttemptState::Admitted,
        continuity,
        route: attached.route.clone(),
        budget: attached.launch.context_budget.clone(),
        authority: attached.authority.clone(),
        cancellation: eliot_agent_api::CancellationState::NotRequested,
        event_cursor: None,
        continuation: None,
        provider_binding: None, // S1: unresolved at construction; S2 lifecycle establishes
    };
    attempt.validate()?;
    attempt.transition(AttemptState::Started)?;
    Ok(attempt)
}

/// Strict per-attempt binding that fails when no catalogue snapshot is bound.
/// Use this in production to prevent caller-invented universal model strings.
pub fn begin_attempt_strict(
    attached: &CodexAttachReceipt,
    gate: &crate::preflight::CodexPreflightGate,
    lease: WorkLeaseId,
    attempt_id: AttemptId,
    continuity: ContinuityKind,
) -> Result<AgentAttempt, CodexAdapterError> {
    gate.require_ready()?;
    begin_attempt_with_gate(attached, Some(gate), lease, attempt_id, continuity)
}

/// Codex App Server JSONL envelope.  Provider fields remain opaque `Value`s;
/// callers receive typed A-01 events/results after translation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodexWireMessage {
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<Value>,
    #[serde(
        rename = "type",
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub message_type: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub method: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub params: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub result: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub error: Option<Value>,
}

fn deserialize_non_null_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)?
        .ok_or_else(|| de::Error::custom("explicit null is not permitted"))
        .map(Some)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireMessageKind {
    Request,
    Notification,
    Response,
}

fn valid_wire_id(value: &Value) -> bool {
    let Some(id) = value.as_str() else {
        return false;
    };
    valid_wire_id_text(id)
}

fn valid_wire_id_text(id: &str) -> bool {
    let mut bytes = id.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_method(method: &str) -> bool {
    let mut bytes = method.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && method == method.trim()
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
}

fn validate_wire_message(message: &CodexWireMessage) -> Result<WireMessageKind, CodexAdapterError> {
    if let Some(id) = &message.id
        && !valid_wire_id(id)
    {
        return Err(CodexAdapterError::MalformedWire(
            "id must be a supported string",
        ));
    }
    if message.params.as_ref().is_some_and(Value::is_null)
        || message.result.as_ref().is_some_and(Value::is_null)
        || message.error.as_ref().is_some_and(Value::is_null)
    {
        return Err(CodexAdapterError::MalformedWire(
            "explicit null field is not permitted",
        ));
    }
    if let Some(method) = &message.method
        && !valid_method(method)
    {
        return Err(CodexAdapterError::MalformedWire("invalid method"));
    }
    if let Some(message_type) = &message.message_type
        && !matches!(
            message_type.as_str(),
            "request" | "notification" | "response"
        )
    {
        return Err(CodexAdapterError::MalformedWire("unsupported type"));
    }
    if message.result.is_some() && message.error.is_some() {
        return Err(CodexAdapterError::AmbiguousResponse);
    }

    let kind = if message.result.is_some() || message.error.is_some() {
        if message.id.is_none() || message.method.is_some() || message.params.is_some() {
            return Err(CodexAdapterError::MalformedWire(
                "response contains request or notification fields",
            ));
        }
        WireMessageKind::Response
    } else if message.method.is_some() {
        if message.id.is_some() {
            WireMessageKind::Request
        } else {
            WireMessageKind::Notification
        }
    } else {
        return Err(CodexAdapterError::MalformedWire("message has no operation"));
    };

    if message.message_type.as_deref().is_some_and(|declared| {
        !matches!(
            (declared, kind),
            ("request", WireMessageKind::Request)
                | ("notification", WireMessageKind::Notification)
                | ("response", WireMessageKind::Response)
        )
    }) {
        return Err(CodexAdapterError::MalformedWire(
            "type conflicts with message shape",
        ));
    }
    Ok(kind)
}

impl CodexWireMessage {
    pub fn parse_line(line: &[u8]) -> Result<Self, CodexAdapterError> {
        if line.len() > MAX_JSONL_LINE_BYTES {
            return Err(CodexAdapterError::WireTooLarge);
        }
        let message: Self = serde_json::from_slice(line)
            .map_err(|_| CodexAdapterError::MalformedWire("invalid JSON object"))?;
        validate_wire_message(&message)?;
        Ok(message)
    }

    pub fn request(id: impl Into<String>, method: impl Into<String>, params: Value) -> Self {
        Self {
            id: Some(Value::String(id.into())),
            message_type: None,
            method: Some(method.into()),
            params: Some(params),
            result: None,
            error: None,
        }
    }

    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            id: None,
            message_type: None,
            method: Some(method.into()),
            params,
            result: None,
            error: None,
        }
    }

    /// Stable App Server initialize request. The provider wire deliberately
    /// omits both a JSON-RPC version header and any ELIOT-internal protocol ID.
    pub fn initialize(
        id: impl Into<String>,
        client_name: impl Into<String>,
        client_version: impl Into<String>,
    ) -> Self {
        Self::request(
            id,
            "initialize",
            serde_json::json!({
                "clientInfo": {"name": client_name.into(), "version": client_version.into()},
                "capabilities": {"experimentalApi": false}
            }),
        )
    }

    /// Required lifecycle notification after a successful initialize response.
    pub fn initialized() -> Self {
        Self::notification("initialized", None)
    }

    /// Zero-model current-account catalogue request.
    pub fn model_list(
        id: impl Into<String>,
        cursor: Option<&str>,
        include_hidden: bool,
        limit: Option<u32>,
    ) -> Self {
        let mut params = Map::new();
        if let Some(cursor) = cursor {
            params.insert("cursor".into(), Value::String(cursor.to_owned()));
        }
        params.insert("includeHidden".into(), Value::Bool(include_hidden));
        if let Some(limit) = limit {
            params.insert("limit".into(), Value::from(limit));
        }
        Self::request(id, "model/list", Value::Object(params))
    }

    /// Zero-model account quota observation request.
    pub fn account_rate_limits(id: impl Into<String>) -> Self {
        Self::request(id, "account/rateLimits/read", Value::Object(Map::new()))
    }

    pub fn thread_start(id: impl Into<String>, cwd: impl Into<String>) -> Self {
        Self::request(id, "thread/start", serde_json::json!({ "cwd": cwd.into() }))
    }

    /// Gated thread/start that requires a ready preflight gate.
    pub fn thread_start_checked(
        id: impl Into<String>,
        cwd: impl Into<String>,
        gate: &crate::preflight::CodexPreflightGate,
    ) -> Result<Self, CodexAdapterError> {
        gate.require_ready()?;
        Ok(Self::request(
            id,
            "thread/start",
            serde_json::json!({ "cwd": cwd.into() }),
        ))
    }

    pub fn turn_start(id: impl Into<String>, thread_id: &str, input: &Value) -> Self {
        Self::request(
            id,
            "turn/start",
            serde_json::json!({ "threadId": thread_id, "input": input }),
        )
    }

    /// Gated turn/start that requires a ready preflight gate.
    pub fn turn_start_checked(
        id: impl Into<String>,
        thread_id: &str,
        input: &Value,
        gate: &crate::preflight::CodexPreflightGate,
    ) -> Result<Self, CodexAdapterError> {
        gate.require_ready()?;
        Ok(Self::request(
            id,
            "turn/start",
            serde_json::json!({ "threadId": thread_id, "input": input }),
        ))
    }

    pub fn turn_interrupt(id: impl Into<String>, thread_id: &str, turn_id: &str) -> Self {
        Self::request(
            id,
            "turn/interrupt",
            serde_json::json!({ "threadId": thread_id, "turnId": turn_id }),
        )
    }
}

/// Validate response correlation without interpreting vendor result shape.
pub fn correlate_response<'a>(
    message: &'a CodexWireMessage,
    request_id: &str,
) -> Result<&'a Value, CodexAdapterError> {
    if validate_wire_message(message)? != WireMessageKind::Response {
        return Err(CodexAdapterError::MalformedWire(
            "message is not a response",
        ));
    }
    let actual = message.id.as_ref().and_then(Value::as_str);
    if !valid_wire_id_text(request_id) || actual != Some(request_id) {
        return Err(CodexAdapterError::ResponseCorrelation {
            expected: request_id.into(),
        });
    }
    message.result.as_ref().ok_or_else(|| {
        if message.error.is_some() {
            CodexAdapterError::MalformedWire("provider returned an error")
        } else {
            CodexAdapterError::MissingResult
        }
    })
}

/// Namespace of the exact Codex execution unit: the turn ID. Matches the S1
/// owner fixture (`crates/agent/eliot-agent-api/tests/execution_binding.rs`).
const CODEX_EXECUTION_UNIT_NAMESPACE: &str = "codex";

/// Closed-payload classification for one Codex notification.
///
/// Every branch returns a member of the closed
/// [`NormalizedHostEventPayload`] family (no generic `Value`, no `Other`
/// escape). Raw provider text/arguments/results stay behind the restricted
/// source handle; the public payload carries only bounded summaries or
/// canonical digests. Unknown methods and non-terminal `turn/completed`
/// statuses quarantine as [`NormalizedHostEventPayload::UnsupportedQuarantined`],
/// never as terminal success.
struct ClassifiedCodexPayload {
    payload: NormalizedHostEventPayload,
    omitted_fields: Vec<String>,
    warnings: Vec<String>,
    privacy_class: HostEventPrivacyClass,
    coverage: NormalizationCoverage,
}

/// Count characters of the first present string field, in Unicode scalar
/// values. Absent fields yield `0` (absent evidence, never a guessed length).
fn delta_chars_from(params: &Value, keys: &[&str]) -> u64 {
    params
        .as_object()
        .and_then(|object| {
            keys.iter()
                .filter_map(|key| object.get(*key))
                .filter_map(Value::as_str)
                .next()
        })
        .map(|text| text.chars().count() as u64)
        .unwrap_or(0)
}

/// Extract an opaque tool name from the wire without publishing arguments.
/// Falls back to the wire method family (real wire evidence, never a canned
/// universal name) when no explicit name is present.
fn tool_name_from(params: &Value, method: &str) -> String {
    params
        .as_object()
        .and_then(|object| {
            ["tool", "name", "command", "function", "toolName"]
                .iter()
                .filter_map(|key| object.get(*key))
                .filter_map(Value::as_str)
                .map(str::trim)
                .find(|name| !name.is_empty())
        })
        .unwrap_or(method)
        .to_owned()
}

/// Canonical digest of the exact wire arguments/results for the restricted
/// source commitment. Uses the shared canonical-JSON + SHA-256 primitive
/// (never a new digest algorithm).
fn digest_value(value: &Value) -> Result<LowercaseSha256, CodexAdapterError> {
    let bytes = eliot_contracts::canonical_json_bytes(value)
        .map_err(|_| CodexAdapterError::Contract(eliot_agent_api::ContractError::DigestMismatch))?;
    let hex = eliot_contracts::sha256_hex(&bytes);
    serde_json::from_value(Value::String(hex))
        .map_err(|_| CodexAdapterError::Contract(eliot_agent_api::ContractError::DigestMismatch))
}

/// Classify the provider terminal status from `params.turn.status`.
/// Only exact `"completed"`/`"failed"` become observed terminal success/failure;
/// every other status (interrupted, unknown, in-progress, numeric, missing)
/// stays quarantine and never upgrades to success.
fn terminal_status_from(params: &Value) -> Option<ProviderTerminalStatus> {
    match params
        .get("turn")
        .and_then(Value::as_object)
        .and_then(|turn| turn.get("status"))
        .and_then(Value::as_str)
    {
        Some("completed") => Some(ProviderTerminalStatus::CompletedObserved),
        Some("failed") => Some(ProviderTerminalStatus::FailedObserved),
        _ => None,
    }
}

/// Classify a tool outcome without inferring success. Only exact
/// success/failure/cancelled strings classify; absent or unrecognized outcome
/// stays [`ToolOutcomeClass::Unknown`], never success.
fn tool_outcome_from(params: &Value) -> ToolOutcomeClass {
    let status = params
        .as_object()
        .and_then(|object| {
            ["status", "outcome", "result", "state"]
                .iter()
                .filter_map(|key| object.get(*key))
                .filter_map(Value::as_str)
                .next()
        })
        .map(|value| value.trim().to_ascii_lowercase());
    match status.as_deref() {
        Some("succeeded") | Some("success") | Some("completed") | Some("ok") => {
            ToolOutcomeClass::Succeeded
        }
        Some("failed") | Some("failure") | Some("error") => ToolOutcomeClass::Failed,
        Some("cancelled") | Some("canceled") | Some("interrupted") => ToolOutcomeClass::Cancelled,
        _ => ToolOutcomeClass::Unknown,
    }
}

/// Top-level params keys dropped from the public typed summary. Used for the
/// loss manifest (`omitted_fields`); raw bytes stay behind the restricted
/// handle by construction.
fn omitted_top_level_keys(params: &Value, retained: &[&str]) -> Vec<String> {
    let Some(object) = params.as_object() else {
        return Vec::new();
    };
    object
        .keys()
        .filter(|key| !retained.contains(&key.as_str()))
        .take(32)
        .cloned()
        .collect()
}

fn unsupported_quarantine(
    method: &str,
    reason: UnsupportedEventReason,
    warnings: Vec<String>,
    omitted_fields: Vec<String>,
) -> ClassifiedCodexPayload {
    let namespace = method
        .split('/')
        .next()
        .filter(|part| !part.trim().is_empty())
        .unwrap_or("codex");
    ClassifiedCodexPayload {
        payload: NormalizedHostEventPayload::UnsupportedQuarantined(UnsupportedEventObservation {
            source_namespace: namespace.to_owned(),
            source_version: Some(CODEX_WIRE_SCHEMA_VERSION.to_owned()),
            reason,
            detail_ref: Some(method.to_owned()),
        }),
        omitted_fields,
        warnings,
        privacy_class: HostEventPrivacyClass::RestrictedHandleOnly,
        coverage: NormalizationCoverage::LossyOmission,
    }
}

/// Map one Codex notification method + params to the closed typed payload.
/// The bound turn/sequence supply correlation references minted by the adapter
/// (never a provider-native cursor); raw content stays behind the handle.
fn classify_codex_payload(
    method: &str,
    params: &Value,
    bound_turn: &str,
    sequence: u64,
    bound_unit: &ExecutionUnit,
) -> Result<ClassifiedCodexPayload, CodexAdapterError> {
    match method {
        "turn/started" | "turn/created" => Ok(ClassifiedCodexPayload {
            payload: NormalizedHostEventPayload::ExecutionStarted(ExecutionStartedObservation {
                execution_unit: bound_unit.clone(),
                start_ref: bound_turn.to_owned(),
            }),
            omitted_fields: omitted_top_level_keys(params, &["threadId", "thread_id", "turn"]),
            warnings: Vec::new(),
            privacy_class: HostEventPrivacyClass::RedactedSummary,
            coverage: if omitted_top_level_keys(params, &["threadId", "thread_id", "turn"])
                .is_empty()
            {
                NormalizationCoverage::Complete
            } else {
                NormalizationCoverage::LossyOmission
            },
        }),
        "item/agentMessage/delta" | "item/assistantMessage/delta" => {
            let delta_chars =
                delta_chars_from(params, &["delta", "text", "content", "message", "output"]);
            Ok(ClassifiedCodexPayload {
                payload: NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
                    delta_chars,
                    truncated: false,
                }),
                omitted_fields: vec!["raw_delta_text".to_owned()],
                warnings: Vec::new(),
                privacy_class: HostEventPrivacyClass::RedactedSummary,
                coverage: NormalizationCoverage::LossyOmission,
            })
        }
        "item/reasoningSummary/delta" | "item/reasoning/delta" => {
            let summary_chars =
                delta_chars_from(params, &["delta", "text", "summary", "content", "message"]);
            Ok(ClassifiedCodexPayload {
                payload: NormalizedHostEventPayload::ReasoningSummary(
                    ReasoningSummaryObservation {
                        summary_chars,
                        truncated: false,
                    },
                ),
                omitted_fields: vec!["raw_reasoning_text".to_owned()],
                warnings: Vec::new(),
                privacy_class: HostEventPrivacyClass::RestrictedHandleOnly,
                coverage: NormalizationCoverage::LossyOmission,
            })
        }
        "item/commandExecution/requestApproval" | "item/toolCall" => {
            let tool_name = tool_name_from(params, method);
            if tool_name.trim().is_empty()
                || tool_name.chars().any(char::is_control)
                || tool_name.chars().count() > 1024
            {
                return Err(CodexAdapterError::MalformedWire("tool name"));
            }
            Ok(ClassifiedCodexPayload {
                payload: NormalizedHostEventPayload::ToolInvocation(ToolInvocationObservation {
                    tool_name,
                    invocation_ref: format!("{bound_turn}:{sequence}"),
                    arguments_digest: digest_value(params)?,
                }),
                omitted_fields: vec!["raw_arguments".to_owned()],
                warnings: Vec::new(),
                privacy_class: HostEventPrivacyClass::RestrictedHandleOnly,
                coverage: NormalizationCoverage::LossyOmission,
            })
        }
        "item/commandExecution/finished" | "item/toolResult" => {
            let tool_name = tool_name_from(params, method);
            if tool_name.trim().is_empty()
                || tool_name.chars().any(char::is_control)
                || tool_name.chars().count() > 1024
            {
                return Err(CodexAdapterError::MalformedWire("tool name"));
            }
            let result_source = params.get("result").unwrap_or(params);
            Ok(ClassifiedCodexPayload {
                payload: NormalizedHostEventPayload::ToolOutcome(ToolOutcomeObservation {
                    tool_name,
                    invocation_ref: format!("{bound_turn}:{sequence}"),
                    outcome: tool_outcome_from(params),
                    result_digest: digest_value(result_source)?,
                    safe_summary: None,
                }),
                omitted_fields: vec!["raw_result".to_owned()],
                warnings: Vec::new(),
                privacy_class: HostEventPrivacyClass::RestrictedHandleOnly,
                coverage: NormalizationCoverage::LossyOmission,
            })
        }
        "turn/completed" => {
            if let Some(status) = terminal_status_from(params) {
                let omitted = omitted_top_level_keys(params, &["threadId", "thread_id", "turn"]);
                let coverage = if omitted.is_empty() {
                    NormalizationCoverage::Complete
                } else {
                    NormalizationCoverage::LossyOmission
                };
                Ok(ClassifiedCodexPayload {
                    payload: NormalizedHostEventPayload::ProviderTerminalObserved(
                        ProviderTerminalObservation {
                            status,
                            terminal_ref: bound_turn.to_owned(),
                        },
                    ),
                    omitted_fields: omitted,
                    warnings: Vec::new(),
                    privacy_class: HostEventPrivacyClass::RedactedSummary,
                    coverage,
                })
            } else {
                Ok(unsupported_quarantine(
                    method,
                    UnsupportedEventReason::UnknownMethod,
                    vec!["non-terminal-turn-status".to_owned()],
                    omitted_top_level_keys(params, &["threadId", "thread_id"]),
                ))
            }
        }
        "turn/usage" | "usage" => {
            let (input_tokens, output_tokens, cost_microunits) = params
                .get("usage")
                .and_then(Value::as_object)
                .map(|usage| {
                    (
                        usage.get("input_tokens").and_then(Value::as_u64),
                        usage.get("output_tokens").and_then(Value::as_u64),
                        usage.get("cost_microunits").and_then(Value::as_u64),
                    )
                })
                .unwrap_or((None, None, None));
            // Absent native quota/replay evidence stays typed
            // `NotExposed`, never a synthesized zero or string constant.
            Ok(ClassifiedCodexPayload {
                payload: NormalizedHostEventPayload::Usage(UsageReceipt {
                    input_tokens,
                    output_tokens,
                    cost_microunits,
                    quota: QuotaKnowledge::NotExposed,
                }),
                omitted_fields: Vec::new(),
                warnings: Vec::new(),
                privacy_class: HostEventPrivacyClass::RedactedSummary,
                coverage: NormalizationCoverage::Complete,
            })
        }
        "turn/failed" | "error" => Ok(ClassifiedCodexPayload {
            payload: NormalizedHostEventPayload::Error(ErrorObservation {
                code: method.to_owned(),
                safe_summary: format!("codex {method} observed"),
            }),
            omitted_fields: vec!["raw_error".to_owned()],
            warnings: Vec::new(),
            privacy_class: HostEventPrivacyClass::RestrictedHandleOnly,
            coverage: NormalizationCoverage::LossyOmission,
        }),
        _ => Ok(unsupported_quarantine(
            method,
            UnsupportedEventReason::UnknownMethod,
            Vec::new(),
            omitted_top_level_keys(params, &[]),
        )),
    }
}

/// Validate that a recorded binding belongs to this adapter family before use:
/// shape, exact Codex route, and the Codex turn namespace. A foreign-family
/// binding quarantines as a binding mismatch, never as attributed output.
fn validate_binding_for_codex(binding: &ProviderExecutionBinding) -> Result<(), CodexAdapterError> {
    binding.validate_internal()?;
    validate_codex_route(&binding.route)?;
    if binding.execution_unit.namespace != CODEX_EXECUTION_UNIT_NAMESPACE {
        return Err(CodexAdapterError::Contract(
            eliot_agent_api::ContractError::BindingMismatch,
        ));
    }
    Ok(())
}

/// Extract the exact opaque turn ID with the real JSON parser: only
/// `params.turn.id` as a string counts as turn evidence. Absent, null, or
/// non-string turn identity is missing evidence, never a guessed turn.
fn wire_turn_id(params: &Value) -> Option<&str> {
    params
        .get("turn")
        .and_then(Value::as_object)
        .and_then(|turn| turn.get("id"))
        .and_then(Value::as_str)
}

fn validate_wire_session_against_binding(
    params: &Value,
    binding: &ProviderExecutionBinding,
) -> Result<(), CodexAdapterError> {
    let Some(object) = params.as_object() else {
        return Ok(());
    };
    let expected_thread: Option<&str> = match &binding.native_session {
        NativeSession::Native(locator) => Some(locator.locator.as_str()),
        // Codex always records a thread locator; a sessionless binding cannot
        // corroborate a Codex thread event.
        NativeSession::Sessionless => None,
    };
    for key in ["threadId", "thread_id"] {
        if let Some(value) = object.get(key) {
            let matches = match (value.as_str(), expected_thread) {
                (Some(actual), Some(expected)) => actual == expected,
                _ => false,
            };
            if !matches {
                return Err(CodexAdapterError::SessionMismatch);
            }
        }
    }
    // ELIOT session agreement only where the binding carries an admitted
    // session. Coordinator S2 admits no session yet
    // (`crates/agent/eliot-agent-coordinator/src/core.rs:613-615`), so an
    // unadmitted binding cannot corroborate — and never invents — session
    // identity.
    if let Some(expected) = binding.session_id.as_ref() {
        for key in ["sessionId", "session_id"] {
            if let Some(value) = object.get(key)
                && value.as_str() != Some(expected.as_str())
            {
                return Err(CodexAdapterError::SessionMismatch);
            }
        }
    }
    Ok(())
}

/// Session-locator agreement for result input: the Codex thread must equal the
/// bound native locator, and an admitted bound session must equal the locator
/// session. An unadmitted (`None`) bound session is skipped, never invented.
fn validate_session_locator_against_binding(
    session: &CodexSessionBinding,
    binding: &ProviderExecutionBinding,
) -> Result<(), CodexAdapterError> {
    match &binding.native_session {
        NativeSession::Native(locator) if session.thread_id == locator.locator => {}
        _ => return Err(CodexAdapterError::SessionMismatch),
    }
    if let Some(expected) = binding.session_id.as_ref()
        && session.session_id != *expected
    {
        return Err(CodexAdapterError::SessionMismatch);
    }
    Ok(())
}

/// Typed Codex host-event normalization input (issue #371 S7).
///
/// Every field is typed: the wire message travels as [`CodexWireMessage`],
/// the exact execution lineage travels as [`ProviderObservationLineage`]
/// (never parsed from provider locators), event identity/cursor travel as
/// [`EventId`]/[`EventCursor`] from the post-R1 owner (never synthesized as
/// `codex:{sequence}`), digests are computed inside from `raw_source_bytes`
/// (never caller-supplied strings), and observation time is a typed
/// [`ClockReading`] (never a wall-clock string). The closed typed payload is
/// classified inside from the wire method (never caller-supplied).
#[derive(Clone, Debug)]
pub struct CodexHostEventInput<'a> {
    /// Provider wire notification. Must be a notification (not request/response).
    pub message: &'a CodexWireMessage,
    /// Exact session or execution-unit lineage. No string/JSON parsing, no new
    /// attempt invention.
    pub lineage: ProviderObservationLineage,
    /// Event identity from the post-R1 owner. For execution-unit lineage must
    /// equal the recorded observation cursor (no synthesis).
    pub event_id: EventId,
    /// Resume cursor from the post-R1 owner. For execution-unit lineage must
    /// equal the recorded observation cursor (preserved end-to-end).
    pub cursor: EventCursor,
    /// Monotonic sequence within the bound stream. Must be nonzero and must
    /// equal the recorded observation sequence for execution-unit lineage.
    pub sequence: u64,
    /// Previous sequence observed by the owner, for monotonicity. `None` for
    /// the first event; otherwise `sequence` must strictly increase.
    pub previous_sequence: Option<u64>,
    /// Causal predecessor event identities. Must never contain `event_id`.
    pub predecessors: Vec<EventId>,
    /// Raw Codex frame bytes (the exact JSONL wire bytes). Digested inside via
    /// the canonical SHA-256 primitive; never copied into the public payload.
    pub raw_source_bytes: &'a [u8],
    /// Restricted handle addressing the immutable raw source record.
    pub raw_source_handle: RestrictedRawSourceHandle,
    /// Typed observation time. Unknown stays unknown; wall time never advances
    /// sequence, cursor, fence, or attempt state.
    pub observed_at: ClockReading,
    /// Delivery/coverage disposition of this observation.
    pub delivery: HostEventDeliveryDisposition,
    /// Recorded #369 admission. Required for execution-unit lineage (the
    /// envelope references it by digest); forbidden for session-only lineage,
    /// which carries no admission reference.
    pub admission: Option<&'a AdmittedRouteReceipt>,
}

/// Normalize one Codex wire notification into the closed v7 host-event schema
/// (issue #371 S7).
///
/// The adapter identity/version (`eliot-agent-codex` /
/// [`CODEX_WIRE_SCHEMA_VERSION`]) is bound by this function, never supplied by
/// the caller; the input source digest is computed from `raw_source_bytes` via
/// the canonical SHA-256 primitive (never `blake3`, never a new digest); and
/// the sealed envelope is validated before return (execution-unit lineage
/// against the exact binding plus the #369 admission via
/// `validate_for_lineage`, session lineage on the session path via
/// `validate_as_session_observation`). Raw bytes stay behind the restricted
/// handle; the public payload holds the bounded typed summary only.
///
/// S1 binding checks are preserved: the recorded observation must agree with
/// the claimed stream position, monotonicity is enforced by the owner-supplied
/// `previous_sequence` (no hidden local cursor), the wire turn
/// (`params.turn.id` via the real JSON parser) must exactly equal the bound
/// unit (missing/foreign turn quarantines without advancing another attempt),
/// and thread events stay session-only (never yield attempt output).
/// The recorded `observation.cursor` is preserved end-to-end for cursor and
/// event identity; no `codex:{sequence}` cursor is ever synthesized, and
/// absent native replay/quota evidence maps to typed
/// [`QuotaKnowledge::NotExposed`] (never a string constant or zero).
pub fn normalize_codex_event(
    input: CodexHostEventInput<'_>,
) -> Result<(NormalizedHostEventEnvelope, HostEventNormalizationReceipt), CodexAdapterError> {
    if input.sequence == 0 {
        return Err(CodexAdapterError::InvalidInput("sequence"));
    }
    if input.raw_source_bytes.is_empty() || input.raw_source_bytes.len() > MAX_EVENT_BYTES {
        return Err(CodexAdapterError::InvalidInput("raw_source_bytes"));
    }
    if input
        .previous_sequence
        .is_some_and(|previous| input.sequence <= previous)
    {
        return Err(CodexAdapterError::Contract(
            eliot_agent_api::ContractError::NonMonotonicEvent,
        ));
    }
    if validate_wire_message(input.message)? != WireMessageKind::Notification {
        return Err(CodexAdapterError::MalformedWire(
            "event must be a notification",
        ));
    }
    let method = input
        .message
        .method
        .as_deref()
        .ok_or(CodexAdapterError::MalformedWire("event has no method"))?;
    let params = input.message.params.clone().unwrap_or(Value::Null);

    // Lineage/admission pairing (mirrors ACP): execution-unit requires
    // admission, session-only forbids it (no attempt authority, no route
    // reference).
    let execution_observation = match &input.lineage {
        ProviderObservationLineage::ExecutionUnitObservation(observation) => {
            let admission = input
                .admission
                .ok_or(CodexAdapterError::InvalidInput("admission/lineage"))?;
            admission.validate().map_err(CodexAdapterError::Contract)?;
            observation.validate()?;
            validate_binding_for_codex(&observation.binding)?;
            if observation.sequence != input.sequence {
                return Err(CodexAdapterError::Contract(
                    eliot_agent_api::ContractError::BindingMismatch,
                ));
            }
            if observation.cursor != input.cursor
                || observation.cursor.as_str() != input.event_id.as_str()
            {
                // The recorded cursor is preserved end-to-end; a caller
                // cursor that disagrees with the recorded observation is never
                // re-pointed to the active attempt.
                return Err(CodexAdapterError::Contract(
                    eliot_agent_api::ContractError::BindingMismatch,
                ));
            }
            validate_wire_session_against_binding(&params, &observation.binding)?;
            let bound_turn = observation.binding.execution_unit.unit_id.as_str();
            if wire_turn_id(&params) != Some(bound_turn) {
                // Missing or foreign turn: quarantine (caller retains raw);
                // never attribute turn B output to attempt A.
                return Err(CodexAdapterError::Contract(
                    eliot_agent_api::ContractError::BindingMismatch,
                ));
            }
            Some((observation, admission, bound_turn))
        }
        ProviderObservationLineage::SessionObservation(observation) => {
            if input.admission.is_some() {
                return Err(CodexAdapterError::InvalidInput("admission/lineage"));
            }
            observation.validate()?;
            None
        }
    };

    let (payload, omitted_fields, warnings, privacy_class, coverage) = match execution_observation {
        Some((observation, _, bound_turn)) => {
            let classified = classify_codex_payload(
                method,
                &params,
                bound_turn,
                input.sequence,
                &observation.binding.execution_unit,
            )?;
            (
                classified.payload,
                classified.omitted_fields,
                classified.warnings,
                classified.privacy_class,
                classified.coverage,
            )
        }
        None => {
            // Session-only path: thread lifecycle stays session-only.
            // Turn/delta/tool/terminal methods require execution-unit
            // lineage and fail closed here (no attempt authority invented);
            // unknown methods quarantine as typed session evidence.
            match method {
                "thread/started" => (
                    NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
                        transition: SessionLifecycleTransition::Started,
                        detail_ref: None,
                    }),
                    Vec::new(),
                    Vec::new(),
                    HostEventPrivacyClass::RedactedSummary,
                    NormalizationCoverage::Complete,
                ),
                "thread/resumed" => (
                    NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
                        transition: SessionLifecycleTransition::Resumed,
                        detail_ref: None,
                    }),
                    Vec::new(),
                    Vec::new(),
                    HostEventPrivacyClass::RedactedSummary,
                    NormalizationCoverage::Complete,
                ),
                _ if classify_needs_execution_unit(method, &params) => {
                    return Err(CodexAdapterError::Contract(
                        eliot_agent_api::ContractError::BindingMismatch,
                    ));
                }
                _ => {
                    let classified = unsupported_quarantine(
                        method,
                        UnsupportedEventReason::UnknownMethod,
                        Vec::new(),
                        omitted_top_level_keys(&params, &[]),
                    );
                    (
                        classified.payload,
                        classified.omitted_fields,
                        classified.warnings,
                        classified.privacy_class,
                        classified.coverage,
                    )
                }
            }
        }
    };

    let unsupported_disposition = match &payload {
        NormalizedHostEventPayload::UnsupportedQuarantined(_) => {
            UnsupportedDisposition::UnsupportedMethodQuarantined
        }
        _ => UnsupportedDisposition::None,
    };
    let input_digest: LowercaseSha256 = serde_json::from_value(Value::String(
        eliot_contracts::sha256_hex(input.raw_source_bytes),
    ))
    .map_err(|_| CodexAdapterError::Contract(eliot_agent_api::ContractError::DigestMismatch))?;
    let receipt = HostEventNormalizationReceipt {
        normalizer_identity: CODEX_NORMALIZER_IDENTITY.to_owned(),
        normalizer_version: CODEX_NORMALIZER_VERSION.to_owned(),
        input_handle: input.raw_source_handle.clone(),
        input_digest: QualifiedSourceDigest {
            algorithm: HOST_EVENT_DIGEST_ALGORITHM.to_owned(),
            digest: input_digest,
        },
        output_schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
        output_digest: serde_json::from_value(Value::String(
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ))
        .map_err(|_| CodexAdapterError::Contract(eliot_agent_api::ContractError::DigestMismatch))?,
        omitted_fields,
        warnings,
        unsupported_disposition,
        privacy_class,
        coverage,
        proof_ceiling: eliot_agent_api::ProofCeiling::Observation,
    };
    let admitted_route_digest = input
        .admission
        .map(|admission| admission.self_digest.clone());
    let mut envelope = NormalizedHostEventEnvelope {
        schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
        event_id: input.event_id,
        cursor: input.cursor,
        lineage: input.lineage,
        producer_adapter_identity: CODEX_NORMALIZER_IDENTITY.to_owned(),
        adapter_contract_version: CODEX_NORMALIZER_VERSION.to_owned(),
        sequence: input.sequence,
        causal_predecessors: input.predecessors,
        payload,
        admitted_route_digest,
        raw_source: RawSourceRecord {
            handle: input.raw_source_handle,
            digest: receipt.input_digest.clone(),
        },
        normalization: receipt,
        observed_at: input.observed_at,
        delivery: input.delivery,
    };
    envelope
        .seal()
        .map_err(|_| CodexAdapterError::MalformedWire("event serialization"))?;
    match envelope.lineage.attributable_binding() {
        Ok(binding) => {
            let admission = input
                .admission
                .ok_or(CodexAdapterError::InvalidInput("admission/lineage"))?;
            envelope
                .validate_for_lineage(binding, admission)
                .map_err(CodexAdapterError::Contract)?;
        }
        Err(_) => {
            envelope
                .validate_as_session_observation()
                .map_err(CodexAdapterError::Contract)?;
        }
    }
    let receipt = envelope.normalization.clone();
    Ok((envelope, receipt))
}

/// Whether a wire method needs execution-unit lineage (i.e. its typed payload
/// requires attempt authority). Session-only callers with such methods fail
/// closed instead of inventing binding.
fn classify_needs_execution_unit(method: &str, params: &Value) -> bool {
    match method {
        "thread/started" | "thread/resumed" => false,
        "turn/started" | "turn/created" => true,
        "item/agentMessage/delta"
        | "item/assistantMessage/delta"
        | "item/reasoningSummary/delta"
        | "item/reasoning/delta"
        | "item/commandExecution/requestApproval"
        | "item/toolCall"
        | "item/commandExecution/finished"
        | "item/toolResult"
        | "turn/failed"
        | "error"
        | "turn/usage"
        | "usage" => true,
        "turn/completed" => terminal_status_from(params).is_some(),
        _ => false,
    }
}

/// Result input owned by the caller, assembled from a complete event stream.
/// The adapter refuses to infer completion from an incomplete stream: the
/// terminal observation is the exact bound envelope from the validated stream,
/// not a boolean completion claim. `None` means no terminal observation was
/// recorded and yields unknown outcome.
#[derive(Clone, Debug)]
pub struct CodexResultInput {
    pub route: RouteFingerprint,
    pub session: CodexSessionBinding,
    pub output: Option<String>,
    pub terminal_observation: Option<NormalizedHostEventEnvelope>,
    pub cancelled: bool,
    pub unknown_reason: Option<String>,
    pub usage: UsageReceipt,
    pub continuation: Option<RouteContinuationLocator>,
    pub proposed_effects: Vec<eliot_agent_api::ProposedEffect>,
}

fn is_terminal_observation(payload: &NormalizedHostEventPayload) -> bool {
    matches!(
        payload,
        NormalizedHostEventPayload::ProviderTerminalObserved(observation)
            if matches!(
                observation.status,
                ProviderTerminalStatus::CompletedObserved
                    | ProviderTerminalStatus::FailedObserved
            )
    )
}

/// Validate a supplied terminal observation against the recorded binding: the
/// envelope must carry attributable execution-unit lineage for exactly this
/// binding (a same-thread turn B observation never yields attempt A output)
/// and must be terminal (observed completed/failed, never a quarantined,
/// usage, or session observation). Provider-effect/attempt linkage beyond this
/// stays with S5 (`AgentResult::validate_for_binding`).
fn validate_terminal_observation(
    terminal: &NormalizedHostEventEnvelope,
    binding: &ProviderExecutionBinding,
    admission: &AdmittedRouteReceipt,
) -> Result<(), CodexAdapterError> {
    terminal
        .validate_for_lineage(binding, admission)
        .map_err(CodexAdapterError::Contract)?;
    let observed_binding = terminal
        .lineage
        .attributable_binding()
        .map_err(CodexAdapterError::Contract)?;
    if observed_binding != binding {
        return Err(CodexAdapterError::Contract(
            eliot_agent_api::ContractError::BindingMismatch,
        ));
    }
    if !is_terminal_observation(&terminal.payload) {
        return Err(CodexAdapterError::MalformedWire(
            "result terminal observation is not terminal",
        ));
    }
    Ok(())
}

/// Translate a complete Codex result into the neutral result contract.
///
/// Attempt identity comes from the recorded `binding`, never from an ambient
/// parameter. Session/route inputs must agree with that binding, and the
/// observed route is never defaulted from the requested route: the physical
/// observation is always `UNOBSERVED` with an explicit reason (the adapter
/// records no separate physical route), and the admitted/binding linkage is
/// enforced via `validate_against(binding, admission)`.
pub fn translate_result(
    input: CodexResultInput,
    binding: &ProviderExecutionBinding,
    admission: &AdmittedRouteReceipt,
    authority: &EffectCeiling,
) -> Result<AgentResult, CodexAdapterError> {
    validate_codex_route(&input.route)?;
    input.session.validate(&input.route)?;
    validate_binding_for_codex(binding)?;
    if input.route != binding.route {
        return Err(CodexAdapterError::Contract(
            eliot_agent_api::ContractError::BindingMismatch,
        ));
    }
    validate_session_locator_against_binding(&input.session, binding)?;
    if let Some(locator) = &input.continuation {
        if locator.route != input.route {
            return Err(CodexAdapterError::RouteMismatch);
        }
        locator.validate()?;
    }
    if let Some(terminal) = &input.terminal_observation {
        validate_terminal_observation(terminal, binding, admission)?;
    }
    let output_digest = input
        .output
        .as_deref()
        .map(|text| blake3::hash(text.as_bytes()).to_hex().to_string());
    let mut evidence_refs = output_digest
        .into_iter()
        .map(|digest| format!("codex-output:{digest}"))
        .collect::<Vec<_>>();
    if evidence_refs.is_empty()
        && let Some(terminal) = &input.terminal_observation
    {
        evidence_refs.push(format!("codex-terminal:{}", terminal.event_id.as_str()));
    }
    let (disposition, unknown_reason) = if input.cancelled {
        (ResultDisposition::CancelledObserved, input.unknown_reason)
    } else if input.terminal_observation.is_none() {
        (
            ResultDisposition::UnknownOutcome,
            Some(
                input
                    .unknown_reason
                    .unwrap_or_else(|| "terminal observation absent".into()),
            ),
        )
    } else {
        (ResultDisposition::Partial, input.unknown_reason)
    };
    let zero_digest: LowercaseSha256 = serde_json::from_value(serde_json::Value::String(
        "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
    ))
    .map_err(|_| CodexAdapterError::Contract(eliot_agent_api::ContractError::DigestMismatch))?;
    // Binding-gated physical observation: UNOBSERVED with explicit reason,
    // never observed=requested. Cancelled carries observed cancellation;
    // all other outcomes stay UNKNOWN_OUTCOME with a quarantine recovery
    // handle, preserving evidence without fabricating wall time.
    let (execution_outcome, cancellation, recovery_ref) = if input.cancelled {
        (
            ExecutionOutcome::Observed,
            Some(CancellationState::Acknowledged),
            None,
        )
    } else if input.terminal_observation.is_some() {
        let handle = input
            .terminal_observation
            .as_ref()
            .map(|terminal| format!("codex-terminal:{}", terminal.event_id.as_str()))
            .unwrap_or_else(|| "codex-partial-recovery".to_owned());
        (ExecutionOutcome::UnknownOutcome, None, Some(handle))
    } else {
        (
            ExecutionOutcome::UnknownOutcome,
            None,
            Some(
                unknown_reason
                    .clone()
                    .unwrap_or_else(|| "terminal observation absent".to_owned()),
            ),
        )
    };
    let mut actual_route = PhysicalRouteObservationReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        attempt_id: binding.attempt_id.clone(),
        state_fence: binding.state_fence.clone(),
        runtime_generation: binding.runtime_generation,
        admitted_route_digest: admission.self_digest.clone(),
        binding: binding.clone(),
        requested_route: input.route.clone(),
        observed_route: None,
        route_state: RouteObservationState::Unobserved,
        diverged_fields: Vec::new(),
        execution_outcome,
        request_digest: zero_digest,
        translation_digest: None,
        raw_evidence_digest: None,
        raw_evidence_ref: None,
        usage: input.usage.clone(),
        started: ClockReading::default(),
        first_byte: ClockReading::default(),
        first_semantic: ClockReading::default(),
        terminal: ClockReading::default(),
        event_cursor: EventCursor::new("codex-result")?,
        event_sequence: 1,
        cancellation,
        unobserved_reason: Some(
            "codex physical route not separately observed; requested retained without synthesis"
                .to_owned(),
        ),
        recovery_ref,
        safe_public_error: None,
        restricted_raw_error_ref: None,
        self_digest: serde_json::from_value(serde_json::Value::String(
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ))
        .map_err(|_| CodexAdapterError::Contract(eliot_agent_api::ContractError::DigestMismatch))?,
    };
    actual_route.self_digest = actual_route
        .compute_digest()
        .map_err(|_| CodexAdapterError::Contract(eliot_agent_api::ContractError::DigestMismatch))?;
    // Enforce exact binding/attempt/lease/fence/generation/admission
    // agreement and requested==admitted-selected; forged or mismatched
    // linkage fails closed here, never at a later intake.
    actual_route.validate_against(binding, admission)?;
    let result = AgentResult {
        attempt_id: binding.attempt_id.clone(),
        disposition,
        artifacts: Vec::new(),
        evidence_refs,
        proposed_effects: input.proposed_effects,
        unresolved_questions: Vec::new(),
        usage: input.usage.clone(),
        actual_route,
        unknown_reason,
    };
    result.validate(authority)?;
    Ok(result)
}

/// Checked interrupt construction: targets the exact bound turn on the exact
/// bound thread. A sessionless binding cannot address a Codex turn and fails
/// closed; the request ID follows the validated wire-ID shape so the later
/// start/interrupt reply correlates with the real parser.
pub fn turn_interrupt_bound(
    request_id: &str,
    binding: &ProviderExecutionBinding,
) -> Result<CodexWireMessage, CodexAdapterError> {
    if !valid_wire_id_text(request_id) {
        return Err(CodexAdapterError::MalformedWire(
            "id must be a supported string",
        ));
    }
    validate_binding_for_codex(binding)?;
    let NativeSession::Native(locator) = &binding.native_session else {
        return Err(CodexAdapterError::SessionMismatch);
    };
    Ok(CodexWireMessage::turn_interrupt(
        request_id,
        locator.locator.as_str(),
        binding.execution_unit.unit_id.as_str(),
    ))
}

/// Translate a provider continuation locator into A-01 continuation state.
pub fn translate_continuation(
    route: &RouteFingerprint,
    external_locator: impl Into<String>,
    checkpoint_digest: impl Into<String>,
    expires_at: impl Into<String>,
) -> Result<RouteContinuationLocator, CodexAdapterError> {
    validate_codex_route(route)?;
    let locator = RouteContinuationLocator {
        route: route.clone(),
        external_locator: external_locator.into(),
        checkpoint_digest: checkpoint_digest.into(),
        expires_at: expires_at.into(),
    };
    locator.validate()?;
    Ok(locator)
}

/// Stable JSON schema for the private wire envelope, useful to probes and
/// compatibility fixtures without exporting vendor SDK definitions.
pub fn wire_schema() -> Value {
    let mut object = Map::new();
    object.insert(
        "schema_version".into(),
        Value::String(CODEX_WIRE_SCHEMA_VERSION.into()),
    );
    object.insert("adapter".into(), Value::String(CODEX_ADAPTER_ID.into()));
    object.insert(
        "transport".into(),
        Value::String(CODEX_PROTOCOL_TRANSPORT.into()),
    );
    object.insert("max_line_bytes".into(), Value::from(MAX_JSONL_LINE_BYTES));
    Value::Object(object)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]
mod tests {
    use super::*;
    use eliot_agent_api::{
        EventCursor, ExecutionUnit, ExecutionUnitObservation, NativeSessionLocator,
        SessionObservation,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use eliot_agent_api::{
        BudgetEnvelope, EffectKind, EpochId, LaunchRequestId, QuotaKnowledge, ResourceGeneration,
        StateFence, WorkUnitId,
    };
    use eliot_contracts::EpochLineageId;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, OperationId, PermitIssuance, PhysicalProcessBinding,
        ProcessExecutionView, ProcessHealth, ProcessHealthStatus, ProcessId, ProcessIntent,
        ProcessState, ProcessTreeId, ResourceLimits, SessionId as ProcessSessionId,
        SuspendedProcessIdentity,
    };
    use eliot_source_assurance::{
        AdmissibleUse, AxisStatus, GoverningSourceIdentity, GoverningSourceSet, InstructionTaint,
        PrivacyClass, QuarantineStatus, SOURCE_ASSURANCE_SCHEMA_VERSION, ScopeBindingProof,
        SourceFrontierBinding, SourceProvenance, SourceSnapshotBinding, SourceTrustProfile,
        ThreatStatus,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn fixture_digest(seed: &str) -> LowercaseSha256 {
        serde_json::from_value(serde_json::json!(eliot_contracts::sha256_hex(
            format!("codex-fixture-{seed}").as_bytes()
        )))
        .expect("valid fixture digest")
    }

    fn route() -> RouteFingerprint {
        codex_route(
            fixture_digest("runtime"),
            fixture_digest("adapter"),
            "provider",
            "model",
            "subscription",
            fixture_digest("serializer"),
            fixture_digest("tools"),
            "visible",
            "native_resume",
            fixture_digest("features"),
        )
    }

    fn budget() -> BudgetEnvelope {
        BudgetEnvelope {
            context_tokens: 100,
            wall_time_ms: 1_000,
            output_bytes: 10_000,
            cost_microunits: 10,
            max_depth: 1,
            max_descendants: 1,
        }
    }

    fn ceiling() -> EffectCeiling {
        EffectCeiling {
            scope_ref: "scope-1".into(),
            allowed: BTreeSet::from([EffectKind::Observe]),
            max_external_effects: 0,
        }
    }

    fn source() -> TestResult<(SourceAssurance, AdmissionExpectation)> {
        let digest = |text: &str| blake3::hash(text.as_bytes()).to_hex().to_string();
        let member = GoverningSourceIdentity {
            source_id: "architecture".into(),
            kind: "governing".into(),
            canonical_ref: "architecture".into(),
            content_digest: digest("architecture"),
            origin_ref: "origin".into(),
            revision: "r1".into(),
        };
        let sources = GoverningSourceSet::new("sources", "r1", vec![member])?;
        let frontier = SourceFrontierBinding {
            frontier_id: "frontier".into(),
            workspace_identity: "workspace".into(),
            repository_revision: "revision".into(),
            dirty_state_digest: digest("dirty"),
            generation: 1,
        };
        let frontier_digest = blake3::hash(&serde_json::to_vec(&frontier)?)
            .to_hex()
            .to_string();
        let scope = ScopeBindingProof {
            expected_scope: "scope-1".into(),
            observed_scope: "scope-1".into(),
            expected_generation: 1,
            observed_generation: 1,
            evidence_digest: digest("scope"),
        };
        let assurance = SourceAssurance {
            schema_version: SOURCE_ASSURANCE_SCHEMA_VERSION.into(),
            governing_sources: sources,
            provenance: SourceProvenance {
                producer: "test".into(),
                acquisition_ref: "capture".into(),
                lineage_digest: digest("lineage"),
                authentication_ref: "auth".into(),
            },
            trust: SourceTrustProfile {
                integrity: AxisStatus::Verified,
                freshness: AxisStatus::Verified,
                competence: AxisStatus::Verified,
                incentives: AxisStatus::Verified,
                independence: AxisStatus::Verified,
                privacy: PrivacyClass::Internal,
                instruction_taint: InstructionTaint::InstructionChannel,
                threat: ThreatStatus::NoneObserved,
            },
            quarantine: QuarantineStatus::Clear,
            snapshot: SourceSnapshotBinding {
                snapshot_id: "snapshot".into(),
                source_set_id: "sources".into(),
                source_set_revision: "r1".into(),
                content_digest: digest("snapshot"),
                frontier_digest,
                state_fence: "fence".into(),
            },
            frontier: frontier.clone(),
            scope: scope.clone(),
            requested_use: AdmissibleUse::Evidence,
            effect_ceiling: eliot_source_assurance::EffectCeiling::ReadOnlyCandidate,
        };
        let expectation = AdmissionExpectation {
            source_set_id: "sources".into(),
            source_set_revision: "r1".into(),
            frontier,
            scope,
        };
        Ok((assurance, expectation))
    }

    fn process_request() -> TestResult<ProcessRequest> {
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            OperationId::new("op-1")?,
            ProcessTreeId::new("tree-1")?,
            JobId::new("job-1")?,
            ImageId::new("image-1")?,
            ProcessSessionId::new("session-1")?,
            generation,
            "codex-app-server",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            vec!["--stdio".into()],
            "C:\\workspace",
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)?,
            ResourceLimits::new(1_000, None, None, 10_000, 10_000, 1)?,
        )?;
        let fence = FencingToken::new(test_epoch(TEST_LINEAGE_A, 1), generation, "nonce")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("codex-authority")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("codex-lease")?,
                fence,
                revisions(),
                100,
                10_000,
                "codex-nonce-1",
            )?,
        )?;
        Ok(ProcessRequest::new(intent, permit)?)
    }

    fn revisions() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ])
    }

    fn validated_process_state(
        request: ProcessRequest,
    ) -> Result<ProcessState, ProcessExecutionError> {
        let intent = request.intent().clone();
        let fence = request.fence().clone();
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("codex-authority")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let _permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("codex-lease")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "codex-nonce-1",
            )?,
        )?;
        let observed = SuspendedProcessIdentity::new(
            ProcessId::new("process-1")?,
            intent.process_tree_id().clone(),
            intent.job_id().clone(),
            intent.image_id().clone(),
            intent.session_id().clone(),
            intent.generation(),
            PhysicalProcessBinding::new(4242, 11, intent.executable(), r"Local\Eliot-Codex-Test")?,
            120,
            intent.executable_sha256(),
        )?;
        let clock = serde_json::from_value(serde_json::json!({
            "valid_time_ms": 150,
            "known_time_ms": 150,
            "transaction_sequence": null,
            "monotonic_ns": 1
        }))
        .map_err(|_| ProcessExecutionError::Unavailable("fixture clock".to_owned()))?;
        let context = DispatchValidationContext::new(
            clock,
            fence,
            test_epoch(TEST_LINEAGE_A, 1),
            revisions(),
            41,
        )?;
        let validated = authority.validate_and_consume(request, observed, &context)?;
        let mut state = ProcessState::from_validated(&validated);
        state.mark_resumed(
            151,
            ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)?,
        )?;
        Ok(state)
    }

    fn launch() -> TestResult<AgentLaunchRequest> {
        Ok(AgentLaunchRequest {
            id: LaunchRequestId::new("launch-1")?,
            task_id: eliot_agent_api::TaskId::new("task-1")?,
            parent_attempt: None,
            work_units: vec![AgentWorkUnitBrief {
                id: WorkUnitId::new("unit-1")?,
                objective: "observe".into(),
                causal_property: "adapter".into(),
                scope_ref: "scope-1".into(),
                expected_outputs: vec!["result".into()],
                source_refs: vec!["architecture".into()],
                verifier_ref: "test".into(),
                integration_owner: "owner".into(),
                contract_revision: "v1".into(),
                budget: budget(),
                effect_ceiling: ceiling(),
                stop_condition: "test".into(),
            }],
            required_competence: vec!["codex".into()],
            allowed_route_classes: vec![CODEX_ROUTE_CLASS.into()],
            native_child_policy: "none".into(),
            root_context_revision: "context-1".into(),
            context_budget: budget(),
            evidence_capability_refs: vec!["source".into()],
            privacy_profile: "internal".into(),
            effect_ceiling: ceiling(),
            max_depth: 1,
            max_fanout: 1,
            cumulative_descendant_budget: budget(),
            verifier_ref: "test".into(),
            synthesis_owner: "owner".into(),
            integration_owner: "owner".into(),
            cancellation_policy: "reconcile".into(),
        })
    }

    fn attached() -> TestResult<CodexAttachReceipt> {
        let (source_assurance, source_expectation) = source()?;
        Ok(attach(CodexAttachInput {
            launch: launch()?,
            authority: AuthorityEnvelope {
                epoch: test_epoch(TEST_LINEAGE_A, 1),
                scope_ref: "scope-1".into(),
                effect_ceiling: ceiling(),
                lease: serde_json::from_value::<WorkLeaseId>(
                    serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
                )?,
                state_fence: StateFence::new(
                    test_epoch(TEST_LINEAGE_A, 1),
                    ResourceGeneration::new(1)?,
                ),
                valid_until: "never".into(),
            },
            route: route(),
            session: CodexSessionBinding {
                session_id: SessionId::new("session-1")?,
                thread_id: "thread-1".into(),
                runtime_hash: fixture_digest("runtime"),
                working_directory: "C:\\workspace".into(),
            },
            process_request: process_request()?,
            source_assurance,
            source_expectation,
        })?)
    }

    struct Sink;
    impl ProcessEvidenceSink for Sink {
        fn record(
            &self,
            _evidence: ProcessEvidence,
        ) -> Result<(), eliot_process::EvidenceSinkError> {
            Ok(())
        }
    }

    struct FakeExecutor {
        starts: AtomicUsize,
    }
    impl ProcessExecutor for FakeExecutor {
        async fn start(
            &self,
            request: ProcessRequest,
            _sink: Arc<dyn ProcessEvidenceSink>,
        ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            let state = validated_process_state(request)?;
            ProcessStartReceipt::new(&state).map_err(ProcessExecutionError::from)
        }
        async fn inspect(
            &self,
            _operation_id: eliot_process::OperationId,
        ) -> Result<ProcessExecutionView, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable("fixture".into()))
        }
        async fn cancel(
            &self,
            _operation_id: eliot_process::OperationId,
        ) -> Result<CancellationReceipt, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable("fixture".into()))
        }
        async fn reconcile(
            &self,
            _operation_id: eliot_process::OperationId,
        ) -> Result<ProcessEvidence, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable("fixture".into()))
        }
    }

    #[test]
    fn exact_route_and_wire_schema_are_stable() -> TestResult {
        assert_eq!(route().adapter, CODEX_ADAPTER_ID);
        assert_eq!(wire_schema()["schema_version"], CODEX_WIRE_SCHEMA_VERSION);
        let message = CodexWireMessage::parse_line(br#"{"id":"1","result":{"ok":true}}"#)?;
        assert!(correlate_response(&message, "1").is_ok());
        Ok(())
    }

    #[test]
    fn stable_wire_omits_legacy_headers_and_exposes_zero_model_requests() -> TestResult {
        let initialize = serde_json::to_value(CodexWireMessage::initialize(
            "initialize-1",
            "eliot",
            "0.1.0",
        ))?;
        assert_eq!(initialize["method"], "initialize");
        assert!(initialize.get("jsonrpc").is_none());
        assert!(initialize.get("result").is_none());
        assert!(initialize["params"].get("protocolVersion").is_none());
        assert_eq!(
            initialize["params"]["capabilities"]["experimentalApi"],
            false
        );

        let initialized = serde_json::to_value(CodexWireMessage::initialized())?;
        assert_eq!(initialized["method"], "initialized");
        assert!(initialized.get("id").is_none());
        assert!(initialized.get("params").is_none());
        assert!(initialized.get("jsonrpc").is_none());

        let model_list = serde_json::to_value(CodexWireMessage::model_list(
            "models-1",
            Some("cursor-1"),
            true,
            Some(64),
        ))?;
        assert_eq!(model_list["method"], "model/list");
        assert_eq!(model_list["params"]["cursor"], "cursor-1");
        assert_eq!(model_list["params"]["includeHidden"], true);
        assert_eq!(model_list["params"]["limit"], 64);

        let quota = serde_json::to_value(CodexWireMessage::account_rate_limits("quota-1"))?;
        assert_eq!(quota["method"], "account/rateLimits/read");
        assert!(quota.get("jsonrpc").is_none());

        assert!(
            CodexWireMessage::parse_line(br#"{"jsonrpc":"2.0","id":"legacy","result":{}}"#)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn malformed_and_ambiguous_wire_are_rejected() -> TestResult {
        assert!(CodexWireMessage::parse_line(br#"{"id":"1","result":{},"error":{}}"#).is_err());
        assert!(CodexWireMessage::parse_line(br"[]").is_err());
        let message = CodexWireMessage::parse_line(br#"{"id":"other","result":{}}"#)?;
        assert!(matches!(
            correlate_response(&message, "1"),
            Err(CodexAdapterError::ResponseCorrelation { .. })
        ));
        Ok(())
    }

    #[test]
    fn wire_grammar_matrix_is_closed_and_disjoint() {
        for valid in [
            br#"{"id":"1","method":"turn/start"}"#.as_slice(),
            br#"{"id":"request_1.2","method":"model/list","params":{}}"#.as_slice(),
            br#"{"method":"initialized"}"#.as_slice(),
            br#"{"type":"notification","method":"initialized","params":[]}"#.as_slice(),
            br#"{"type":"request","id":"request-1","method":"thread/start","params":{}}"#
                .as_slice(),
            br#"{"id":"response-1","result":{}}"#.as_slice(),
            br#"{"type":"response","id":"response-1","error":{"code":1}}"#.as_slice(),
        ] {
            assert!(
                CodexWireMessage::parse_line(valid).is_ok(),
                "valid wire: {valid:?}"
            );
        }

        for invalid in [
            br"{}".as_slice(),
            br#"{"id":null,"method":"x"}"#,
            br#"{"id":1,"result":{}}"#,
            br#"{"id":true,"result":{}}"#,
            br#"{"id":{},"result":{}}"#,
            br#"{"id":[],"result":{}}"#,
            br#"{"id":"","result":{}}"#,
            br#"{"id":"bad id","result":{}}"#,
            br#"{"id":"bad/id","result":{}}"#,
            br#"{"id":"1","method":""}"#,
            br#"{"id":"1","method":42}"#,
            br#"{"id":"1","method":"bad method"}"#,
            br#"{"method":null}"#,
            br#"{"method":"x","params":null}"#,
            br#"{"id":"1","result":null}"#,
            br#"{"id":"1","error":null}"#,
            br#"{"id":"1","result":{},"error":{}}"#,
            br#"{"id":"1","method":"x","result":{}}"#,
            br#"{"id":"1","method":"x","params":{},"result":{}}"#,
            br#"{"method":"x","result":{}}"#,
            br#"{"result":{}}"#,
            br#"{"type":null,"method":"x"}"#,
            br#"{"type":"","method":"x"}"#,
            br#"{"type":"request","method":"x"}"#,
            br#"{"type":"response","id":"1","method":"x"}"#,
            br#"{"type":"notification","id":"1","method":"x"}"#,
            br#"{"type":"unsupported","method":"x"}"#,
            br#"{"jsonrpc":"2.0","id":"1","result":{}}"#,
        ] {
            assert!(
                CodexWireMessage::parse_line(invalid).is_err(),
                "invalid wire accepted: {invalid:?}"
            );
        }
    }

    #[test]
    fn response_correlation_rejects_request_and_notification_fields() {
        let request = CodexWireMessage::request("response-1", "turn/start", serde_json::json!({}));
        assert!(matches!(
            correlate_response(&request, "response-1"),
            Err(CodexAdapterError::MalformedWire(_))
        ));

        let mixed = CodexWireMessage {
            id: Some(Value::String("response-1".into())),
            message_type: Some("response".into()),
            method: Some("turn/start".into()),
            params: Some(serde_json::json!({})),
            result: Some(serde_json::json!({})),
            error: None,
        };
        assert!(matches!(
            correlate_response(&mixed, "response-1"),
            Err(CodexAdapterError::MalformedWire(_))
        ));

        let notification = CodexWireMessage::notification("turn/completed", None);
        assert!(matches!(
            correlate_response(&notification, "response-1"),
            Err(CodexAdapterError::MalformedWire(_))
        ));
    }

    #[test]
    fn wire_size_limit_is_checked_before_decoding() {
        let oversized = vec![b' '; MAX_JSONL_LINE_BYTES + 1];
        assert!(matches!(
            CodexWireMessage::parse_line(&oversized),
            Err(CodexAdapterError::WireTooLarge)
        ));
    }

    #[test]
    fn stale_route_and_authority_widening_fail_closed() -> TestResult {
        let mut bad = attached()?;
        bad.route.host_family = "other".into();
        assert!(matches!(
            translate_continuation(&bad.route, "x", "y", "z"),
            Err(CodexAdapterError::RouteMismatch)
        ));
        let input = launch()?;
        let mut authority = attached()?.authority.clone();
        authority
            .effect_ceiling
            .allowed
            .insert(EffectKind::ProcessExecution);
        let (source_assurance, source_expectation) = source()?;
        let result = attach(CodexAttachInput {
            launch: input,
            authority,
            route: route(),
            session: attached()?.session.clone(),
            process_request: process_request()?,
            source_assurance,
            source_expectation,
        });
        assert!(matches!(
            result,
            Err(CodexAdapterError::Contract(
                eliot_agent_api::ContractError::InsufficientAuthority
            ))
        ));
        Ok(())
    }

    fn bound_binding() -> TestResult<ProviderExecutionBinding> {
        Ok(ProviderExecutionBinding {
            attempt_id: AttemptId::new("attempt-1")?,
            lease_id: serde_json::from_value::<WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
            )?,
            state_fence: eliot_contracts::StateFence::new(
                test_epoch(TEST_LINEAGE_A, 1),
                eliot_contracts::ResourceGeneration::new(1)?,
            ),
            runtime_generation: eliot_contracts::ResourceGeneration::new(1)?,
            route: route(),
            session_id: Some(SessionId::new("session-1")?),
            provider_scope_ref: "scope-1".into(),
            native_session: NativeSession::Native(NativeSessionLocator::new("thread-1")?),
            execution_unit: ExecutionUnit::new("codex", "turn-1")?,
            start_request_id: eliot_contracts::RequestId::new("req-1")?,
            start_request_sha256: eliot_contracts::sha256_hex(b"req-1"),
        })
    }

    fn admission_for(binding: &ProviderExecutionBinding) -> TestResult<AdmittedRouteReceipt> {
        use eliot_agent_api::{
            CandidateSelectionDisposition, PolicyRevision, RouteSelectionCandidate,
            candidate_digest_for,
        };
        use eliot_contracts::DecisionId;
        let candidate = RouteSelectionCandidate {
            capability: "codex".to_owned(),
            query_intent: "test-intent".to_owned(),
            scope_ref: "scope:test".to_owned(),
            policy_revision: PolicyRevision::new(3)?,
            candidates: vec![binding.route.clone()],
            selected: Some(binding.route.clone()),
            rejected: Vec::new(),
            selection: CandidateSelectionDisposition::Selected,
            evidence_refs: vec!["evidence-1".to_owned()],
        };
        candidate.validate()?;
        let zero: LowercaseSha256 = serde_json::from_value(serde_json::json!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ))?;
        let mut receipt = AdmittedRouteReceipt {
            schema_version: CONTRACT_VERSION.to_owned(),
            decision_id: DecisionId::new("decision-1")?,
            candidate_digest: candidate_digest_for(&candidate)?,
            attempt_id: binding.attempt_id.clone(),
            lease_id: binding.lease_id.clone(),
            state_fence: binding.state_fence.clone(),
            runtime_generation: binding.runtime_generation,
            policy_revision: PolicyRevision::new(3)?,
            requested_route: binding.route.clone(),
            selected_route: Some(binding.route.clone()),
            no_route: None,
            evidence_refs: vec!["evidence-1".to_owned()],
            proof_ceiling: eliot_agent_api::ProofCeiling::CandidateArtifact,
            self_digest: zero,
        };
        receipt.self_digest = receipt.compute_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn bound_lineage(
        binding: &ProviderExecutionBinding,
        sequence: u64,
    ) -> TestResult<ProviderObservationLineage> {
        Ok(ProviderObservationLineage::ExecutionUnitObservation(
            Box::new(ExecutionUnitObservation {
                binding: binding.clone(),
                cursor: EventCursor::new(format!("turn-1:{sequence}"))?,
                sequence,
            }),
        ))
    }

    fn clock_at(valid_time_ms: Option<i64>) -> ClockReading {
        ClockReading {
            valid_time_ms,
            known_time_ms: valid_time_ms,
            transaction_sequence: None,
            monotonic_ns: Some(1),
        }
    }

    fn normalize_bound(
        method: &str,
        params: Value,
        binding: &ProviderExecutionBinding,
        admission: &AdmittedRouteReceipt,
        sequence: u64,
        previous_sequence: Option<u64>,
    ) -> Result<(NormalizedHostEventEnvelope, HostEventNormalizationReceipt), CodexAdapterError>
    {
        // Keep the owned message alive for the input lifetime.
        let message = CodexWireMessage::notification(method, Some(params));
        let raw_source_bytes = serde_json::to_vec(&message)
            .map_err(|_| CodexAdapterError::MalformedWire("event serialization"))?;
        // Leak-free: normalize within this scope via a helper that owns bytes.
        normalize_bound_with_bytes(
            message,
            raw_source_bytes,
            binding,
            admission,
            sequence,
            previous_sequence,
            clock_at(Some(1_786_000_000_000)),
        )
    }

    fn normalize_bound_with_bytes(
        message: CodexWireMessage,
        raw_source_bytes: Vec<u8>,
        binding: &ProviderExecutionBinding,
        admission: &AdmittedRouteReceipt,
        sequence: u64,
        previous_sequence: Option<u64>,
        observed_at: ClockReading,
    ) -> Result<(NormalizedHostEventEnvelope, HostEventNormalizationReceipt), CodexAdapterError>
    {
        let lineage = bound_lineage(binding, sequence).expect("fixture lineage");
        let cursor = EventCursor::new(format!("turn-1:{sequence}")).expect("fixture cursor");
        let event_id = EventId::new(format!("turn-1:{sequence}")).expect("fixture event");
        // SAFETY: `raw_source_bytes` outlives the call; the input borrows it.
        // To satisfy the borrow checker without unsafe, re-serialize inside:
        // the canonical raw bytes are the JSON serialization of the message.
        // We pass a reference to the local bytes (which lives for the call).
        let handle = RestrictedRawSourceHandle::new(format!("restricted-codex:turn-1:{sequence}"))
            .expect("fixture handle");
        normalize_codex_event(CodexHostEventInput {
            message: &message,
            lineage,
            event_id,
            cursor,
            sequence,
            previous_sequence,
            predecessors: Vec::new(),
            raw_source_bytes: &raw_source_bytes,
            raw_source_handle: handle,
            observed_at,
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: Some(admission),
        })
    }

    // Legacy name kept for minimal churn in existing test bodies: forwards to
    // the typed normalizer and returns the envelope (receipt discarded by
    // callers that only assert on envelope fields). New tests use
    // `normalize_bound` directly to assert on receipts.
    fn translate_bound(
        method: &str,
        params: Value,
        binding: &ProviderExecutionBinding,
        sequence: u64,
        previous_sequence: Option<u64>,
    ) -> Result<NormalizedHostEventEnvelope, CodexAdapterError> {
        let admission = admission_for(binding).expect("fixture admission");
        Ok(normalize_bound(
            method,
            params,
            binding,
            &admission,
            sequence,
            previous_sequence,
        )?
        .0)
    }

    fn completed_params(thread: &str, turn: &str, status: &str) -> Value {
        serde_json::json!({
            "threadId": thread,
            "turn": {"id": turn, "status": status},
        })
    }

    fn is_binding_mismatch<T>(result: &Result<T, CodexAdapterError>) -> bool {
        matches!(
            result,
            Err(CodexAdapterError::Contract(
                eliot_agent_api::ContractError::BindingMismatch
            ))
        )
    }

    #[test]
    fn event_from_wrong_session_is_rejected() -> TestResult {
        let binding = bound_binding()?;
        let admission = admission_for(&binding)?;
        let message = CodexWireMessage::notification(
            "turn/completed",
            Some(completed_params("other-thread", "turn-1", "completed")),
        );
        let raw = serde_json::to_vec(&message)?;
        assert!(matches!(
            normalize_codex_event(CodexHostEventInput {
                message: &message,
                lineage: bound_lineage(&binding, 1)?,
                event_id: EventId::new("turn-1:1")?,
                cursor: EventCursor::new("turn-1:1")?,
                sequence: 1,
                previous_sequence: None,
                predecessors: Vec::new(),
                raw_source_bytes: &raw,
                raw_source_handle: RestrictedRawSourceHandle::new(
                    "restricted-codex:test-wrong-session"
                )?,
                observed_at: clock_at(Some(1_786_000_000_000)),
                delivery: HostEventDeliveryDisposition::BestEffortOrdered,
                admission: Some(&admission),
            }),
            Err(CodexAdapterError::SessionMismatch)
        ));
        Ok(())
    }

    #[test]
    fn event_session_fields_are_typed_and_event_shape_is_notification_only() -> TestResult {
        let binding = bound_binding()?;
        let admission = admission_for(&binding)?;
        let wrong_type = CodexWireMessage::notification(
            "turn/completed",
            Some(serde_json::json!({ "threadId": 42 })),
        );
        let raw_wrong = serde_json::to_vec(&wrong_type)?;
        assert!(matches!(
            normalize_codex_event(CodexHostEventInput {
                message: &wrong_type,
                lineage: bound_lineage(&binding, 1)?,
                event_id: EventId::new("turn-1:1")?,
                cursor: EventCursor::new("turn-1:1")?,
                sequence: 1,
                previous_sequence: None,
                predecessors: Vec::new(),
                raw_source_bytes: &raw_wrong,
                raw_source_handle: RestrictedRawSourceHandle::new(
                    "restricted-codex:test-wrong-type"
                )?,
                observed_at: clock_at(Some(1_786_000_000_000)),
                delivery: HostEventDeliveryDisposition::BestEffortOrdered,
                admission: Some(&admission),
            }),
            Err(CodexAdapterError::SessionMismatch)
        ));

        let request = CodexWireMessage::request(
            "event-1",
            "turn/completed",
            completed_params("thread-1", "turn-1", "completed"),
        );
        let raw_req = serde_json::to_vec(&request)?;
        assert!(matches!(
            normalize_codex_event(CodexHostEventInput {
                message: &request,
                lineage: bound_lineage(&binding, 1)?,
                event_id: EventId::new("turn-1:1")?,
                cursor: EventCursor::new("turn-1:1")?,
                sequence: 1,
                previous_sequence: None,
                predecessors: Vec::new(),
                raw_source_bytes: &raw_req,
                raw_source_handle: RestrictedRawSourceHandle::new(
                    "restricted-codex:test-request-shape"
                )?,
                observed_at: clock_at(Some(1_786_000_000_000)),
                delivery: HostEventDeliveryDisposition::BestEffortOrdered,
                admission: Some(&admission),
            }),
            Err(CodexAdapterError::MalformedWire(_))
        ));
        Ok(())
    }

    #[test]
    fn session_only_lineage_carries_no_attempt_authority() -> TestResult {
        let binding = bound_binding()?;
        let session_only = ProviderObservationLineage::SessionObservation(SessionObservation {
            session_id: binding.session_id.clone(),
            native: binding.native_session.clone(),
        });
        let message = CodexWireMessage::notification(
            "thread/started",
            Some(serde_json::json!({ "threadId": "thread-1" })),
        );
        let raw = serde_json::to_vec(&message)?;
        // Thread lifecycle stays session-only: typed session observation with
        // no admission reference and no attempt authority (never invented).
        let (envelope, receipt) = normalize_codex_event(CodexHostEventInput {
            message: &message,
            lineage: session_only.clone(),
            event_id: EventId::new("session-1:1")?,
            cursor: EventCursor::new("session-1:1")?,
            sequence: 1,
            previous_sequence: None,
            predecessors: Vec::new(),
            raw_source_bytes: &raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-codex:session-1")?,
            observed_at: clock_at(Some(1_786_000_000_000)),
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: None,
        })?;
        assert_eq!(envelope.normalization, receipt);
        envelope.validate_as_session_observation()?;
        assert!(envelope.admitted_route_digest.is_none());
        assert!(matches!(
            envelope.payload,
            NormalizedHostEventPayload::SessionLifecycle(_)
        ));
        // Session lineage never yields attributable execution binding.
        assert!(session_only.attributable_binding().is_err());
        assert!(envelope.lineage.attributable_binding().is_err());
        assert_eq!(
            envelope.producer_adapter_identity,
            CODEX_NORMALIZER_IDENTITY
        );
        assert_eq!(envelope.adapter_contract_version, CODEX_NORMALIZER_VERSION);
        Ok(())
    }

    #[test]
    fn missing_and_foreign_turns_quarantine_without_advancing() -> TestResult {
        let binding = bound_binding()?;
        // Same thread, foreign turn: never attempt A output.
        assert!(is_binding_mismatch(&translate_bound(
            "turn/completed",
            completed_params("thread-1", "turn-2", "completed"),
            &binding,
            1,
            None,
        )));
        // Same thread, missing turn: retained/quarantined, never guessed.
        assert!(is_binding_mismatch(&translate_bound(
            "turn/completed",
            serde_json::json!({ "threadId": "thread-1" }),
            &binding,
            1,
            None,
        )));
        // Same-turn steer keeps the same binding across the stream.
        let first = translate_bound(
            "turn/started",
            completed_params("thread-1", "turn-1", "inProgress"),
            &binding,
            1,
            None,
        )?;
        let second = translate_bound(
            "turn/completed",
            completed_params("thread-1", "turn-1", "completed"),
            &binding,
            2,
            Some(1),
        )?;
        let first_binding = first.lineage.attributable_binding()?;
        let second_binding = second.lineage.attributable_binding()?;
        assert_eq!(first_binding, &binding);
        assert_eq!(second_binding, &binding);
        assert!(matches!(
            first.payload,
            NormalizedHostEventPayload::ExecutionStarted(_)
        ));
        assert!(matches!(
            second.payload,
            NormalizedHostEventPayload::ProviderTerminalObserved(ref observation)
                if observation.status == ProviderTerminalStatus::CompletedObserved
        ));
        Ok(())
    }

    #[test]
    fn recorded_cursor_and_clock_are_preserved_without_synthesis() -> TestResult {
        let binding = bound_binding()?;
        let admission = admission_for(&binding)?;
        let envelope = translate_bound(
            "turn/completed",
            completed_params("thread-1", "turn-1", "completed"),
            &binding,
            3,
            Some(2),
        )?;
        // No synthesized `codex:{sequence}` identity: the recorded cursor is
        // preserved end-to-end for both cursor and event identity.
        assert_eq!(envelope.cursor.as_str(), "turn-1:3");
        assert_eq!(envelope.event_id.as_str(), "turn-1:3");
        assert_eq!(envelope.sequence, 3);
        assert_eq!(
            envelope.lineage.attributable_binding()?.attempt_id,
            binding.attempt_id
        );
        assert_eq!(
            envelope.admitted_route_digest.as_ref(),
            Some(&admission.self_digest)
        );
        assert_eq!(envelope.observed_at.valid_time_ms, Some(1_786_000_000_000));
        assert_eq!(envelope.lineage.attributable_binding()?, &binding);
        envelope.validate_for_lineage(&binding, &admission)?;
        // Unknown time stays unknown; causal order is never fabricated.
        let unknown_message = CodexWireMessage::notification(
            "turn/completed",
            Some(completed_params("thread-1", "turn-1", "completed")),
        );
        let unknown_raw = serde_json::to_vec(&unknown_message)?;
        let (unknown, _) = normalize_codex_event(CodexHostEventInput {
            message: &unknown_message,
            lineage: bound_lineage(&binding, 4)?,
            event_id: EventId::new("turn-1:4")?,
            cursor: EventCursor::new("turn-1:4")?,
            sequence: 4,
            previous_sequence: Some(3),
            predecessors: Vec::new(),
            raw_source_bytes: &unknown_raw,
            raw_source_handle: RestrictedRawSourceHandle::new(
                "restricted-codex:test-unknown-clock",
            )?,
            observed_at: clock_at(None),
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: Some(&admission),
        })?;
        assert_eq!(unknown.observed_at.valid_time_ms, None);
        // The recorded observation must agree with the claimed stream position.
        let mismatch_message = CodexWireMessage::notification(
            "turn/completed",
            Some(completed_params("thread-1", "turn-1", "completed")),
        );
        let mismatch_raw = serde_json::to_vec(&mismatch_message)?;
        assert!(is_binding_mismatch(&normalize_codex_event(
            CodexHostEventInput {
                message: &mismatch_message,
                lineage: bound_lineage(&binding, 9)?,
                event_id: EventId::new("turn-1:9")?,
                cursor: EventCursor::new("turn-1:9")?,
                sequence: 4,
                previous_sequence: Some(3),
                predecessors: Vec::new(),
                raw_source_bytes: &mismatch_raw,
                raw_source_handle: RestrictedRawSourceHandle::new(
                    "restricted-codex:test-position-mismatch",
                )?,
                observed_at: clock_at(Some(1_786_000_000_000)),
                delivery: HostEventDeliveryDisposition::BestEffortOrdered,
                admission: Some(&admission),
            }
        )));
        Ok(())
    }

    #[test]
    fn typed_normalizer_seals_receipt_and_preserves_recorded_cursor() -> TestResult {
        let binding = bound_binding()?;
        let admission = admission_for(&binding)?;
        let (envelope, receipt) = normalize_bound(
            "turn/completed",
            completed_params("thread-1", "turn-1", "completed"),
            &binding,
            &admission,
            1,
            None,
        )?;
        // Sealed receipt coherence: identity/version/digest/loss/privacy/ceiling.
        assert_eq!(envelope.normalization, receipt);
        assert_eq!(
            envelope.producer_adapter_identity,
            CODEX_NORMALIZER_IDENTITY
        );
        assert_eq!(envelope.adapter_contract_version, CODEX_NORMALIZER_VERSION);
        assert_eq!(receipt.normalizer_identity, CODEX_NORMALIZER_IDENTITY);
        assert_eq!(receipt.normalizer_version, CODEX_NORMALIZER_VERSION);
        assert_eq!(
            receipt.output_schema_version,
            eliot_agent_api::HOST_EVENT_CONTRACT_VERSION
        );
        assert_eq!(receipt.output_digest, envelope.compute_digest()?);
        assert_eq!(
            receipt.proof_ceiling,
            eliot_agent_api::ProofCeiling::Observation
        );
        // Recorded cursor preserved; no synthesized provider-native cursor.
        assert_eq!(envelope.cursor.as_str(), "turn-1:1");
        assert_eq!(envelope.event_id.as_str(), "turn-1:1");
        // Canonical SHA-256 over raw bytes (never blake3 for source).
        let message = CodexWireMessage::notification(
            "turn/completed",
            Some(completed_params("thread-1", "turn-1", "completed")),
        );
        let raw = serde_json::to_vec(&message)?;
        assert_eq!(
            envelope.raw_source.digest.digest.as_str(),
            eliot_contracts::sha256_hex(&raw)
        );
        assert_eq!(
            envelope.raw_source.digest.algorithm,
            eliot_agent_api::HOST_EVENT_DIGEST_ALGORITHM
        );
        envelope.validate_for_lineage(&binding, &admission)?;
        Ok(())
    }

    #[test]
    fn same_thread_different_turn_quarantines_with_typed_envelope() -> TestResult {
        let binding = bound_binding()?;
        let admission = admission_for(&binding)?;
        // Same thread, different turn (turn-2 vs bound turn-1): quarantine.
        assert!(is_binding_mismatch(&normalize_bound(
            "turn/completed",
            completed_params("thread-1", "turn-2", "completed"),
            &binding,
            &admission,
            1,
            None,
        )));
        // Same-thread steer on the exact bound turn succeeds with typed payloads.
        let (started, _) = normalize_bound(
            "turn/started",
            completed_params("thread-1", "turn-1", "inProgress"),
            &binding,
            &admission,
            1,
            None,
        )?;
        assert!(matches!(
            started.payload,
            NormalizedHostEventPayload::ExecutionStarted(_)
        ));
        Ok(())
    }

    #[test]
    fn terminal_and_usage_are_typed_without_synthetic_quota() -> TestResult {
        let binding = bound_binding()?;
        let admission = admission_for(&binding)?;
        let (terminal, _) = normalize_bound(
            "turn/completed",
            completed_params("thread-1", "turn-1", "failed"),
            &binding,
            &admission,
            1,
            None,
        )?;
        assert!(matches!(
            terminal.payload,
            NormalizedHostEventPayload::ProviderTerminalObserved(ref observation)
                if observation.status == ProviderTerminalStatus::FailedObserved
        ));
        let (usage, _) = normalize_bound(
            "turn/usage",
            serde_json::json!({
                "threadId": "thread-1",
                "turn": {"id": "turn-1"},
                "usage": {"input_tokens": 7}
            }),
            &binding,
            &admission,
            2,
            Some(1),
        )?;
        match usage.payload {
            NormalizedHostEventPayload::Usage(receipt) => {
                assert_eq!(receipt.input_tokens, Some(7));
                // Absent quota stays typed NotExposed, never zero/success.
                assert_eq!(receipt.quota, QuotaKnowledge::NotExposed);
            }
            other => panic!("expected Usage, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn unknown_method_quarantines_as_typed_with_disposition() -> TestResult {
        let binding = bound_binding()?;
        let admission = admission_for(&binding)?;
        let (envelope, receipt) = normalize_bound(
            "turn/cancelled",
            completed_params("thread-1", "turn-1", "completed"),
            &binding,
            &admission,
            1,
            None,
        )?;
        assert!(matches!(
            envelope.payload,
            NormalizedHostEventPayload::UnsupportedQuarantined(_)
        ));
        assert_eq!(
            receipt.unsupported_disposition,
            UnsupportedDisposition::UnsupportedMethodQuarantined
        );
        envelope.validate_for_lineage(&binding, &admission)?;
        Ok(())
    }

    fn result_input(
        attached: &CodexAttachReceipt,
        output: Option<&str>,
        terminal_observation: Option<NormalizedHostEventEnvelope>,
        cancelled: bool,
        unknown_reason: Option<&str>,
    ) -> TestResult<CodexResultInput> {
        Ok(CodexResultInput {
            route: attached.route.clone(),
            session: attached.session.clone(),
            output: output.map(str::to_owned),
            terminal_observation,
            cancelled,
            unknown_reason: unknown_reason.map(str::to_owned),
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            continuation: None,
            proposed_effects: Vec::new(),
        })
    }

    fn terminal_envelope(
        binding: &ProviderExecutionBinding,
    ) -> TestResult<NormalizedHostEventEnvelope> {
        translate_bound(
            "turn/completed",
            completed_params("thread-1", "turn-1", "completed"),
            binding,
            1,
            None,
        )
        .map_err(Into::into)
    }

    #[test]
    fn provider_success_stays_candidate_and_terminal_mappings_are_preserved() -> TestResult {
        let a = attached()?;
        let binding = bound_binding()?;
        let admission = admission_for(&binding)?;
        let success = translate_result(
            result_input(
                &a,
                Some("provider output"),
                Some(terminal_envelope(&binding)?),
                false,
                None,
            )?,
            &binding,
            &admission,
            &a.authority.effect_ceiling,
        )?;
        assert_eq!(success.disposition, ResultDisposition::Partial);
        assert_ne!(success.disposition, ResultDisposition::CandidateSucceeded);
        assert_eq!(success.attempt_id, binding.attempt_id);
        // Observed route is never defaulted from the requested route.
        assert_eq!(success.actual_route.observed_route, None);
        assert_eq!(
            success.actual_route.route_state,
            RouteObservationState::Unobserved
        );
        assert_eq!(success.actual_route.requested_route, binding.route);

        let cancelled = translate_result(
            result_input(
                &a,
                Some("provider output"),
                Some(terminal_envelope(&binding)?),
                true,
                None,
            )?,
            &binding,
            &admission,
            &a.authority.effect_ceiling,
        )?;
        assert_eq!(cancelled.disposition, ResultDisposition::CancelledObserved);

        let unknown = translate_result(
            result_input(&a, None, None, false, None)?,
            &binding,
            &admission,
            &a.authority.effect_ceiling,
        )?;
        assert_eq!(unknown.disposition, ResultDisposition::UnknownOutcome);
        assert!(unknown.unknown_reason.is_some());
        Ok(())
    }

    #[test]
    fn foreign_or_nonterminal_observations_never_become_results() -> TestResult {
        let a = attached()?;
        let binding = bound_binding()?;
        let admission = admission_for(&binding)?;
        // Same-thread turn B observation presented for attempt A quarantines.
        let mut foreign_binding = binding.clone();
        foreign_binding.execution_unit = ExecutionUnit::new("codex", "turn-2")?;
        let foreign_terminal = translate_bound(
            "turn/completed",
            completed_params("thread-1", "turn-2", "completed"),
            &foreign_binding,
            1,
            None,
        )?;
        assert!(is_binding_mismatch(&translate_result(
            result_input(&a, Some("output"), Some(foreign_terminal), false, None)?,
            &binding,
            &admission,
            &a.authority.effect_ceiling,
        )));
        // A non-terminal observation cannot stand in as terminal evidence.
        let nonterminal = translate_bound(
            "turn/started",
            completed_params("thread-1", "turn-1", "inProgress"),
            &binding,
            1,
            None,
        )?;
        assert!(matches!(
            translate_result(
                result_input(&a, Some("output"), Some(nonterminal), false, None)?,
                &binding,
                &admission,
                &a.authority.effect_ceiling,
            ),
            Err(CodexAdapterError::MalformedWire(_))
        ));
        // Session locator agreement is enforced against the binding.
        let mut wrong_session = a.session.clone();
        wrong_session.thread_id = "other-thread".into();
        let mut mismatched = result_input(
            &a,
            Some("output"),
            Some(terminal_envelope(&binding)?),
            false,
            None,
        )?;
        mismatched.session = wrong_session;
        assert!(matches!(
            translate_result(
                mismatched,
                &binding,
                &admission,
                &a.authority.effect_ceiling,
            ),
            Err(CodexAdapterError::SessionMismatch)
        ));
        Ok(())
    }

    #[test]
    fn interrupt_targets_the_exact_bound_turn() -> TestResult {
        let binding = bound_binding()?;
        let message = turn_interrupt_bound("req-interrupt-1", &binding)?;
        let params = message.params.expect("interrupt params");
        assert_eq!(message.method.as_deref(), Some("turn/interrupt"));
        assert_eq!(
            params.get("threadId").and_then(Value::as_str),
            Some("thread-1")
        );
        assert_eq!(params.get("turnId").and_then(Value::as_str), Some("turn-1"));
        assert!(matches!(
            turn_interrupt_bound("bad id", &binding),
            Err(CodexAdapterError::MalformedWire(_))
        ));
        let sessionless = ProviderExecutionBinding {
            native_session: NativeSession::Sessionless,
            ..binding.clone()
        };
        assert!(matches!(
            turn_interrupt_bound("req-interrupt-1", &sessionless),
            Err(CodexAdapterError::SessionMismatch)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn launch_uses_only_injected_process_executor() -> TestResult {
        let executor = Arc::new(FakeExecutor {
            starts: AtomicUsize::new(0),
        });
        let adapter = CodexAdapter::new(executor.clone());
        let mut attached = attached()?;
        let receipt = adapter.launch(&mut attached, Arc::new(Sink)).await?;
        assert_eq!(
            receipt.process.lifecycle(),
            eliot_process::ProcessLifecycle::Running
        );
        assert!(attached.process_request().is_none());
        assert_eq!(executor.starts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn second_launch_is_rejected_without_starting_another_process() -> TestResult {
        // Single-take binding: after one admitted launch, no second process
        // may be started to escape uncertainty; the retry path is the exact
        // `reconcile_unknown` on the same operation, never a fresh launch.
        let executor = Arc::new(FakeExecutor {
            starts: AtomicUsize::new(0),
        });
        let adapter = CodexAdapter::new(executor.clone());
        let mut attached = attached()?;
        let _first = adapter.launch(&mut attached, Arc::new(Sink)).await?;
        assert_eq!(executor.starts.load(Ordering::SeqCst), 1);
        assert!(matches!(
            adapter.launch(&mut attached, Arc::new(Sink)).await,
            Err(CodexAdapterError::ProcessAlreadyStarted)
        ));
        assert_eq!(executor.starts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    fn make_gate_and_snapshot(
        now: u64,
        model: &str,
    ) -> TestResult<(
        crate::preflight::CodexPreflightGate,
        eliot_agent_coordinator::ModelCatalogueSnapshot,
    )> {
        use crate::catalogue::{
            CODEX_CATALOGUE_CONTEXT_VERSION, CodexModelWire, CodexProviderPolicy,
            CodexRouteTemplate, compile_codex_model_catalogue,
        };
        use eliot_agent_coordinator::{
            ModelRole, QuotaDisposition, QuotaObservation, RouteAdmissionStatus, RouteHealthStatus,
        };
        use std::collections::{BTreeMap, BTreeSet};
        let mut gate = crate::preflight::CodexPreflightGate::new();
        gate.observe(&CodexWireMessage::initialize("init-1", "eliot", "0.1.0"))?;
        gate.observe(&CodexWireMessage {
            id: Some(Value::String("init-1".to_owned())),
            message_type: None,
            method: None,
            params: None,
            result: Some(serde_json::json!({})),
            error: None,
        })?;
        gate.observe(&CodexWireMessage::initialized())?;
        gate.observe(&CodexWireMessage::model_list("ml-1", None, false, None))?;
        gate.observe(&CodexWireMessage {
            id: Some(Value::String("ml-1".to_owned())),
            message_type: None,
            method: None,
            params: None,
            result: Some(serde_json::json!({"data": {}})),
            error: None,
        })?;
        let ctx = crate::catalogue::CodexCatalogueContext {
            schema_version: CODEX_CATALOGUE_CONTEXT_VERSION.to_owned(),
            snapshot_id: "snapshot-1".to_owned(),
            account_scope: "account-1".to_owned(),
            collector_identity: "codex-provider-catalogue-v1".to_owned(),
            observed_at_unix_ms: now - 50,
            expires_at_unix_ms: now + 50,
            health_receipt_ref: "health-receipt".to_owned(),
            catalogue_receipt_ref: "catalogue-receipt".to_owned(),
            provider_id: "codex".to_owned(),
            provider_policy: CodexProviderPolicy {
                route: CodexRouteTemplate {
                    runtime_hash: fixture_digest("runtime"),
                    adapter_hash: fixture_digest("adapter"),
                    auth_billing: "account-1".to_owned(),
                    serializer_hash: fixture_digest("serializer"),
                    tool_semantics_hash: fixture_digest("tools"),
                    reasoning_mode: "catalogue-default".to_owned(),
                    continuation_behavior: "native-resume".to_owned(),
                    feature_flags_hash: fixture_digest("features"),
                },
                route_admission: RouteAdmissionStatus::Admitted,
                route_health: RouteHealthStatus::Healthy,
                billing_mode: crate::catalogue::CodexBillingMode::CataloguePrice,
                model_billing_overrides: BTreeMap::new(),
                billing_source: "codex-billing".to_owned(),
                billing_receipt_ref: "billing-receipt".to_owned(),
                quota: Some(QuotaObservation {
                    disposition: QuotaDisposition::Available,
                    source: "codex-quota".to_owned(),
                    receipt_ref: "quota-receipt".to_owned(),
                    observed_at_unix_ms: now - 50,
                    expires_at_unix_ms: now + 50,
                    reset_at_unix_ms: Some(now + 1000),
                    remaining_microunits: Some(10),
                }),
                quota_source: "codex-quota".to_owned(),
                quota_receipt_ref: "quota-receipt".to_owned(),
                cost_class: 1,
                latency_class: 1,
                role_eligibility: BTreeSet::from([ModelRole::Worker]),
                evidence_refs: vec!["route-policy-receipt".to_owned()],
            },
            provider_connected: true,
            provider_health: RouteHealthStatus::Healthy,
            evidence_refs: vec!["collector-receipt".to_owned()],
        };
        let mut models = BTreeMap::new();
        models.insert(
            model.to_owned(),
            CodexModelWire {
                id: Some(model.to_owned()),
                display_name: Some(model.to_owned()),
                family: Some("family-a".to_owned()),
                context_window: Some(200_000),
                context_limit: None,
                limit: None,
                cost: Some(crate::catalogue::CodexModelCost {
                    input: Some(serde_json::Number::from(0)),
                    output: Some(serde_json::Number::from(0)),
                }),
                capabilities: None,
                extra: BTreeMap::new(),
            },
        );
        let collection = compile_codex_model_catalogue(&ctx, &models)?;
        let mut snapshot = collection.snapshot;
        snapshot.observed_at_unix_ms = now - 50;
        snapshot.expires_at_unix_ms = now + 50;
        for entry in &mut snapshot.entries {
            entry.billing.observed_at_unix_ms = now - 50;
            entry.billing.expires_at_unix_ms = now + 50;
            entry.quota.observed_at_unix_ms = now - 50;
            entry.quota.expires_at_unix_ms = now + 50;
        }
        snapshot.validate()?;
        // bind catalogue using the exact route that the attached receipt will use
        let route = crate::codex_route(
            fixture_digest("runtime"),
            fixture_digest("adapter"),
            "codex",
            model,
            "account-1",
            fixture_digest("serializer"),
            fixture_digest("tools"),
            "catalogue-default",
            "native-resume",
            fixture_digest("features"),
        );
        gate.bind_catalogue(&snapshot, &route, now)?;
        Ok((gate, snapshot))
    }

    #[test]
    fn preflight_gate_blocks_thread_turn_before_ready() -> TestResult {
        let gate = crate::preflight::CodexPreflightGate::new();
        assert!(matches!(
            CodexWireMessage::thread_start_checked("t-1", "C:\\workspace", &gate),
            Err(CodexAdapterError::PreflightIncomplete)
        ));
        assert!(matches!(
            CodexWireMessage::turn_start_checked(
                "turn-1",
                "thread-1",
                &serde_json::json!({}),
                &gate
            ),
            Err(CodexAdapterError::PreflightIncomplete)
        ));
        Ok(())
    }

    #[test]
    fn preflight_gate_allows_thread_turn_after_ready() -> TestResult {
        let now = 10_000;
        let (gate, _) = make_gate_and_snapshot(now, "model-a")?;
        assert!(CodexWireMessage::thread_start_checked("t-1", "C:\\workspace", &gate).is_ok());
        assert!(
            CodexWireMessage::turn_start_checked(
                "turn-1",
                "thread-1",
                &serde_json::json!({ "prompt": "hi" }),
                &gate
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn begin_attempt_strict_requires_bound_catalogue() -> TestResult {
        let attached = attached()?;
        let gate = crate::preflight::CodexPreflightGate::new();
        assert!(matches!(
            begin_attempt_strict(
                &attached,
                &gate,
                serde_json::from_value::<WorkLeaseId>(
                    serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"})
                )?,
                AttemptId::new("attempt-1")?,
                ContinuityKind::Fresh
            ),
            Err(CodexAdapterError::PreflightIncomplete)
        ));
        Ok(())
    }

    #[test]
    fn begin_attempt_strict_rejects_mismatched_catalogue() -> TestResult {
        let now = 10_000;
        // gate bound to model-a but attached route is for generic "model"
        let (gate, snapshot) = make_gate_and_snapshot(now, "model-a")?;
        let attached = attached()?; // route model == "model"
        // gate bound to model-a, attached expects model-a? Actually attached route model == "model", so mismatch
        assert!(matches!(
            begin_attempt_strict(
                &attached,
                &gate,
                serde_json::from_value::<WorkLeaseId>(
                    serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"})
                )?,
                AttemptId::new("attempt-1")?,
                ContinuityKind::Fresh
            ),
            Err(CodexAdapterError::CatalogueMismatch(_))
        ));
        // also test mismatched snapshot directly via gate binding: try bind wrong model
        let wrong_route = crate::codex_route(
            fixture_digest("runtime"),
            fixture_digest("adapter"),
            "codex",
            "other-model",
            "account-1",
            fixture_digest("serializer"),
            fixture_digest("tools"),
            "catalogue-default",
            "native-resume",
            fixture_digest("features"),
        );
        let mut fresh_gate = crate::preflight::CodexPreflightGate::new();
        fresh_gate.observe(&CodexWireMessage::initialize("init-1", "eliot", "0.1.0"))?;
        fresh_gate.observe(&CodexWireMessage {
            id: Some(Value::String("init-1".to_owned())),
            message_type: None,
            method: None,
            params: None,
            result: Some(serde_json::json!({})),
            error: None,
        })?;
        fresh_gate.observe(&CodexWireMessage::initialized())?;
        fresh_gate.observe(&CodexWireMessage::model_list("ml-1", None, false, None))?;
        fresh_gate.observe(&CodexWireMessage {
            id: Some(Value::String("ml-1".to_owned())),
            message_type: None,
            method: None,
            params: None,
            result: Some(serde_json::json!({})),
            error: None,
        })?;
        assert!(matches!(
            fresh_gate.bind_catalogue(&snapshot, &wrong_route, now),
            Err(CodexAdapterError::ModelNotInCatalogue)
        ));
        Ok(())
    }

    #[test]
    fn begin_attempt_strict_rejects_absent_snapshot_and_stale_wire() -> TestResult {
        // absent: gate without catalogue Observed phase
        let mut gate = crate::preflight::CodexPreflightGate::new();
        gate.observe(&CodexWireMessage::initialize("init-1", "eliot", "0.1.0"))?;
        // not completing remaining phases -> require_ready fails
        assert!(gate.require_ready().is_err());
        // legacy wire rejected via parse_line
        assert!(
            CodexWireMessage::parse_line(
                br#"{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}"#
            )
            .is_err()
        );
        // stale protocolVersion via gate
        let mut gate2 = crate::preflight::CodexPreflightGate::new();
        let mut legacy = CodexWireMessage::initialize("init-1", "eliot", "0.1.0");
        legacy.params = Some(serde_json::json!({"protocolVersion": "0.1.0"}));
        assert!(matches!(
            gate2.observe(&legacy),
            Err(CodexAdapterError::StaleWire(_))
        ));
        Ok(())
    }

    #[test]
    fn begin_attempt_strict_succeeds_with_exact_binding() -> TestResult {
        let now = 10_000;
        // Create an attached receipt whose route matches the snapshot's model
        // Build a custom attached with runtime-hash etc matching snapshot
        let (source_assurance, source_expectation) = source()?;
        let launch = launch()?;
        let route = crate::codex_route(
            fixture_digest("runtime"),
            fixture_digest("adapter"),
            "codex",
            "model-a",
            "account-1",
            fixture_digest("serializer"),
            fixture_digest("tools"),
            "catalogue-default",
            "native-resume",
            fixture_digest("features"),
        );
        let authority = eliot_agent_api::AuthorityEnvelope {
            epoch: test_epoch(TEST_LINEAGE_A, 1),
            scope_ref: "scope-1".into(),
            effect_ceiling: ceiling(),
            lease: serde_json::from_value::<WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
            )?,
            state_fence: eliot_agent_api::StateFence::new(
                test_epoch(TEST_LINEAGE_A, 1),
                eliot_agent_api::ResourceGeneration::new(1)?,
            ),
            valid_until: "never".into(),
        };
        let attached = attach(crate::CodexAttachInput {
            launch,
            authority,
            route: route.clone(),
            session: CodexSessionBinding {
                session_id: SessionId::new("session-1")?,
                thread_id: "thread-1".into(),
                runtime_hash: fixture_digest("runtime"),
                working_directory: "C:\\workspace".into(),
            },
            process_request: process_request()?,
            source_assurance,
            source_expectation,
        })?;
        let (gate, _) = make_gate_and_snapshot(now, "model-a")?;
        let attempt = begin_attempt_strict(
            &attached,
            &gate,
            serde_json::from_value::<WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
            )?,
            AttemptId::new("attempt-1")?,
            ContinuityKind::Fresh,
        )?;
        assert_eq!(attempt.route.model, "model-a");
        assert_eq!(attempt.route.provider, "codex");
        Ok(())
    }
}
