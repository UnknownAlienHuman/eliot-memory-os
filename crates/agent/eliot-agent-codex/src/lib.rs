//! Stateless Codex App Server stdio/JSONL adapter.
//!
//! The adapter translates the bounded provider wire into the provider-neutral
//! A-01 contracts.  It never starts a child, owns canonical state, creates an
//! authority envelope, or treats a provider terminal message as task finish.
//! Physical execution is exclusively delegated to the P-03 [`ProcessExecutor`]
//! supplied by the caller.

use std::sync::Arc;

use eliot_agent_api::{
    ActualRouteReceipt, AgentAttempt, AgentLaunchRequest, AgentResult, AgentWorkUnitBrief,
    AttemptId, AttemptState, AuthorityEnvelope, CancelReason, ContinuityKind, EffectCeiling,
    EventCursor, EventId, HostEventEnvelope, HostEventKind, ResultDisposition,
    RouteContinuationLocator, RouteFingerprint, SessionId, UsageReceipt, WorkLeaseId,
};
use eliot_process::{
    CancellationReceipt, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutor, ProcessRequest, ProcessStartReceipt,
};
use eliot_source_assurance::{
    AdmissionExpectation, AdmissionOutcome, SourceAssurance, SourceAssuranceError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

pub const CODEX_ADAPTER_ID: &str = "eliot-agent-codex";
pub const CODEX_HOST_FAMILY: &str = "codex";
pub const CODEX_PROTOCOL_TRANSPORT: &str = "app-server+stdio/jsonl";
pub const CODEX_WIRE_SCHEMA_VERSION: &str = "codex-app-server-jsonl/v1";
pub const CODEX_ROUTE_CLASS: &str = "codex-app-server";
pub const MAX_JSONL_LINE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVENT_BYTES: usize = 256 * 1024;

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
    #[error("Codex output is partial; outcome remains unknown")]
    PartialOutput,
    #[error("Codex output has no admissible semantic result")]
    MissingResult,
    #[error("Codex result is already terminal")]
    TerminalAttempt,
}

/// Exact route constructor.  The resulting value is still the A-01 route
/// projection; no vendor SDK type escapes this crate.
#[allow(clippy::too_many_arguments)]
pub fn codex_route(
    runtime_hash: impl Into<String>,
    adapter_hash: impl Into<String>,
    provider: impl Into<String>,
    model: impl Into<String>,
    auth_billing: impl Into<String>,
    serializer_hash: impl Into<String>,
    tool_semantics_hash: impl Into<String>,
    reasoning_mode: impl Into<String>,
    continuation_behavior: impl Into<String>,
    feature_flags_hash: impl Into<String>,
) -> RouteFingerprint {
    RouteFingerprint {
        host_family: CODEX_HOST_FAMILY.into(),
        adapter: CODEX_ADAPTER_ID.into(),
        protocol_transport: CODEX_PROTOCOL_TRANSPORT.into(),
        runtime_hash: runtime_hash.into(),
        adapter_hash: adapter_hash.into(),
        provider: provider.into(),
        model: model.into(),
        auth_billing: auth_billing.into(),
        serializer_hash: serializer_hash.into(),
        tool_semantics_hash: tool_semantics_hash.into(),
        reasoning_mode: reasoning_mode.into(),
        continuation_behavior: continuation_behavior.into(),
        feature_flags_hash: feature_flags_hash.into(),
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
    pub runtime_hash: String,
    pub working_directory: String,
}

impl CodexSessionBinding {
    pub fn validate(&self, route: &RouteFingerprint) -> Result<(), CodexAdapterError> {
        validate_codex_route(route)?;
        for value in [&self.thread_id, &self.runtime_hash, &self.working_directory] {
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct CodexAttachReceipt {
    launch: AgentLaunchRequest,
    authority: AuthorityEnvelope,
    route: RouteFingerprint,
    session: CodexSessionBinding,
    process_request: ProcessRequest,
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
    pub fn process_request(&self) -> &ProcessRequest {
        &self.process_request
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
    Ok(CodexAttachReceipt {
        launch: input.launch,
        authority: input.authority,
        route: input.route,
        session: input.session,
        process_request: input.process_request,
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
        attached: &CodexAttachReceipt,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<CodexLaunchReceipt, CodexAdapterError> {
        let start = self
            .executor
            .start(attached.process_request.clone(), sink)
            .await?;
        if start.operation_id() != attached.process_request.operation_id()
            || start.accepted_generation() != attached.process_request.generation()
        {
            return Err(CodexAdapterError::StaleFence);
        }
        Ok(CodexLaunchReceipt {
            attempt_id: AttemptId::new(attached.launch.id.as_str())?,
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
            .cancel(attached.process_request.operation_id().clone())
            .await?;
        Ok(CodexCancelReceipt {
            attempt_id: AttemptId::new(attached.launch.id.as_str())?,
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
            .reconcile(attached.process_request.operation_id().clone())
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
    };
    attempt.validate()?;
    attempt.transition(AttemptState::Started)?;
    Ok(attempt)
}

/// Codex App Server JSONL envelope.  Provider fields remain opaque `Value`s;
/// callers receive typed A-01 events/results after translation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodexWireMessage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonrpc: Option<String>,
    #[serde(default)]
    pub id: Option<Value>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub message_type: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub params: Option<Value>,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<Value>,
}

impl CodexWireMessage {
    pub fn parse_line(line: &[u8]) -> Result<Self, CodexAdapterError> {
        if line.len() > MAX_JSONL_LINE_BYTES {
            return Err(CodexAdapterError::WireTooLarge);
        }
        let message: Self = serde_json::from_slice(line)
            .map_err(|_| CodexAdapterError::MalformedWire("invalid JSON object"))?;
        if message.id.is_none() && message.method.is_none() {
            return Err(CodexAdapterError::MalformedWire("missing id/method"));
        }
        if message.result.is_some() && message.error.is_some() {
            return Err(CodexAdapterError::AmbiguousResponse);
        }
        Ok(message)
    }

    pub fn request(id: impl Into<String>, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: Some("2.0".into()),
            id: Some(Value::String(id.into())),
            message_type: None,
            method: Some(method.into()),
            params: Some(params),
            result: None,
            error: None,
        }
    }

    /// App Server handshake request with only protocol-owned fields.
    pub fn initialize(
        id: impl Into<String>,
        client_name: impl Into<String>,
        client_version: impl Into<String>,
    ) -> Self {
        Self::request(
            id,
            "initialize",
            serde_json::json!({
                "protocolVersion": CODEX_WIRE_SCHEMA_VERSION,
                "clientInfo": {"name": client_name.into(), "version": client_version.into()}
            }),
        )
    }

    pub fn thread_start(id: impl Into<String>, cwd: impl Into<String>) -> Self {
        Self::request(id, "thread/start", serde_json::json!({ "cwd": cwd.into() }))
    }

    pub fn turn_start(id: impl Into<String>, thread_id: &str, input: &Value) -> Self {
        Self::request(
            id,
            "turn/start",
            serde_json::json!({ "threadId": thread_id, "input": input }),
        )
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
    let actual = message.id.as_ref().and_then(Value::as_str);
    if actual != Some(request_id) {
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

fn event_kind(method: &str) -> HostEventKind {
    match method {
        "thread/started" | "thread/resumed" => HostEventKind::SessionStarted,
        "turn/started" | "turn/created" => HostEventKind::PromptSubmitted,
        "item/agentMessage/delta" | "item/assistantMessage/delta" => HostEventKind::AssistantDelta,
        "item/reasoningSummary/delta" | "item/reasoning/delta" => HostEventKind::ReasoningDelta,
        "item/commandExecution/requestApproval" | "item/toolCall" => HostEventKind::ToolCall,
        "item/commandExecution/finished" | "item/toolResult" => HostEventKind::ToolResult,
        "turn/completed" | "turn/completion" => HostEventKind::Completed,
        "turn/failed" | "error" => HostEventKind::Error,
        "turn/cancelled" => HostEventKind::CancelRequested,
        _ => HostEventKind::Unknown,
    }
}

fn validate_event_session(
    params: &Value,
    session: &CodexSessionBinding,
) -> Result<(), CodexAdapterError> {
    let Some(object) = params.as_object() else {
        return Ok(());
    };
    for key in ["threadId", "thread_id"] {
        if let Some(value) = object.get(key).and_then(Value::as_str)
            && value != session.thread_id
        {
            return Err(CodexAdapterError::SessionMismatch);
        }
    }
    for key in ["sessionId", "session_id"] {
        if let Some(value) = object.get(key).and_then(Value::as_str)
            && value != session.session_id.as_str()
        {
            return Err(CodexAdapterError::SessionMismatch);
        }
    }
    Ok(())
}

/// Translate one provider event into an A-01 event. `previous_sequence` is
/// supplied by the owner, avoiding a hidden local cursor/state assumption.
pub fn translate_host_event(
    message: &CodexWireMessage,
    attempt_id: AttemptId,
    route: &RouteFingerprint,
    session: &CodexSessionBinding,
    sequence: u64,
    previous_sequence: Option<u64>,
    observed_at: impl Into<String>,
) -> Result<HostEventEnvelope, CodexAdapterError> {
    validate_codex_route(route)?;
    session.validate(route)?;
    if sequence == 0 || previous_sequence.is_some_and(|previous| sequence <= previous) {
        return Err(CodexAdapterError::Contract(
            eliot_agent_api::ContractError::NonMonotonicEvent,
        ));
    }
    let method = message
        .method
        .as_deref()
        .ok_or(CodexAdapterError::MalformedWire("event has no method"))?;
    let params = message.params.clone().unwrap_or(Value::Null);
    validate_event_session(&params, session)?;
    let bytes = serde_json::to_vec(&message)
        .map_err(|_| CodexAdapterError::MalformedWire("event serialization"))?;
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(CodexAdapterError::WireTooLarge);
    }
    let cursor = EventCursor::new(format!("codex:{sequence}"))?;
    Ok(HostEventEnvelope {
        event_id: EventId::new(format!("codex:{sequence}"))?,
        attempt_id,
        sequence,
        cursor,
        kind: event_kind(method),
        route: route.clone(),
        raw_payload_digest: blake3::hash(&bytes).to_hex().to_string(),
        normalized_payload: params,
        parent_event_id: None,
        observed_at: observed_at.into(),
    })
}

/// Result input owned by the caller, assembled from a complete event stream.
/// The adapter refuses to infer completion from an incomplete stream.
#[derive(Clone, Debug)]
pub struct CodexResultInput {
    pub attempt_id: AttemptId,
    pub route: RouteFingerprint,
    pub session: CodexSessionBinding,
    pub output: Option<String>,
    pub completed_event_seen: bool,
    pub cancelled: bool,
    pub unknown_reason: Option<String>,
    pub usage: UsageReceipt,
    pub route_id: eliot_agent_api::RouteFingerprintId,
    pub started_at: String,
    pub terminal_at: Option<String>,
    pub continuation: Option<RouteContinuationLocator>,
    pub proposed_effects: Vec<eliot_agent_api::ProposedEffect>,
}

/// Translate a complete Codex result into the neutral result contract.
pub fn translate_result(
    input: CodexResultInput,
    authority: &EffectCeiling,
) -> Result<AgentResult, CodexAdapterError> {
    validate_codex_route(&input.route)?;
    input.session.validate(&input.route)?;
    if let Some(locator) = &input.continuation {
        if locator.route != input.route {
            return Err(CodexAdapterError::RouteMismatch);
        }
        locator.validate()?;
    }
    let output_digest = input
        .output
        .as_deref()
        .map(|text| blake3::hash(text.as_bytes()).to_hex().to_string());
    let mut evidence_refs = output_digest
        .into_iter()
        .map(|digest| format!("codex-output:{digest}"))
        .collect::<Vec<_>>();
    if evidence_refs.is_empty() && input.completed_event_seen {
        evidence_refs.push("codex-event:completed".into());
    }
    let (disposition, unknown_reason) = if input.cancelled {
        (ResultDisposition::Cancelled, input.unknown_reason)
    } else if !input.completed_event_seen {
        (
            ResultDisposition::UnknownOutcome,
            Some(
                input
                    .unknown_reason
                    .unwrap_or_else(|| "completion event absent".into()),
            ),
        )
    } else {
        (ResultDisposition::Partial, input.unknown_reason)
    };
    let result = AgentResult {
        attempt_id: input.attempt_id,
        disposition,
        artifacts: Vec::new(),
        evidence_refs,
        proposed_effects: input.proposed_effects,
        effect_receipts: Vec::new(),
        unresolved_questions: Vec::new(),
        usage: input.usage.clone(),
        actual_route: ActualRouteReceipt {
            requested: input.route.clone(),
            observed: Some(input.route),
            route_id: input.route_id,
            usage: input.usage,
            started_at: input.started_at,
            terminal_at: input.terminal_at,
        },
        unknown_reason,
    };
    result.validate(authority)?;
    Ok(result)
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
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use eliot_agent_api::{
        AuthorityEpoch, BudgetEnvelope, EffectKind, LaunchRequestId, QuotaKnowledge, WorkUnitId,
    };
    use eliot_process::{
        EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation,
        ProcessExecutionView, ResourceLimits,
    };
    use eliot_source_assurance::{
        AdmissibleUse, AxisStatus, GoverningSourceIdentity, GoverningSourceSet, InstructionTaint,
        PrivacyClass, QuarantineStatus, SOURCE_ASSURANCE_SCHEMA_VERSION, ScopeBindingProof,
        SourceFrontierBinding, SourceProvenance, SourceSnapshotBinding, SourceTrustProfile,
        ThreatStatus,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn route() -> RouteFingerprint {
        codex_route(
            "runtime-1",
            "adapter-1",
            "provider",
            "model",
            "subscription",
            "serializer-1",
            "tools-1",
            "visible",
            "native_resume",
            "features-1",
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
        Ok(ProcessRequest::new(
            eliot_process::OperationId::new("op-1")?,
            eliot_process::ProcessTreeId::new("tree-1")?,
            generation,
            "codex-app-server",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            vec!["--stdio".into()],
            "C:\\workspace",
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)?,
            ResourceLimits::new(1_000, None, None, 10_000, 10_000, 1)?,
            FencingToken::new(1, generation, "nonce")?,
        )?)
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
                epoch: AuthorityEpoch::new("epoch-1")?,
                scope_ref: "scope-1".into(),
                effect_ceiling: ceiling(),
                lease: WorkLeaseId::new("lease-1")?,
                state_fence: "fence".into(),
                valid_until: "never".into(),
            },
            route: route(),
            session: CodexSessionBinding {
                session_id: SessionId::new("session-1")?,
                thread_id: "thread-1".into(),
                runtime_hash: "runtime-1".into(),
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
            ProcessStartReceipt::new(&request, eliot_process::ProcessLifecycle::Starting)
                .map_err(ProcessExecutionError::from)
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

    #[test]
    fn event_from_wrong_session_is_rejected() -> TestResult {
        let a = attached()?;
        let message = CodexWireMessage::request(
            "event-1",
            "turn/completed",
            serde_json::json!({ "threadId": "other-thread" }),
        );
        assert!(matches!(
            translate_host_event(
                &message,
                AttemptId::new("attempt-1")?,
                &a.route,
                &a.session,
                1,
                None,
                "now",
            ),
            Err(CodexAdapterError::SessionMismatch)
        ));
        Ok(())
    }

    fn result_input(
        attached: &CodexAttachReceipt,
        output: Option<&str>,
        completed_event_seen: bool,
        cancelled: bool,
        unknown_reason: Option<&str>,
    ) -> TestResult<CodexResultInput> {
        Ok(CodexResultInput {
            attempt_id: AttemptId::new("attempt-1")?,
            route: attached.route.clone(),
            session: attached.session.clone(),
            output: output.map(str::to_owned),
            completed_event_seen,
            cancelled,
            unknown_reason: unknown_reason.map(str::to_owned),
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            route_id: eliot_agent_api::RouteFingerprintId::new("route-1")?,
            started_at: "start".into(),
            terminal_at: None,
            continuation: None,
            proposed_effects: Vec::new(),
        })
    }

    #[test]
    fn provider_success_stays_candidate_and_terminal_mappings_are_preserved() -> TestResult {
        let a = attached()?;
        let success = translate_result(
            result_input(&a, Some("provider output"), true, false, None)?,
            &a.authority.effect_ceiling,
        )?;
        assert_eq!(success.disposition, ResultDisposition::Partial);
        assert_ne!(success.disposition, ResultDisposition::VerifiedComplete);

        let cancelled = translate_result(
            result_input(&a, Some("provider output"), true, true, None)?,
            &a.authority.effect_ceiling,
        )?;
        assert_eq!(cancelled.disposition, ResultDisposition::Cancelled);

        let unknown = translate_result(
            result_input(&a, None, false, false, None)?,
            &a.authority.effect_ceiling,
        )?;
        assert_eq!(unknown.disposition, ResultDisposition::UnknownOutcome);
        assert!(unknown.unknown_reason.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn launch_uses_only_injected_process_executor() -> TestResult {
        let executor = Arc::new(FakeExecutor {
            starts: AtomicUsize::new(0),
        });
        let adapter = CodexAdapter::new(executor.clone());
        let receipt = adapter.launch(&attached()?, Arc::new(Sink)).await?;
        assert_eq!(
            receipt.process.lifecycle(),
            eliot_process::ProcessLifecycle::Starting
        );
        assert_eq!(executor.starts.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
