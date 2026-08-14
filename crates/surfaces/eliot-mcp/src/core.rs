//! Pure request validation, normalization, forwarding, and response bounding.

use std::collections::BTreeSet;

use eliot_protocol::HARD_STRUCTURED_RESPONSE_BYTES;
use eliot_receipts::{ArtifactBinding, ProofCeiling, SessionBinding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ApplicationRequest, ContractViolation, McpProtocolVersion, ToolRequest, validate_proof_ceiling,
};

/// Default and optional local transport profiles. This is validation only.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransportProfile {
    /// Default near-stateless stdio shim.
    #[default]
    Stdio,
    /// Optional loopback-only Streamable HTTP profile.
    LoopbackHttp(LoopbackProfile),
}

impl TransportProfile {
    /// Validates the bounded profile without opening a socket.
    pub fn validate(&self) -> Result<(), BridgeError> {
        match self {
            Self::Stdio => Ok(()),
            Self::LoopbackHttp(profile) => profile.validate(),
        }
    }
}

/// Untrusted per-request transport facts presented to the injected resolver.
///
/// These values never become authority by themselves. Both stdio and loopback
/// calls must carry them, and the trusted port must resolve them to a current
/// [`ActiveSessionBinding`] before semantic dispatch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportRequestContext {
    /// Validated local transport profile.
    pub profile: TransportProfile,
    /// Identity of this concrete transport connection.
    pub connection_id: String,
    /// Opaque reference to a scoped short-lived local credential.
    pub scoped_credential_ref: String,
    /// Exact live transport generation.
    pub transport_generation: u64,
}

impl TransportRequestContext {
    fn validate(&self) -> Result<(), BridgeError> {
        self.profile.validate()?;
        if self.connection_id.trim().is_empty() {
            return Err(BridgeError::invalid(
                "transport.connection_id",
                "must be non-blank",
            ));
        }
        if self.scoped_credential_ref.trim().is_empty() {
            return Err(BridgeError::invalid(
                "transport.scoped_credential_ref",
                "must be non-blank",
            ));
        }
        if self.transport_generation == 0 {
            return Err(BridgeError::invalid(
                "transport.transport_generation",
                "must be greater than zero",
            ));
        }
        if let TransportProfile::LoopbackHttp(profile) = &self.profile
            && profile.credential_ref != self.scoped_credential_ref
        {
            return Err(BridgeError::invalid(
                "transport.scoped_credential_ref",
                "must exactly match the loopback profile credential reference",
            ));
        }
        Ok(())
    }
}

/// Loopback-only HTTP validation inputs. Credentials are opaque references.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopbackProfile {
    /// Exact bind literal: `127.0.0.1` or `::1`.
    pub bind_address: String,
    /// Exact validated HTTP Host, including the selected port.
    pub host: String,
    /// Browser Origin, when browser-originated access is admitted.
    pub browser_origin: Option<String>,
    /// Reference to a scoped short-lived local credential, never raw secret data.
    pub credential_ref: String,
}

impl LoopbackProfile {
    fn validate(&self) -> Result<(), BridgeError> {
        if self.bind_address != "127.0.0.1" && self.bind_address != "::1" {
            return Err(BridgeError::invalid(
                "transport.bind_address",
                "must be the literal 127.0.0.1 or ::1",
            ));
        }
        let port = if self.bind_address == "::1" {
            self.host.strip_prefix("[::1]:")
        } else {
            self.host.strip_prefix("127.0.0.1:")
        };
        if !port.is_some_and(valid_port) {
            return Err(BridgeError::invalid(
                "transport.host",
                "must use the exact loopback literal and an explicit nonzero port",
            ));
        }
        if self.credential_ref.trim().is_empty() {
            return Err(BridgeError::invalid(
                "transport.credential_ref",
                "must reference a scoped local credential",
            ));
        }
        if let Some(origin) = &self.browser_origin {
            let expected = format!("http://{}", self.host);
            if origin != &expected {
                return Err(BridgeError::invalid(
                    "transport.browser_origin",
                    "must exactly match the admitted loopback Host",
                ));
            }
        }
        Ok(())
    }
}

fn valid_port(port: &str) -> bool {
    port.parse::<u16>().is_ok_and(|value| value > 0)
}

/// Initialize input. It intentionally contains no ELIOT session/task/authority fields.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeRequest {
    /// Requested MCP profile.
    pub protocol_version: McpProtocolVersion,
    /// Presentation-only capability advertisement.
    #[serde(default)]
    pub capabilities: crate::ClientCapabilities,
}

/// Initialize projection. It creates no application identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeResponse {
    /// Selected supported profile.
    pub protocol_version: McpProtocolVersion,
    /// Exact canonical tool count.
    pub canonical_tool_count: usize,
    /// Whether the legacy alias is available in the compatibility adapter.
    pub legacy_memory_use_alias: bool,
    /// Hard encoded structured-response limit.
    pub structured_response_limit_bytes: usize,
    /// Explicit statement that initialize did not create application identity.
    pub application_binding_created: bool,
}

/// Correlation-only hint admitted only by the 2025-11-25 adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityCorrelation {
    /// Opaque transport hint. It is not a Session identity.
    pub transport_session_hint: Option<String>,
}

/// Immutable forwarded request passed to the injected semantic owner.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedRequest {
    /// Validated request with its canonical tool form.
    pub request: ApplicationRequest,
    /// SHA-256 over canonical serialized request bytes, including identity.
    pub canonical_request_sha256: String,
    /// Trusted current operational binding resolved for this exact request.
    pub active_session_binding: ActiveSessionBinding,
    /// Compatibility-only transport correlation hint.
    pub compatibility_correlation_hint: Option<String>,
}

/// Request sent to the trusted operational-binding resolver.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingResolutionRequest {
    /// Untrusted local transport facts to authenticate and resolve.
    pub transport: TransportRequestContext,
    /// Caller-claimed application Session to match, never to trust directly.
    pub claimed_session: SessionBinding,
    /// Exact request identity.
    pub request_id: String,
    /// Exact retry identity.
    pub idempotency_key: String,
    /// Exact cancellation identity.
    pub cancellation_id: String,
    /// Exact canonical request digest.
    pub canonical_request_sha256: String,
    /// Absolute request deadline.
    pub deadline_unix_ms: u64,
}

/// Kernel-owned operational Session binding for one exact request.
///
/// It is evidence returned by the injected trusted port. It is not accepted as
/// public tool input and it owns no durable Session or authority state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveSessionBinding {
    /// Opaque live binding identity assigned by the resolver.
    pub binding_id: String,
    /// Authenticated local principal identity.
    pub principal_ref: String,
    /// Resolved durable application Session, authority epoch, and State Fence.
    pub session: SessionBinding,
    /// Resolved connection, credential, profile, and transport generation.
    pub transport: TransportRequestContext,
    /// Exact request correlation.
    pub request_id: String,
    /// Exact idempotency correlation.
    pub idempotency_key: String,
    /// Exact cancellation correlation.
    pub cancellation_id: String,
    /// Exact request-byte correlation.
    pub canonical_request_sha256: String,
    /// Resolver observation time in Unix milliseconds.
    pub resolved_at_unix_ms: u64,
    /// Expiry of this scoped operational binding in Unix milliseconds.
    pub valid_until_unix_ms: u64,
}

/// Kernel/Governor semantic port. The MCP crate provides no implementation state.
pub trait KernelGovernorPort {
    /// Authenticate transport facts and resolve a current operational binding.
    fn resolve_active_session(
        &self,
        request: &BindingResolutionRequest,
    ) -> Result<ActiveSessionBinding, PortFailure>;

    /// Evaluate one validated and explicitly bound request.
    fn dispatch(&self, request: &ForwardedRequest) -> Result<PortProjection, PortFailure>;
}

/// Closed non-authoritative projection classes returned by the injected port.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionKind {
    /// Candidate content awaiting admission/verification.
    Candidate,
    /// Read-only projection of owner state.
    Projection,
}

/// A semantic owner result that still cannot express finish/admission authority.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortProjection {
    /// Candidate/projection class only.
    pub kind: ProjectionKind,
    /// Structured content.
    pub content: Value,
    /// Exact immutable artifacts referenced by the projection.
    #[serde(default)]
    pub artifacts: Vec<ArtifactBinding>,
    /// Strongest interpretation permitted for this projection.
    pub proof_ceiling: ProofCeiling,
    /// Immutable resource handle for large content.
    pub resource: Option<ResourceHandle>,
    /// Durable long-operation handle, if one was started by the real owner.
    pub durable_job: Option<DurableJobHandle>,
}

/// Typed negative outcomes from a real or absent semantic provider.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PortFailure {
    /// Required G-12/Q-01 or another semantic provider is absent/unadmitted.
    #[error("PLAN_GAP: {reason}")]
    PlanGap {
        /// Exact missing provider/capability.
        missing_capability: String,
        /// Public recovery reason.
        reason: String,
    },
    /// The selected provider does not implement the requested semantic contract.
    #[error("UNSUPPORTED: {reason}")]
    Unsupported {
        /// Unsupported contract/capability.
        capability: String,
        /// Public reason.
        reason: String,
    },
    /// Same idempotency identity was bound to different request bytes.
    #[error("IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    /// Request deadline was reached by the semantic owner.
    #[error("DEADLINE_EXCEEDED")]
    DeadlineExceeded,
    /// Request was cancelled by its canonical cancellation identity.
    #[error("CANCELLED")]
    Cancelled,
    /// Owner rejected a stale or mismatched state fence.
    #[error("FENCE_MISMATCH")]
    FenceMismatch,
    /// Scoped credential or operational transport binding was rejected.
    #[error("TRANSPORT_BINDING_REJECTED: {reason}")]
    TransportBindingRejected {
        /// Public bounded rejection reason.
        reason: String,
    },
}

/// Immutable large-data handle. Bytes stay outside the structured response.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceHandle {
    /// Immutable `eliot://resource/...` URI.
    pub uri: String,
    /// Exact artifact/digest identity of the resource bytes.
    pub artifact: ArtifactBinding,
    /// Media type of the resource bytes.
    pub media_type: String,
    /// Exact byte size.
    pub size_bytes: u64,
    /// Session/fence scope in which the resource was produced.
    pub session: SessionBinding,
}

/// Provider-neutral durable job handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableJobHandle {
    /// Durable ELIOT job identity.
    pub job_id: String,
    /// Stable resource used for poll/subscription.
    pub resource_uri: String,
    /// Current job revision.
    pub revision: u64,
    /// Explicit application Session/fence scope.
    pub session: SessionBinding,
}

/// Presentation of one identical durable handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum JobPresentation {
    /// MCP Tasks presentation when advertised.
    McpTask { handle: DurableJobHandle },
    /// Native `DurableJob` presentation otherwise.
    DurableJob { handle: DurableJobHandle },
}

impl JobPresentation {
    /// Returns the semantically identical underlying handle.
    #[must_use]
    pub const fn handle(&self) -> &DurableJobHandle {
        match self {
            Self::McpTask { handle } | Self::DurableJob { handle } => handle,
        }
    }
}

/// Closed MCP response classes. There is deliberately no `SUCCESS` verdict.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseKind {
    /// Candidate content.
    Candidate,
    /// Read-only projection.
    Projection,
    /// Required real provider is absent.
    PlanGap,
    /// Provider contract is not supported.
    Unsupported,
}

/// Bounded, correlated, non-authoritative MCP response.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpResponse {
    /// Exact request identity echoed for correlation.
    pub request_id: String,
    /// Exact idempotency identity echoed for retry correlation.
    pub idempotency_key: String,
    /// SHA-256 of canonical request bytes.
    pub canonical_request_sha256: String,
    /// Candidate/projection/typed-gap class.
    pub kind: ResponseKind,
    /// Canonical tool name after alias normalization.
    pub canonical_tool_name: String,
    /// Structured bounded content or a resource pointer.
    pub content: Value,
    /// Immutable artifacts referenced by the content.
    pub artifacts: Vec<ArtifactBinding>,
    /// Explicit proof ceiling; never a finish decision.
    pub proof_ceiling: ProofCeiling,
    /// Large-data resource handle, when used.
    pub resource: Option<ResourceHandle>,
    /// Long-operation presentation.
    pub job: Option<JobPresentation>,
    /// Compat-only hint echoed solely for transport correlation.
    pub compatibility_correlation_hint: Option<String>,
}

/// Pure stateless MCP core. It stores neither a port nor application state.
#[derive(Clone, Copy, Debug, Default)]
pub struct McpCore;

impl McpCore {
    /// Returns a non-binding initialize projection.
    #[must_use]
    pub const fn initialize(request: InitializeRequest) -> InitializeResponse {
        InitializeResponse {
            protocol_version: request.protocol_version,
            canonical_tool_count: crate::CANONICAL_TOOL_NAMES.len(),
            legacy_memory_use_alias: true,
            structured_response_limit_bytes: HARD_STRUCTURED_RESPONSE_BYTES,
            application_binding_created: false,
        }
    }

    /// Validates and dispatches a primary-profile request.
    pub fn execute<P: KernelGovernorPort + ?Sized>(
        &self,
        port: &P,
        transport: TransportRequestContext,
        request: ApplicationRequest,
    ) -> Result<McpResponse, BridgeError> {
        if request.protocol_version != McpProtocolVersion::Final2026_07_28 {
            return Err(BridgeError::invalid(
                "protocol_version",
                "the primary entrypoint admits only 2026-07-28",
            ));
        }
        Self::execute_inner(port, transport, request, None)
    }

    /// Isolated 2025-11-25 adapter. The hint cannot replace the application binding.
    pub fn execute_compat<P: KernelGovernorPort + ?Sized>(
        &self,
        port: &P,
        transport: TransportRequestContext,
        request: ApplicationRequest,
        correlation: CompatibilityCorrelation,
    ) -> Result<McpResponse, BridgeError> {
        if request.protocol_version != McpProtocolVersion::Compat2025_11_25 {
            return Err(BridgeError::invalid(
                "protocol_version",
                "compatibility correlation is only admitted for 2025-11-25",
            ));
        }
        if correlation
            .transport_session_hint
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(BridgeError::invalid(
                "compatibility.transport_session_hint",
                "must be non-blank when present",
            ));
        }
        Self::execute_inner(port, transport, request, correlation.transport_session_hint)
    }

    fn execute_inner<P: KernelGovernorPort + ?Sized>(
        port: &P,
        transport: TransportRequestContext,
        mut request: ApplicationRequest,
        compatibility_hint: Option<String>,
    ) -> Result<McpResponse, BridgeError> {
        transport.validate()?;
        validate_application_request(&request)?;
        request.tool = request.tool.canonicalized();
        let request_id = request
            .identity
            .request
            .metadata
            .request_id
            .as_str()
            .to_owned();
        let idempotency_key = request.identity.idempotency_key.clone();
        let canonical_tool_name = request.tool.canonical_name().to_owned();
        let canonical_request_sha256 = canonical_sha256(&request)?;
        let client_capabilities = request.client_capabilities;
        let resolution_request = BindingResolutionRequest {
            transport,
            claimed_session: request.session.clone(),
            request_id: request_id.clone(),
            idempotency_key: idempotency_key.clone(),
            cancellation_id: request.identity.cancellation_id.clone(),
            canonical_request_sha256: canonical_request_sha256.clone(),
            deadline_unix_ms: request.identity.deadline_unix_ms,
        };
        let active_session_binding = match port.resolve_active_session(&resolution_request) {
            Ok(binding) => binding,
            Err(failure @ (PortFailure::PlanGap { .. } | PortFailure::Unsupported { .. })) => {
                return negative_response(
                    &request_id,
                    &idempotency_key,
                    &canonical_request_sha256,
                    &canonical_tool_name,
                    compatibility_hint,
                    failure,
                );
            }
            Err(other) => return Err(BridgeError::Port(other)),
        };
        validate_active_session_binding(&resolution_request, &active_session_binding)?;
        let forwarded = ForwardedRequest {
            request,
            canonical_request_sha256: canonical_request_sha256.clone(),
            active_session_binding,
            compatibility_correlation_hint: compatibility_hint.clone(),
        };
        let projection = match port.dispatch(&forwarded) {
            Ok(value) => value,
            Err(failure @ (PortFailure::PlanGap { .. } | PortFailure::Unsupported { .. })) => {
                return negative_response(
                    &request_id,
                    &idempotency_key,
                    &canonical_request_sha256,
                    &canonical_tool_name,
                    compatibility_hint,
                    failure,
                );
            }
            Err(other) => return Err(BridgeError::Port(other)),
        };
        validate_projection(&forwarded.request.session, &projection)?;
        let kind = match projection.kind {
            ProjectionKind::Candidate => ResponseKind::Candidate,
            ProjectionKind::Projection => ResponseKind::Projection,
        };
        let job = projection.durable_job.map(|handle| {
            if client_capabilities.tasks {
                JobPresentation::McpTask { handle }
            } else {
                JobPresentation::DurableJob { handle }
            }
        });
        let response = McpResponse {
            request_id,
            idempotency_key,
            canonical_request_sha256,
            kind,
            canonical_tool_name,
            content: projection.content,
            artifacts: projection.artifacts,
            proof_ceiling: projection.proof_ceiling,
            resource: projection.resource,
            job,
            compatibility_correlation_hint: compatibility_hint,
        };
        bounded_response(response)
    }
}

/// Provider used when no real Kernel/Governor semantic provider is admitted.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoProviderPort;

impl KernelGovernorPort for NoProviderPort {
    fn resolve_active_session(
        &self,
        _request: &BindingResolutionRequest,
    ) -> Result<ActiveSessionBinding, PortFailure> {
        Err(PortFailure::PlanGap {
            missing_capability: "active-session-binding-resolver".to_owned(),
            reason: "no admitted Kernel/Governor provider is injected".to_owned(),
        })
    }

    fn dispatch(&self, request: &ForwardedRequest) -> Result<PortProjection, PortFailure> {
        Err(PortFailure::PlanGap {
            missing_capability: request.request.tool.canonical_name().to_owned(),
            reason: "no admitted Kernel/Governor provider is injected".to_owned(),
        })
    }
}

fn negative_response(
    request_id: &str,
    idempotency_key: &str,
    canonical_request_sha256: &str,
    canonical_tool_name: &str,
    compatibility_hint: Option<String>,
    failure: PortFailure,
) -> Result<McpResponse, BridgeError> {
    let (kind, content) = match failure {
        PortFailure::PlanGap {
            missing_capability,
            reason,
        } => (
            ResponseKind::PlanGap,
            json!({
                "code": "PLAN_GAP",
                "missing_capability": missing_capability,
                "reason": reason,
            }),
        ),
        PortFailure::Unsupported { capability, reason } => (
            ResponseKind::Unsupported,
            json!({
                "code": "UNSUPPORTED",
                "capability": capability,
                "reason": reason,
            }),
        ),
        other => return Err(BridgeError::Port(other)),
    };
    bounded_response(McpResponse {
        request_id: request_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        canonical_request_sha256: canonical_request_sha256.to_owned(),
        kind,
        canonical_tool_name: canonical_tool_name.to_owned(),
        content,
        artifacts: Vec::new(),
        proof_ceiling: ProofCeiling::Observation,
        resource: None,
        job: None,
        compatibility_correlation_hint: compatibility_hint,
    })
}

/// Pure bridge validation/forwarding failure.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// Input contract violation.
    #[error("INVALID_ARGUMENT at {field}: {reason}")]
    InvalidArgument {
        /// Stable field path.
        field: &'static str,
        /// Public reason.
        reason: String,
    },
    /// Semantic owner negative outcome that is not a typed plan gap.
    #[error("semantic provider: {0}")]
    Port(#[from] PortFailure),
    /// Serialization/schema failure.
    #[error("contract serialization failed: {0}")]
    Serialization(String),
    /// Structured output exceeded the hard limit without a valid resource route.
    #[error("RESOURCE_REQUIRED: structured response is {actual} bytes; maximum is {maximum}")]
    ResourceRequired {
        /// Encoded response size.
        actual: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// A resource handle did not bind the exact canonical inline content.
    #[error("RESOURCE_BINDING_MISMATCH: resource does not bind canonical content bytes")]
    ResourceBindingMismatch,
}

impl BridgeError {
    fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidArgument {
            field,
            reason: reason.into(),
        }
    }
}

fn validate_application_request(request: &ApplicationRequest) -> Result<(), BridgeError> {
    request
        .identity
        .validate()
        .map_err(|error| BridgeError::invalid("identity", error.to_string()))?;
    request
        .session
        .state_fence
        .validate()
        .map_err(|error| BridgeError::invalid("session.state_fence", error.to_string()))?;
    if request.session.authority_epoch != request.session.state_fence.authority_epoch {
        return Err(BridgeError::invalid(
            "session.authority_epoch",
            "must match session.state_fence.authority_epoch",
        ));
    }
    if request.session.state_fence != request.identity.request.state_fence {
        return Err(BridgeError::invalid(
            "identity.request.state_fence",
            "must exactly match the application Session state fence",
        ));
    }
    if request.identity.request.metadata.session_id.as_ref() != Some(&request.session.session_id) {
        return Err(BridgeError::invalid(
            "identity.request.metadata.session_id",
            "must exactly match the explicit application Session",
        ));
    }
    if request
        .identity
        .request
        .metadata
        .clock
        .known_time_ms
        .and_then(|value| u64::try_from(value).ok())
        .is_some_and(|known_time_ms| request.identity.deadline_unix_ms <= known_time_ms)
    {
        return Err(BridgeError::invalid(
            "identity.deadline_unix_ms",
            "must be later than the request known-time observation",
        ));
    }
    request.tool.validate().map_err(contract_violation)?;
    if let ToolRequest::Finish(draft) = &request.tool {
        let metadata_task = request.identity.request.metadata.task_id.as_ref();
        if !matches!(metadata_task, Some(value) if value.as_str() == draft.task_id.as_str()) {
            return Err(BridgeError::invalid(
                "finish.task_id",
                "must exactly match request metadata task_id",
            ));
        }
        if !matches!(
            request.identity.request.state_fence.task_revision,
            Some(value) if value.value() == draft.expected_task_revision
        ) {
            return Err(BridgeError::invalid(
                "finish.expected_task_revision",
                "must exactly match the request State Fence task revision",
            ));
        }
    }
    Ok(())
}

fn contract_violation(value: ContractViolation) -> BridgeError {
    match value {
        ContractViolation::InvalidField { field, reason } => BridgeError::invalid(field, reason),
    }
}

fn validate_active_session_binding(
    resolution: &BindingResolutionRequest,
    binding: &ActiveSessionBinding,
) -> Result<(), BridgeError> {
    if binding.binding_id.trim().is_empty() || binding.principal_ref.trim().is_empty() {
        return Err(BridgeError::invalid(
            "active_session_binding",
            "must identify both the live binding and authenticated principal",
        ));
    }
    binding.transport.validate()?;
    if binding.session != resolution.claimed_session {
        return Err(BridgeError::invalid(
            "active_session_binding.session",
            "must exactly match the caller claim after trusted resolution",
        ));
    }
    if binding.transport != resolution.transport {
        return Err(BridgeError::invalid(
            "active_session_binding.transport",
            "must exactly match the resolved credential, connection, profile, and generation",
        ));
    }
    if binding.request_id != resolution.request_id
        || binding.idempotency_key != resolution.idempotency_key
        || binding.cancellation_id != resolution.cancellation_id
        || binding.canonical_request_sha256 != resolution.canonical_request_sha256
    {
        return Err(BridgeError::invalid(
            "active_session_binding.request_correlation",
            "must bind the exact request, idempotency, cancellation, and canonical bytes",
        ));
    }
    if binding.resolved_at_unix_ms == 0
        || binding.resolved_at_unix_ms > resolution.deadline_unix_ms
        || binding.valid_until_unix_ms < resolution.deadline_unix_ms
        || binding.valid_until_unix_ms <= binding.resolved_at_unix_ms
    {
        return Err(BridgeError::invalid(
            "active_session_binding.validity",
            "must be current and remain valid through the exact request deadline",
        ));
    }
    Ok(())
}

fn validate_projection(
    request_session: &SessionBinding,
    projection: &PortProjection,
) -> Result<(), BridgeError> {
    validate_proof_ceiling(projection.proof_ceiling).map_err(contract_violation)?;
    let mut artifacts = BTreeSet::new();
    for artifact in &projection.artifacts {
        if !is_sha256(&artifact.sha256) {
            return Err(BridgeError::invalid(
                "response.artifacts.sha256",
                "must be a lowercase SHA-256 digest",
            ));
        }
        if artifact
            .source_revision
            .as_ref()
            .is_some_and(|revision| revision.trim().is_empty())
        {
            return Err(BridgeError::invalid(
                "response.artifacts.source_revision",
                "must be non-blank when present",
            ));
        }
        if !artifacts.insert(artifact.artifact_id.as_str()) {
            return Err(BridgeError::invalid(
                "response.artifacts",
                "must not contain duplicate artifact identities",
            ));
        }
    }
    if let Some(resource) = &projection.resource {
        validate_resource(request_session, resource)?;
        if projection
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == resource.artifact.artifact_id)
            != Some(&resource.artifact)
        {
            return Err(BridgeError::invalid(
                "response.resource.artifact",
                "must exactly match its full binding in response.artifacts",
            ));
        }
    }
    if let Some(job) = &projection.durable_job {
        validate_job(request_session, job)?;
    }
    Ok(())
}

fn validate_resource(
    request_session: &SessionBinding,
    resource: &ResourceHandle,
) -> Result<(), BridgeError> {
    if !resource.uri.starts_with("eliot://resource/") {
        return Err(BridgeError::invalid(
            "response.resource.uri",
            "must be an immutable eliot://resource/ URI",
        ));
    }
    if resource.media_type.trim().is_empty() || resource.size_bytes == 0 {
        return Err(BridgeError::invalid(
            "response.resource",
            "must have a media type and nonzero exact size",
        ));
    }
    if !is_sha256(&resource.artifact.sha256) {
        return Err(BridgeError::invalid(
            "response.resource.artifact.sha256",
            "must be a lowercase SHA-256 digest",
        ));
    }
    if &resource.session != request_session {
        return Err(BridgeError::invalid(
            "response.resource.session",
            "must exactly match the request Session and State Fence",
        ));
    }
    Ok(())
}

fn validate_job(
    request_session: &SessionBinding,
    job: &DurableJobHandle,
) -> Result<(), BridgeError> {
    if job.job_id.trim().is_empty()
        || !job.resource_uri.starts_with("eliot://job/")
        || job.revision == 0
    {
        return Err(BridgeError::invalid(
            "response.durable_job",
            "must have a non-blank identity, immutable job URI, and nonzero revision",
        ));
    }
    if &job.session != request_session {
        return Err(BridgeError::invalid(
            "response.durable_job.session",
            "must exactly match the request Session and State Fence",
        ));
    }
    Ok(())
}

fn bounded_response(mut response: McpResponse) -> Result<McpResponse, BridgeError> {
    let encoded = serde_json::to_vec(&response)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    if encoded.len() <= HARD_STRUCTURED_RESPONSE_BYTES {
        return Ok(response);
    }
    let Some(resource) = response.resource.as_ref() else {
        return Err(BridgeError::ResourceRequired {
            actual: encoded.len(),
            maximum: HARD_STRUCTURED_RESPONSE_BYTES,
        });
    };
    let canonical_content = canonicalize(response.content.clone());
    let canonical_content_bytes = serde_json::to_vec(&canonical_content)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    let content_size = u64::try_from(canonical_content_bytes.len())
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    let content_sha256 = hex_digest(&Sha256::digest(&canonical_content_bytes));
    if resource.media_type != "application/json"
        || resource.size_bytes != content_size
        || resource.artifact.sha256 != content_sha256
    {
        return Err(BridgeError::ResourceBindingMismatch);
    }
    response.content = json!({
        "resource_uri": resource.uri,
        "artifact_id": resource.artifact.artifact_id,
        "sha256": resource.artifact.sha256,
        "size_bytes": resource.size_bytes,
    });
    let bounded = serde_json::to_vec(&response)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    if bounded.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        return Err(BridgeError::ResourceRequired {
            actual: bounded.len(),
            maximum: HARD_STRUCTURED_RESPONSE_BYTES,
        });
    }
    Ok(response)
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, BridgeError> {
    let value = serde_json::to_value(value)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    Ok(hex_digest(&Sha256::digest(bytes)))
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut keys = values.into_iter().collect::<Vec<_>>();
            keys.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                keys.into_iter()
                    .map(|(key, value)| (key, canonicalize(value)))
                    .collect::<Map<_, _>>(),
            )
        }
        other => other,
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}
