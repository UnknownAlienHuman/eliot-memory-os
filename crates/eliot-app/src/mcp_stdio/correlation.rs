//! MCP invocation correlation for the legacy stdio facade.
//!
//! GitHub issue #7 observed one completed local MCP stdio response while the
//! host later displayed a timeout/stale responding state. The 2026-08-05
//! observation is stale evidence: it does not distinguish a Desktop UI defect,
//! host bridge correlation loss, stdio delivery loss, adapter event loss, or an
//! operation that was never durably staged. This module carries the ELIOT-side
//! half of that correlation — MCP request identity through server handling,
//! response framing, and stdout write/flush disposition — so a fresh
//! current-fingerprint run can bind or refute each hypothesis with evidence.
//!
//! Issue #2899 keeps three facts separate throughout:
//!
//! 1. ELIOT wrote and flushed a response frame ([`EliotEmissionObservation`]);
//! 2. host/UI completion is not yet observed or coverage is unavailable
//!    ([`PartialObservation`], [`CoverageProof`]);
//! 3. competent host evidence proves a route fault, timeout, misclassification
//!    or transport loss ([`CorrelationAssessmentState`], [`RouteDegradation`]).
//!
//! The immediate stdio boundary records only the first fact plus an explicit
//! `PartialUnknown` denominator. It never classifies a healthy emission as
//! degradation and never prescribes recovery without owner evidence. Observed
//! host terminal state ([`HostTerminalState`]) arrives only through the
//! host-event adapter; derived fault classes arrive only through
//! [`assess_correlation`] with competent evidence; retry authority arrives only
//! through an owner-minted [`OwnerValidatedOperationBinding`].
//!
//! Carriers only: nothing here changes wire payloads, canonical write
//! semantics, finish semantics, or host UI expectations. Structured events
//! carry identifiers, digests, stages, counts, and outcome classes; they never
//! carry tool payloads, host secrets, or private conversation content, per
//! `docs/integrations/claude/CLAUDE_INTEGRATION_SECURITY.md`.

use anyhow::Context as _;
use eliot_agent_bridge_core::TransportEdgeKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

/// Stable schema identity for ELIOT-side MCP invocation correlation records.
///
/// Version 2 separates the immutable emission observation from later host
/// assessment revisions (issue #2899). Version 1 combined them and classified
/// every healthy emission as route degradation.
pub(crate) const CORRELATION_SCHEMA_ID: &str = "eliot.mcp-stdio-correlation.v2";

/// Version of the logical correlation identity bound into every record.
pub(crate) const CORRELATION_IDENTITY_VERSION: u32 = 1;

/// Maximum assessment revisions retained on one correlation record.
///
/// The record is per-invocation and dropped after emission; the cap only
/// bounds the append-only revision chain, never a process-wide table.
pub(crate) const MAX_ASSESSMENT_REVISIONS: usize = 16;

/// Maximum missing-evidence entries carried by one assessment summary.
pub(crate) const MAX_SUMMARY_EVIDENCE: usize = 8;

/// Lowercase hex SHA-256 over opaque bytes, for join digests.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Versioned logical identity of one MCP invocation (issue #2899, item 1).
///
/// Binds the transport request, the exact method/tool, the serving host
/// profile and session, and the route/process generation. Where the tool
/// owner issued an operation handle, the binding joins it here; raw caller
/// strings never enter this identity until the owner resolves them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct CorrelationIdentity {
    /// Identity schema version ([`CORRELATION_IDENTITY_VERSION`]).
    pub(crate) version: u32,
    /// Stringified JSON-RPC request id (transport correlation).
    pub(crate) mcp_request_id: String,
    /// JSON-RPC method name.
    pub(crate) method: String,
    /// Tool name for `tools/call`, when present.
    pub(crate) tool_name: Option<String>,
    /// Integration/host access profile that served the request, when observed.
    pub(crate) host_profile: Option<String>,
    /// Authenticated ELIOT session that served the request, when known.
    pub(crate) session_id: Option<String>,
    /// Runtime instance identity, when observed.
    pub(crate) runtime_id: Option<String>,
    /// Authority generation of the serving route/process, when observed.
    pub(crate) auth_generation: Option<String>,
    /// Owner-issued retry-stable operation handle, when the tool owner bound one.
    pub(crate) owner_operation_handle: Option<String>,
    /// Owner-attested effect class, when the tool owner bound one.
    pub(crate) effect_class: Option<OperationEffectClass>,
    /// Digest over the canonical identity fields above; the exact join key.
    pub(crate) identity_digest: String,
}

impl CorrelationIdentity {
    /// Assembles the identity from observed record fields and digests it.
    ///
    /// Absent fields digest as empty segments; absence is explicit, never a
    /// fabricated default generation or profile.
    pub(crate) fn assemble(correlation: &McpInvocationCorrelation) -> Self {
        let binding = correlation.operation_binding.as_ref();
        let owner_operation_handle = binding.map(|bound| bound.retry_identity.clone());
        let effect_class = binding.map(|bound| bound.effect_class);
        let mut canonical = String::from("eliot.mcp-correlation-identity.v1\0");
        for segment in [
            correlation.mcp_request_id.as_str(),
            correlation.method.as_str(),
            correlation.tool_name.as_deref().unwrap_or_default(),
            correlation.route_profile.as_deref().unwrap_or_default(),
            correlation.session_id.as_deref().unwrap_or_default(),
            correlation.route_runtime_id.as_deref().unwrap_or_default(),
            correlation
                .route_auth_generation
                .as_deref()
                .unwrap_or_default(),
            owner_operation_handle.as_deref().unwrap_or_default(),
            effect_class.map_or("", OperationEffectClass::as_str),
        ] {
            canonical.push_str(segment);
            canonical.push('\0');
        }
        Self {
            version: CORRELATION_IDENTITY_VERSION,
            mcp_request_id: correlation.mcp_request_id.clone(),
            method: correlation.method.clone(),
            tool_name: correlation.tool_name.clone(),
            host_profile: correlation.route_profile.clone(),
            session_id: correlation.session_id.clone(),
            runtime_id: correlation.route_runtime_id.clone(),
            auth_generation: correlation.route_auth_generation.clone(),
            owner_operation_handle,
            effect_class,
            identity_digest: sha256_hex(canonical.as_bytes()),
        }
    }
}

/// Identity of the idempotent operation a `tools/call` request carries, if any.
///
/// Extracted read-only from call arguments (`write_id`, `idempotency_key`).
/// These are UNTRUSTED caller hints: they are preserved as a diagnostic
/// carrier only and can never authorize resubmission. Retry authority
/// requires an owner-minted [`OwnerValidatedOperationBinding`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct OperationIdentity {
    /// Caller-supplied idempotency key hint, when the call carried one.
    pub(crate) idempotency_key: Option<String>,
    /// Caller-supplied write id hint, when the call carried one.
    pub(crate) write_id: Option<String>,
}

impl OperationIdentity {
    /// Extracts operation identity hints from `tools/call` params, unvalidated.
    ///
    /// Validation stays with the owning tool handler; this only preserves the
    /// carrier so a later stage can bind request to operation once the owner
    /// resolves the hints.
    pub(crate) fn from_call_params(params: &Value) -> Self {
        let arguments = params.get("arguments").unwrap_or(&Value::Null);
        Self {
            idempotency_key: arguments
                .get("idempotency_key")
                .and_then(Value::as_str)
                .map(str::to_owned),
            write_id: arguments
                .get("write_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }

    /// Whether the call carried any operation identity hint at all.
    pub(crate) const fn is_empty(&self) -> bool {
        self.idempotency_key.is_none() && self.write_id.is_none()
    }
}

/// Observable ELIOT-side stage of one MCP invocation.
///
/// Constructed, written, flushed, host-acknowledged, UI-observed, and
/// canonically committed stages stay distinct: reaching one stage never
/// implies a later one (I7.2 transport acknowledgement cannot impersonate
/// durable or canonical application).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CorrelationStage {
    /// Raw JSON-RPC line received and parsed.
    Received,
    /// Handler produced a result or typed error; response envelope built.
    HandlerCompleted,
    /// Response bytes framed for stdout emission.
    Framed,
    /// Bytes written and flushed on stdout.
    Emitted,
    /// Stdout emission failed; host delivery is unconfirmed.
    EmissionFailed,
}

impl CorrelationStage {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::HandlerCompleted => "handler_completed",
            Self::Framed => "framed",
            Self::Emitted => "emitted",
            Self::EmissionFailed => "emission_failed",
        }
    }
}

/// Typed outcome of the request handler on this path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HandlerOutcome {
    /// Handler produced a success result.
    CompletedOk,
    /// Handler produced a typed JSON-RPC error envelope with this code.
    JsonRpcError {
        /// JSON-RPC error code of the produced envelope.
        code: i64,
    },
    /// Handler failed without a typed envelope.
    InternalFailure,
    /// No handler ran on this path (relayed responses observe framing only).
    NotObservedOnThisPath,
}

impl HandlerOutcome {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CompletedOk => "completed_ok",
            Self::JsonRpcError { .. } => "json_rpc_error",
            Self::InternalFailure => "internal_failure",
            Self::NotObservedOnThisPath => "not_observed_on_this_path",
        }
    }

    /// Whether the handler provably produced a success envelope.
    pub(crate) const fn is_success(self) -> bool {
        matches!(self, Self::CompletedOk)
    }
}

/// Terminal cause of one stdout frame emission on the Governor stdio path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EmissionCause {
    /// Bytes written and flushed; host delivery handed to the pipe.
    Emitted,
    /// Framed bytes were not fully written.
    WriteFailed,
    /// Bytes were written but the flush failed, so delivery is unconfirmed.
    FlushFailed,
}

impl EmissionCause {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Emitted => "emitted",
            Self::WriteFailed => "write_failed",
            Self::FlushFailed => "flush_failed",
        }
    }
}

/// Immutable disposition of one stdout response emission.
///
/// Populated at the exact write/flush stage with the real framed byte count
/// and the real flush outcome. `bytes` counts only fully placed frames; a
/// failed emission carries zero bytes even if the transport accepted a prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct StdioEmissionReceipt {
    /// Exact bytes placed on stdout, including the framing newline.
    pub(crate) bytes: usize,
    /// Whether the stream flush succeeded after the bytes were written.
    pub(crate) flushed: bool,
    /// Terminal cause of this emission.
    pub(crate) cause: EmissionCause,
}

impl StdioEmissionReceipt {
    /// Fails closed when the emission did not provably reach the pipe.
    ///
    /// Callers propagate the error exactly as the previous bare `?` on
    /// `write_all`/`flush` did; the receipt only adds the typed stage.
    pub(crate) fn into_result(self, mcp_request_id: &str) -> anyhow::Result<usize> {
        if self.flushed && matches!(self.cause, EmissionCause::Emitted) {
            Ok(self.bytes)
        } else {
            let cause = self.cause.as_str();
            let bytes = self.bytes;
            let flushed = self.flushed;
            anyhow::bail!(
                "STDIO_EMISSION_FAILED: request_id={mcp_request_id} cause={cause} bytes={bytes} flushed={flushed}"
            );
        }
    }
}

/// Writes one already-framed response to stdout and captures the disposition.
///
/// The frame must include its trailing newline. The outcome is reported as a
/// receipt instead of `Result` so the caller always observes the exact stage,
/// then fails closed through [`StdioEmissionReceipt::into_result`].
pub(crate) fn emit_stdout_frame(frame: &[u8]) -> StdioEmissionReceipt {
    use std::io::Write as _;
    let mut stdout = std::io::stdout();
    if stdout.write_all(frame).is_err() {
        return StdioEmissionReceipt {
            bytes: 0,
            flushed: false,
            cause: EmissionCause::WriteFailed,
        };
    }
    if stdout.flush().is_err() {
        return StdioEmissionReceipt {
            bytes: 0,
            flushed: false,
            cause: EmissionCause::FlushFailed,
        };
    }
    StdioEmissionReceipt {
        bytes: frame.len(),
        flushed: true,
        cause: EmissionCause::Emitted,
    }
}

/// Verifies that a relayed response belongs to the request being served.
///
/// The stdio facade previously forwarded whatever the daemon returned without
/// checking the envelope id. A mismatched envelope misattributes completion:
/// the caller keeps waiting on its own id (a phantom timeout) while another
/// invocation's outcome is delivered to the wrong waiter. Fail closed instead.
pub(crate) fn check_response_correlation(
    request_id: &Value,
    response_line: &str,
) -> anyhow::Result<Value> {
    let response: Value = serde_json::from_str(response_line)
        .with_context(|| "parse relayed MCP response envelope")?;
    let response_id = response.get("id");
    if response_id != Some(request_id) {
        anyhow::bail!(
            "RESPONSE_CORRELATION_MISMATCH: relayed response id does not match the served MCP request id"
        );
    }
    Ok(response)
}

/// ELIOT-side correlation record for one MCP invocation.
///
/// Built at receive time from the request envelope, advanced through handler
/// and emission stages, and emitted as one structured event. Host/UI terminal
/// state is never inferred here; see [`HostTerminalObservation`].
#[derive(Clone, Debug, Serialize)]
pub(crate) struct McpInvocationCorrelation {
    /// Schema identity of this record.
    pub(crate) schema: &'static str,
    /// Stringified JSON-RPC request id.
    pub(crate) mcp_request_id: String,
    /// JSON-RPC method name.
    pub(crate) method: String,
    /// Tool name for `tools/call`, when present.
    pub(crate) tool_name: Option<String>,
    /// Untrusted operation identity hints carried by the call arguments.
    pub(crate) operation: OperationIdentity,
    /// Owner-validated operation binding, when a tool owner minted one.
    pub(crate) operation_binding: Option<OwnerValidatedOperationBinding>,
    /// Authenticated session that served the request, when known.
    pub(crate) session_id: Option<String>,
    /// Integration/host access profile that served the request, when observed.
    pub(crate) route_profile: Option<String>,
    /// Runtime instance identity, when observed.
    pub(crate) route_runtime_id: Option<String>,
    /// Authority generation of the serving route/process, when observed.
    pub(crate) route_auth_generation: Option<String>,
    /// Time the request line was received.
    pub(crate) received_at: OffsetDateTime,
    /// Latest observed ELIOT-side stage.
    pub(crate) stage: CorrelationStage,
    /// Typed handler outcome observed on this path.
    pub(crate) handler_outcome: HandlerOutcome,
    /// Whether the request was rejected before any handler ran.
    pub(crate) failed_before_handler: bool,
    /// JSON-RPC error code of the produced envelope, when it is an error.
    pub(crate) error_code: Option<i64>,
    /// Canonical receipt write id observed in the result, when present.
    pub(crate) receipt_write_id: Option<String>,
    /// Exact framed response bytes, once framed.
    pub(crate) response_bytes: Option<usize>,
    /// Stdout emission disposition, once emitted or failed.
    pub(crate) emission: Option<StdioEmissionReceipt>,
    /// Append-only assessment revisions for this invocation.
    pub(crate) assessments: AssessmentLog,
}

impl McpInvocationCorrelation {
    /// Binds a received request envelope to its correlation carriers.
    pub(crate) fn receive(request: &Value, method: &str) -> Self {
        let params = request.get("params").unwrap_or(&Value::Null);
        Self {
            schema: CORRELATION_SCHEMA_ID,
            mcp_request_id: request_id_string(request.get("id")),
            method: method.to_owned(),
            tool_name: if method == "tools/call" {
                params
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            } else {
                None
            },
            operation: if method == "tools/call" {
                OperationIdentity::from_call_params(params)
            } else {
                OperationIdentity::default()
            },
            operation_binding: None,
            session_id: None,
            route_profile: None,
            route_runtime_id: None,
            route_auth_generation: None,
            received_at: OffsetDateTime::now_utc(),
            stage: CorrelationStage::Received,
            handler_outcome: HandlerOutcome::NotObservedOnThisPath,
            failed_before_handler: false,
            error_code: None,
            receipt_write_id: None,
            response_bytes: None,
            emission: None,
            assessments: AssessmentLog::default(),
        }
    }

    /// Records the authenticated session that served this invocation.
    pub(crate) fn observe_session(&mut self, session_id: &str) {
        self.session_id = Some(session_id.to_owned());
    }

    /// Records the serving route context for the correlation identity.
    ///
    /// The profile names the integration/host access path; the runtime id and
    /// authority generation pin the exact serving route/process generation so
    /// a later host observation can prove it belongs to this invocation.
    pub(crate) fn observe_route_context(
        &mut self,
        profile: &str,
        runtime_id: &str,
        auth_generation: &str,
    ) {
        self.route_profile = Some(profile.to_owned());
        self.route_runtime_id = Some(runtime_id.to_owned());
        self.route_auth_generation = Some(auth_generation.to_owned());
    }

    /// Records an owner-minted operation binding for this invocation.
    ///
    /// Only the tool handler/result owner may mint the binding; the facade
    /// never derives one from caller strings. No current tool owner mints
    /// bindings yet, so this stays unset and resubmission stays omitted.
    #[allow(
        dead_code,
        reason = "owner seam: invoked only once a tool owner mints bindings; unset keeps resubmit omitted (#2899)"
    )]
    pub(crate) fn observe_owner_operation_binding(
        &mut self,
        binding: OwnerValidatedOperationBinding,
    ) {
        self.operation_binding = Some(binding);
    }

    /// Records handler completion and extracts receipt correlation, if any.
    ///
    /// Reads only the stable receipt carrier (`result.write_receipt.write_id`)
    /// emitted by committing tools; other results leave it absent, which is
    /// itself the honest record for read-only invocations.
    pub(crate) fn observe_handler_result(&mut self, result: &Result<Value, anyhow::Error>) {
        self.stage = CorrelationStage::HandlerCompleted;
        if let Ok(value) = result {
            self.handler_outcome = HandlerOutcome::CompletedOk;
            self.receipt_write_id = value
                .get("write_receipt")
                .and_then(|receipt| receipt.get("write_id"))
                .and_then(|write_id| {
                    write_id
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| serde_json::to_string(write_id).ok())
                });
        } else {
            self.handler_outcome = HandlerOutcome::InternalFailure;
            self.error_code = Some(-32603);
        }
    }

    /// Records a typed handler error code for early-rejection envelopes.
    ///
    /// Early rejection runs before any tool handler, so the invocation failed
    /// before any mutating stage could execute.
    pub(crate) fn observe_error_code(&mut self, code: i64) {
        self.stage = CorrelationStage::HandlerCompleted;
        self.handler_outcome = HandlerOutcome::JsonRpcError { code };
        self.failed_before_handler = true;
        self.error_code = Some(code);
    }

    /// Records response framing.
    pub(crate) fn observe_framed(&mut self, bytes: usize) {
        self.stage = CorrelationStage::Framed;
        self.response_bytes = Some(bytes);
    }

    /// Records stdout emission disposition.
    pub(crate) fn observe_emission(&mut self, receipt: &StdioEmissionReceipt) {
        self.stage = if receipt.flushed && matches!(receipt.cause, EmissionCause::Emitted) {
            CorrelationStage::Emitted
        } else {
            CorrelationStage::EmissionFailed
        };
        self.emission = Some(*receipt);
    }

    /// Whether ELIOT provably wrote and flushed exactly one response frame.
    pub(crate) const fn emitted_exactly_once(&self) -> bool {
        matches!(self.stage, CorrelationStage::Emitted)
    }

    /// Assembles the versioned logical identity for this invocation.
    pub(crate) fn identity(&self) -> CorrelationIdentity {
        CorrelationIdentity::assemble(self)
    }

    /// Derives the canonical disposition provable from facade evidence alone.
    ///
    /// The facade owns its protocol-method handlers (known reads) and observes
    /// early rejection (failed before any handler) and canonical receipt
    /// carriers. It never observes exact readback, so committed-with-readback
    /// and rolled-back dispositions stay with the canonical owner.
    pub(crate) fn facade_canonical_disposition(&self) -> CanonicalDisposition {
        let commit = CommitEvidence {
            canonical_receipt_write_id: self.receipt_write_id.clone(),
            exact_readback_match: None,
        };
        CanonicalDisposition::from_facade_evidence(
            &self.method,
            self.failed_before_handler,
            &commit,
        )
    }

    /// Emits one structured correlation event: emission observation only.
    ///
    /// Fields are identifiers, digests, stages, counts, and outcome classes
    /// only. Request/response payloads are never logged. The event records
    /// the immutable [`EliotEmissionObservation`] plus the explicit
    /// `PartialUnknown` coverage ceiling and appends the initial assessment
    /// revision, which is pending — never a degradation — while host evidence
    /// is absent. A successful emission therefore produces no
    /// route-degradation code and no recovery directive (issue #2899).
    pub(crate) fn emit(&mut self) {
        let observation = EliotEmissionObservation::from_correlation(self);
        let gaps: Vec<&str> = observation
            .coverage
            .missing
            .iter()
            .map(|gap| gap.as_str())
            .collect();
        let window = ObservationWindow::no_host_evidence();
        let host = HostTerminalObservation::PartialUnknown(observation.coverage.clone());
        let canonical = self.facade_canonical_disposition();
        let inputs = AssessmentInputs {
            emission: &observation,
            host: &host,
            window: &window,
            transport_edge: None,
            operation_binding: self.operation_binding.as_ref(),
            canonical: &canonical,
            ui_confirmed_stale: false,
        };
        let assessment = assess_correlation(&inputs);
        let digest = observation.identity.identity_digest.clone();
        if self.assessments.append(&digest, assessment).is_err() {
            return;
        }
        let summary = AssessmentSummary::summarize(self.assessments.revisions());
        let missing: Vec<&str> = summary
            .missing_evidence
            .iter()
            .map(String::as_str)
            .collect();
        let Some(latest) = self.assessments.latest() else {
            return;
        };
        let assessment_state = latest.assessment.state.as_str();
        let assessment_revision = latest.revision;
        let host_terminal_state = match host {
            HostTerminalObservation::Observed { state, .. } => state.as_str(),
            HostTerminalObservation::PartialUnknown(_) => "",
        };
        let coverage_proof = window.coverage.as_str();
        let route_degradation = latest
            .assessment
            .degradation
            .as_ref()
            .map_or("", |degradation| degradation.code.as_str());
        let recovery_actions = latest
            .assessment
            .recovery
            .as_ref()
            .map_or_else(String::new, RecoveryDirective::action_names);
        tracing::info!(
            schema = self.schema,
            mcp_request_id = %self.mcp_request_id,
            identity_digest = %digest,
            identity_version = CORRELATION_IDENTITY_VERSION,
            method = %self.method,
            tool_name = self.tool_name.as_deref().unwrap_or(""),
            operation_present = !self.operation.is_empty(),
            idempotency_key_present = self.operation.idempotency_key.is_some(),
            operation_write_id = self.operation.write_id.as_deref().unwrap_or(""),
            owner_operation_bound = self.operation_binding.is_some(),
            receipt_write_id = self.receipt_write_id.as_deref().unwrap_or(""),
            session_id = self.session_id.as_deref().unwrap_or(""),
            host_profile = self.route_profile.as_deref().unwrap_or(""),
            route_runtime_id = self.route_runtime_id.as_deref().unwrap_or(""),
            route_auth_generation = self.route_auth_generation.as_deref().unwrap_or(""),
            received_at = %self.received_at,
            stage = self.stage.as_str(),
            handler_outcome = self.handler_outcome.as_str(),
            error_code = self.error_code.unwrap_or(0),
            response_bytes = self.response_bytes.unwrap_or(0),
            emission_cause = self.emission.map_or("", |receipt| receipt.cause.as_str()),
            emitted_exactly_once = self.emitted_exactly_once(),
            canonical_disposition = canonical.as_str(),
            host_observation = host.as_str(),
            host_terminal_state = host_terminal_state,
            coverage_proof = coverage_proof,
            coverage_gaps = ?gaps,
            coverage_note = %observation.coverage.coverage_note,
            assessment_state = assessment_state,
            assessment_revision = assessment_revision,
            route_degradation = route_degradation,
            recovery_actions = %recovery_actions,
            pending_count = summary.pending,
            completed_count = summary.completed,
            degraded_count = summary.degraded,
            missing_evidence = ?missing,
            "mcp invocation correlation"
        );
    }
}

/// Stringifies a JSON-RPC id for correlation without touching the envelope.
fn request_id_string(id: Option<&Value>) -> String {
    match id {
        None => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// Immutable ELIOT-side observation of one MCP invocation (issue #2899, item 2).
///
/// Records only what the stdio boundary directly observed: the correlation
/// identity, the receive/handler/frame/emission stages, the exact byte/flush
/// receipt, the typed handler outcome, and the explicit `PartialUnknown`
/// coverage ceiling. A successful emission observation carries no
/// route-degradation code and no recovery directive; those arrive only in
/// later [`Assessment`] revisions derived from competent host evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct EliotEmissionObservation {
    /// Versioned logical identity of the invocation.
    pub(crate) identity: CorrelationIdentity,
    /// Latest ELIOT-side stage actually reached.
    pub(crate) stage: CorrelationStage,
    /// Typed handler outcome observed on this path.
    pub(crate) handler_outcome: HandlerOutcome,
    /// Exact framed response bytes, once framed.
    pub(crate) framed_bytes: Option<usize>,
    /// Stdout emission disposition, once emitted or failed.
    pub(crate) emission: Option<StdioEmissionReceipt>,
    /// Explicit coverage ceiling: host/UI state stays unobserved here.
    pub(crate) coverage: PartialObservation,
}

impl EliotEmissionObservation {
    /// Freezes the ELIOT-side record into its immutable observation.
    pub(crate) fn from_correlation(correlation: &McpInvocationCorrelation) -> Self {
        Self {
            identity: correlation.identity(),
            stage: correlation.stage,
            handler_outcome: correlation.handler_outcome,
            framed_bytes: correlation.response_bytes,
            emission: correlation.emission,
            coverage: PartialObservation::stdio_boundary(),
        }
    }

    /// Whether ELIOT provably wrote and flushed exactly one response frame.
    pub(crate) const fn emitted_exactly_once(&self) -> bool {
        matches!(self.stage, CorrelationStage::Emitted)
    }
}

/// Host/UI terminal state attested by competent host evidence.
///
/// Terminal states a host event can directly attest are `Observed`; stuck,
/// misclassified, and transport-loss classes are never observed — they are
/// derived by [`assess_correlation`] from deadline plus coverage proof, from
/// comparing a host error against a proven success envelope, or from an
/// owner-recorded disconnect edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostTerminalObservation {
    /// A competent host observation attested the terminal state.
    Observed {
        /// What the host terminally reached.
        state: HostTerminalState,
        /// Typed identity/digest evidence for the attesting event.
        evidence: Box<HostObservationEvidence>,
    },
    /// Host/UI terminal state is not observable from this boundary.
    PartialUnknown(PartialObservation),
}

impl HostTerminalObservation {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Observed { .. } => "observed",
            Self::PartialUnknown(_) => "partial_unknown",
        }
    }
}

/// Terminal states a host invocation event can directly attest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostTerminalState {
    /// The host completed the invocation and cleared the responding indicator.
    InvocationCompleted,
    /// The host surfaced an invocation error.
    InvocationError,
}

impl HostTerminalState {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvocationCompleted => "invocation_completed",
            Self::InvocationError => "invocation_error",
        }
    }
}

/// Typed identity/digest evidence for one observed host terminal event.
///
/// Identifiers, digests, sequences, and closed codes only. No tool arguments,
/// response bodies, conversation content, credentials, or host-controlled
/// prose ever enter this evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct HostObservationEvidence {
    /// Host integration identity that produced the observation.
    pub(crate) integration_id: String,
    /// Installation identity the observation is bound to.
    pub(crate) installation_id: String,
    /// Session generation the observation is bound to.
    pub(crate) session_generation: String,
    /// Process generation the observation is bound to.
    pub(crate) process_generation: String,
    /// Owner-attested correlation digest this event is joined to.
    pub(crate) correlation_digest: String,
    /// Digest of the route fingerprint the event arrived on.
    pub(crate) route_digest: String,
    /// Host event identity from the owning journal.
    pub(crate) event_id: String,
    /// Host observation sequence of the event.
    pub(crate) sequence: u64,
    /// Resume cursor carried by the event.
    pub(crate) cursor: String,
    /// Digest over the canonical event bytes, for replay/conflict checks.
    pub(crate) event_digest: String,
    /// Host-observed time carried by the event.
    pub(crate) observed_at: String,
    /// Applicable observation deadline, when the owner admitted one.
    pub(crate) deadline_unix_ms: Option<u64>,
}

/// Explicit coverage ceiling for unobservable host/UI state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct PartialObservation {
    /// Which host/UI evidence is missing.
    pub(crate) missing: Vec<CoverageGap>,
    /// Why the gap cannot be closed from this boundary.
    pub(crate) coverage_note: String,
}

impl PartialObservation {
    /// Coverage ceiling honest at the stdio facade boundary.
    pub(crate) fn stdio_boundary() -> Self {
        Self {
            missing: vec![
                CoverageGap::HostBridgeEvents,
                CoverageGap::UiTerminalState,
                CoverageGap::SequenceCursor,
                CoverageGap::EventTimestamps,
            ],
            coverage_note:
                "host/UI terminal state is outside the ELIOT process; observe it out of band"
                    .to_owned(),
        }
    }
}

/// One unobservable host/UI evidence class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoverageGap {
    /// Host bridge/tool-invocation completion events.
    HostBridgeEvents,
    /// Desktop-visible terminal indicator state.
    UiTerminalState,
    /// Host event sequence/cursor denominator.
    SequenceCursor,
    /// Host-side event timestamps.
    EventTimestamps,
}

impl CoverageGap {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::HostBridgeEvents => "host_bridge_events",
            Self::UiTerminalState => "ui_terminal_state",
            Self::SequenceCursor => "sequence_cursor",
            Self::EventTimestamps => "event_timestamps",
        }
    }
}

/// Owner-proven coverage over the host-event interval (issue #2899, item 7).
///
/// A stuck/timeout conclusion requires [`CoverageProof::CompleteInterval`]
/// past the admitted deadline. No event yet is pending; a cursor gap is
/// unknown; only an explicit host state or an owner-proven complete interval
/// past deadline may establish a fault class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoverageProof {
    /// No host event observed yet; the invocation is still pending.
    NoEventYet,
    /// The owner observed a cursor/sequence gap over the interval.
    CursorGap {
        /// Highest contiguous sequence observed.
        last_contiguous_seq: u64,
        /// Highest sequence observed past the gap.
        highest_observed_seq: u64,
    },
    /// The owner proved a contiguous observed interval.
    CompleteInterval {
        /// First contiguous sequence of the proven interval.
        from_seq: u64,
        /// Last contiguous sequence of the proven interval.
        to_seq: u64,
    },
    /// Coverage cannot be proven (rotation, unattached owner, no denominator).
    Indeterminate {
        /// Why coverage is unprovable.
        cause: CoverageIndeterminacy,
    },
}

impl CoverageProof {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::NoEventYet => "no_event_yet",
            Self::CursorGap { .. } => "cursor_gap",
            Self::CompleteInterval { .. } => "complete_interval",
            Self::Indeterminate { .. } => "indeterminate",
        }
    }
}

/// Why host-event coverage is unprovable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoverageIndeterminacy {
    /// The owning journal rotated, so the interval is no longer contiguous.
    JournalRotated,
    /// The event owner is unattached, so no denominator exists.
    OwnerUnattached,
    /// No host-event stream was ever admitted for this route.
    NoStreamAdmitted,
}

impl CoverageIndeterminacy {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::JournalRotated => "journal_rotated",
            Self::OwnerUnattached => "owner_unattached",
            Self::NoStreamAdmitted => "no_stream_admitted",
        }
    }
}

/// Bounded observation window admitted by the event owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ObservationWindow {
    /// Settlement deadline admitted by the owner, when one exists.
    pub(crate) deadline_unix_ms: Option<u64>,
    /// Owner clock at assessment time, when the owner supplied one.
    pub(crate) now_unix_ms: Option<u64>,
    /// Owner-proven coverage over the host-event interval.
    pub(crate) coverage: CoverageProof,
}

impl ObservationWindow {
    /// Window honest at the stdio facade: no host evidence, no deadline.
    pub(crate) const fn no_host_evidence() -> Self {
        Self {
            deadline_unix_ms: None,
            now_unix_ms: None,
            coverage: CoverageProof::NoEventYet,
        }
    }

    /// Whether a complete observed interval extends past the admitted deadline.
    ///
    /// False unless the owner proved a complete interval AND admitted both a
    /// deadline and a clock reading past it. Anything else stays pending.
    pub(crate) const fn complete_interval_past_deadline(&self) -> bool {
        match (&self.coverage, self.deadline_unix_ms, self.now_unix_ms) {
            (CoverageProof::CompleteInterval { .. }, Some(deadline), Some(now)) => now > deadline,
            _ => false,
        }
    }
}

/// Owner-attested effect class of one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationEffectClass {
    /// The operation performs no mutation.
    ReadOnly,
    /// The operation may mutate and is safe to replay under its retry identity.
    MutatingRetryStable,
    /// The operation may mutate and must never be replayed as the same identity.
    MutatingSingleShot,
}

impl OperationEffectClass {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::MutatingRetryStable => "mutating_retry_stable",
            Self::MutatingSingleShot => "mutating_single_shot",
        }
    }
}

/// Typed operation binding minted by the tool handler/result owner.
///
/// This is the only retry authority in correlation: [`RecoveryAction::ResubmitSameOperationIdentity`]
/// is derivable only when a binding exists and its owner-approved recovery
/// options include resubmission. Caller `write_id`/`idempotency_key` strings
/// can never mint this type; only the owning tool can, after proving the
/// operation is retry-stable and safe to reconcile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct OwnerValidatedOperationBinding {
    /// Digest of the canonical operation/request the owner admitted.
    operation_digest: String,
    /// Owner-issued retry-stable identity for same-operation replay.
    retry_identity: String,
    /// Owner-attested effect class.
    effect_class: OperationEffectClass,
    /// Durable state handle carrying the operation disposition.
    durable_state_ref: String,
    /// Independent readback handle, when the owner holds one.
    readback_ref: Option<String>,
    /// Owner-approved recovery subset; resubmit requires explicit inclusion.
    approved_recovery: Vec<RecoveryAction>,
}

/// Why an owner operation binding was rejected at mint time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OwnerBindingError {
    /// A required identity handle was blank.
    BlankField(&'static str),
}

impl std::fmt::Display for OwnerBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlankField(field) => {
                write!(
                    formatter,
                    "owner operation binding field {field} must not be blank"
                )
            }
        }
    }
}

impl std::error::Error for OwnerBindingError {}

impl OwnerValidatedOperationBinding {
    /// Mints the binding from owner-held evidence. Fails closed on blanks.
    ///
    /// Callable only by the tool handler/result owner: the facade never
    /// invokes this constructor, so no binding exists until an owner proves
    /// retry stability. The binding deliberately has no `Deserialize`
    /// implementation: it is minted, never parsed from untrusted input.
    #[allow(
        dead_code,
        reason = "owner seam: minted only by tool owners; none mint yet so resubmit stays omitted (#2899)"
    )]
    pub(crate) fn bind(
        operation_digest: &str,
        retry_identity: &str,
        effect_class: OperationEffectClass,
        durable_state_ref: &str,
        readback_ref: Option<&str>,
        approved_recovery: Vec<RecoveryAction>,
    ) -> Result<Self, OwnerBindingError> {
        for (field, value) in [
            ("operation_digest", operation_digest),
            ("retry_identity", retry_identity),
            ("durable_state_ref", durable_state_ref),
        ] {
            if value.trim().is_empty() {
                return Err(OwnerBindingError::BlankField(field));
            }
        }
        Ok(Self {
            operation_digest: operation_digest.to_owned(),
            retry_identity: retry_identity.to_owned(),
            effect_class,
            durable_state_ref: durable_state_ref.to_owned(),
            readback_ref: readback_ref.map(str::to_owned),
            approved_recovery,
        })
    }

    /// Whether the owner approved this recovery action for the operation.
    pub(crate) fn allows(&self, action: RecoveryAction) -> bool {
        self.approved_recovery.contains(&action)
    }
}

/// Canonical operation disposition, orthogonal to host completion.
///
/// Host completion never proves a canonical commit and a route fault never
/// erases a valid receipt: this disposition moves only on canonical evidence
/// (receipt plus exact readback), never on host/UI observations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CanonicalDisposition {
    /// The request performs no mutation.
    ReadOnly,
    /// The request failed before any mutating stage could execute.
    FailedBeforeStage,
    /// A mutation may have committed; reconciliation is still required.
    PossibleCommit,
    /// Committed with a current receipt plus independent exact readback.
    CommittedWithReadback,
    /// The operation provably rolled back; retry-stable replay may be lawful.
    RolledBack,
    /// Canonical outcome is unknown to the assessing path.
    Unknown,
}

impl CanonicalDisposition {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::FailedBeforeStage => "failed_before_stage",
            Self::PossibleCommit => "possible_commit",
            Self::CommittedWithReadback => "committed_with_readback",
            Self::RolledBack => "rolled_back",
            Self::Unknown => "unknown",
        }
    }

    /// Whether read-only status/reconciliation must precede any replay.
    pub(crate) const fn needs_reconciliation_first(&self) -> bool {
        matches!(self, Self::PossibleCommit | Self::Unknown)
    }

    /// Derives the disposition provable from facade evidence alone.
    ///
    /// Early rejection failed before any handler ran. A current canonical
    /// receipt without readback is a possible commit. Facade-owned protocol
    /// methods are known reads. Anything else stays unknown: the facade must
    /// not claim a tool call was read-only merely because it lacks a receipt.
    pub(crate) fn from_facade_evidence(
        method: &str,
        failed_before_handler: bool,
        commit: &CommitEvidence,
    ) -> Self {
        if failed_before_handler {
            return Self::FailedBeforeStage;
        }
        if commit.is_committed() {
            return Self::CommittedWithReadback;
        }
        if commit.canonical_receipt_write_id.is_some() {
            return Self::PossibleCommit;
        }
        if matches!(
            method,
            "initialize" | "ping" | "tools/list" | "prompts/list" | "prompts/get"
        ) {
            return Self::ReadOnly;
        }
        Self::Unknown
    }
}

/// Evidence gate for calling a candidate committed.
///
/// Committed requires both a current canonical receipt and an independent
/// exact readback. A UI-displayed identifier proves neither.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct CommitEvidence {
    /// Canonical receipt write id resolved independently of any UI, if any.
    pub(crate) canonical_receipt_write_id: Option<String>,
    /// Whether independent exact readback reproduced the committed record.
    pub(crate) exact_readback_match: Option<bool>,
}

impl CommitEvidence {
    /// True only with a current canonical receipt and exact readback.
    pub(crate) const fn is_committed(&self) -> bool {
        self.canonical_receipt_write_id.is_some() && matches!(self.exact_readback_match, Some(true))
    }
}

/// Explicit assessment state of one correlated invocation (issue #2899, item 6).
///
/// Pending, unavailable, gapped, unknown, and local-emission-failed states
/// are not degradation: they prescribe no fault recovery. Route-fault states
/// arise only from competent host evidence or an owner-recorded disconnect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CorrelationAssessmentState {
    /// ELIOT emitted exactly once; host observation is still pending.
    EmissionSucceededAwaitingHostObservation,
    /// Host evidence is unavailable or gapped; the outcome stays unknown.
    HostObservationUnavailableOrGapped,
    /// A competent host observation attested invocation completion.
    HostCompleted,
    /// The host surfaced an invocation error consistent with our envelope.
    HostReportedInvocationError,
    /// A complete observed interval passed the deadline with no host terminal.
    HostRespondingStuckAfterDeadline,
    /// The host errored on an envelope ELIOT provably completed successfully.
    ResponseMisclassifiedByHost,
    /// Transport outcome is unknown: coverage is indeterminate after emission.
    TransportOutcomeUnknown,
    /// An owner-recorded disconnect proves transport loss after flush.
    TransportLostAfterFlush,
    /// ELIOT-side emission failed; a local delivery defect, not a host fault.
    EliotEmissionFailed,
}

impl CorrelationAssessmentState {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::EmissionSucceededAwaitingHostObservation => {
                "emission_succeeded_awaiting_host_observation"
            }
            Self::HostObservationUnavailableOrGapped => "host_observation_unavailable_or_gapped",
            Self::HostCompleted => "host_completed",
            Self::HostReportedInvocationError => "host_reported_invocation_error",
            Self::HostRespondingStuckAfterDeadline => "host_responding_stuck_after_deadline",
            Self::ResponseMisclassifiedByHost => "response_misclassified_by_host",
            Self::TransportOutcomeUnknown => "transport_outcome_unknown",
            Self::TransportLostAfterFlush => "transport_lost_after_flush",
            Self::EliotEmissionFailed => "eliot_emission_failed",
        }
    }

    /// Whether the state is pending (neither completed nor a fault).
    pub(crate) const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::EmissionSucceededAwaitingHostObservation
                | Self::HostObservationUnavailableOrGapped
                | Self::TransportOutcomeUnknown
        )
    }

    /// Whether the state attests healthy host completion.
    pub(crate) const fn is_completed(self) -> bool {
        matches!(self, Self::HostCompleted)
    }
}

/// Typed degradation of the MCP route, derived only from competent evidence.
///
/// This reports route health only. It fabricates neither canonical failure
/// nor canonical success: the canonical operation outcome stays exactly what
/// the committing tool returned. There is deliberately no
/// "emitted-but-unobserved" code: a healthy emission with absent host
/// telemetry is pending coverage, not degradation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RouteDegradation {
    /// Machine-readable degradation class.
    pub(crate) code: RouteDegradationCode,
    /// Latest ELIOT-side stage actually reached.
    pub(crate) last_observed_stage: CorrelationStage,
    /// Human-readable detail bound to the correlation record, not a verdict.
    pub(crate) detail: String,
}

/// Machine-readable route degradation classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RouteDegradationCode {
    /// The host observed bytes but misclassified them (timeout/error/stale).
    ResponseMisclassifiedByHost,
    /// The transport was lost after flush; redelivery state is unknown.
    TransportLostAfterFlush,
    /// The host shows no terminal state past the deadline on complete coverage.
    HostRespondingStuckAfterDeadline,
}

impl RouteDegradationCode {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ResponseMisclassifiedByHost => "response_misclassified_by_host",
            Self::TransportLostAfterFlush => "transport_lost_after_flush",
            Self::HostRespondingStuckAfterDeadline => "host_responding_stuck_after_deadline",
        }
    }
}

/// Usable recovery directive accompanying a route assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RecoveryDirective {
    /// Ordered recovery actions; later actions apply if earlier ones fail.
    pub(crate) actions: Vec<RecoveryAction>,
    /// Which correlation evidence to attach when escalating.
    pub(crate) evidence_hint: String,
}

impl RecoveryDirective {
    /// Comma-joined stable action names for structured events.
    pub(crate) fn action_names(&self) -> String {
        self.actions
            .iter()
            .map(|action| action.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// One bounded recovery action that never invents canonical outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryAction {
    /// Restart the stdio route process and replay by operation identity.
    ReconnectStdioRoute,
    /// Refresh the Desktop view; ELIOT-side state is already terminal.
    RefreshDesktopView,
    /// Call a read-only status tool to re-observe canonical state.
    QueryStatusTool,
    /// Resubmit with the same owner-validated identity; never a fresh write id.
    ResubmitSameOperationIdentity,
    /// Escalate with the correlation record attached.
    EscalateWithCorrelationEvidence,
}

impl RecoveryAction {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ReconnectStdioRoute => "reconnect_stdio_route",
            Self::RefreshDesktopView => "refresh_desktop_view",
            Self::QueryStatusTool => "query_status_tool",
            Self::ResubmitSameOperationIdentity => "resubmit_same_operation_identity",
            Self::EscalateWithCorrelationEvidence => "escalate_with_correlation_evidence",
        }
    }
}

/// Evidence cited by one assessment revision.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AssessmentEvidence {
    /// Attesting host event evidence, when a host terminal was observed.
    pub(crate) host_event: Option<HostObservationEvidence>,
    /// Coverage proof the assessment relied on.
    pub(crate) coverage: Option<CoverageProof>,
    /// Owner-recorded transport edge kind, when one decided the assessment.
    pub(crate) transport_edge: Option<TransportEdgeKind>,
}

/// Inputs to one correlation assessment.
///
/// Every input is either ELIOT-observed, owner-proven, or explicitly absent.
/// Absent host evidence yields a pending state, never a fault.
pub(crate) struct AssessmentInputs<'a> {
    /// Immutable ELIOT-side emission observation.
    pub(crate) emission: &'a EliotEmissionObservation,
    /// Competent host terminal observation, or explicit partial-unknown.
    pub(crate) host: &'a HostTerminalObservation,
    /// Bounded observation window admitted by the event owner.
    pub(crate) window: &'a ObservationWindow,
    /// Owner-recorded transport edge for this invocation, when one exists.
    pub(crate) transport_edge: Option<TransportEdgeKind>,
    /// Owner-validated operation binding, when a tool owner minted one.
    pub(crate) operation_binding: Option<&'a OwnerValidatedOperationBinding>,
    /// Canonical operation disposition from canonical evidence only.
    pub(crate) canonical: &'a CanonicalDisposition,
    /// Whether the owner confirmed a stale UI while the host completed.
    pub(crate) ui_confirmed_stale: bool,
}

/// One derived route assessment: explicit state plus bounded recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Assessment {
    /// Explicit assessment state.
    pub(crate) state: CorrelationAssessmentState,
    /// Route degradation, present only for competent fault states.
    pub(crate) degradation: Option<RouteDegradation>,
    /// Recovery directive, present only when a lawful recovery exists.
    pub(crate) recovery: Option<RecoveryDirective>,
    /// Evidence the assessment relied on.
    pub(crate) evidence: AssessmentEvidence,
}

/// Derives the route assessment from observed cause plus operation disposition.
///
/// A provably flushed frame is a precondition, not a verdict: emission alone
/// never yields a degradation code or a recovery directive (issue #2899). A
/// record that never reached the pipe is a local fact and stays local — it
/// prescribes no host-facing route recovery. Among emissions that provably
/// reached the pipe, decision order is strongest-evidence-first: an explicit
/// host terminal, then an owner-recorded disconnect, then a complete interval
/// past deadline, then coverage-only pending states. Only those evidenced
/// states derive recovery. Misclassification requires a proven success
/// envelope: a host error against an error envelope (or an unobserved relayed
/// envelope) is consistent surfacing, not a route fault.
pub(crate) fn assess_correlation(inputs: &AssessmentInputs<'_>) -> Assessment {
    let emission = inputs.emission;
    let mut evidence = AssessmentEvidence {
        host_event: None,
        coverage: Some(inputs.window.coverage.clone()),
        transport_edge: inputs.transport_edge,
    };
    if !emission.emitted_exactly_once() {
        return Assessment {
            state: CorrelationAssessmentState::EliotEmissionFailed,
            degradation: None,
            recovery: None,
            evidence,
        };
    }
    if let HostTerminalObservation::Observed {
        state,
        evidence: host_evidence,
    } = inputs.host
    {
        evidence.host_event = Some(host_evidence.as_ref().clone());
        return match state {
            HostTerminalState::InvocationCompleted => {
                let state = CorrelationAssessmentState::HostCompleted;
                Assessment {
                    state,
                    degradation: None,
                    recovery: derive_recovery(
                        &emission.identity.identity_digest,
                        state,
                        inputs.operation_binding,
                        inputs.canonical,
                        inputs.ui_confirmed_stale,
                    ),
                    evidence,
                }
            }
            HostTerminalState::InvocationError => assess_host_error(inputs, evidence),
        };
    }
    if matches!(inputs.transport_edge, Some(TransportEdgeKind::Disconnect)) {
        let state = CorrelationAssessmentState::TransportLostAfterFlush;
        return Assessment {
            state,
            degradation: Some(degradation_for(
                emission,
                RouteDegradationCode::TransportLostAfterFlush,
            )),
            recovery: derive_recovery(
                &emission.identity.identity_digest,
                state,
                inputs.operation_binding,
                inputs.canonical,
                inputs.ui_confirmed_stale,
            ),
            evidence,
        };
    }
    if inputs.window.complete_interval_past_deadline() {
        let state = CorrelationAssessmentState::HostRespondingStuckAfterDeadline;
        return Assessment {
            state,
            degradation: Some(degradation_for(
                emission,
                RouteDegradationCode::HostRespondingStuckAfterDeadline,
            )),
            recovery: derive_recovery(
                &emission.identity.identity_digest,
                state,
                inputs.operation_binding,
                inputs.canonical,
                inputs.ui_confirmed_stale,
            ),
            evidence,
        };
    }
    let state = match inputs.window.coverage {
        CoverageProof::CursorGap { .. } => {
            CorrelationAssessmentState::HostObservationUnavailableOrGapped
        }
        CoverageProof::Indeterminate { .. } => CorrelationAssessmentState::TransportOutcomeUnknown,
        CoverageProof::NoEventYet | CoverageProof::CompleteInterval { .. } => {
            CorrelationAssessmentState::EmissionSucceededAwaitingHostObservation
        }
    };
    Assessment {
        state,
        degradation: None,
        recovery: None,
        evidence,
    }
}

/// Assesses a host-reported invocation error against the emitted envelope.
///
/// A host error on an envelope ELIOT provably completed successfully is
/// misclassification. A host error on an error envelope — or on a relayed
/// envelope this path never observed — is consistent surfacing: no route
/// degradation and no route recovery.
fn assess_host_error(inputs: &AssessmentInputs<'_>, evidence: AssessmentEvidence) -> Assessment {
    let emission = inputs.emission;
    if emission.handler_outcome.is_success() {
        let state = CorrelationAssessmentState::ResponseMisclassifiedByHost;
        Assessment {
            state,
            degradation: Some(degradation_for(
                emission,
                RouteDegradationCode::ResponseMisclassifiedByHost,
            )),
            recovery: derive_recovery(
                &emission.identity.identity_digest,
                state,
                inputs.operation_binding,
                inputs.canonical,
                inputs.ui_confirmed_stale,
            ),
            evidence,
        }
    } else {
        Assessment {
            state: CorrelationAssessmentState::HostReportedInvocationError,
            degradation: None,
            recovery: None,
            evidence,
        }
    }
}

/// Builds the degradation record for a competent fault state.
///
/// Called only with fault codes proven by host evidence; there is no
/// emitted-but-unobserved code to construct.
fn degradation_for(
    emission: &EliotEmissionObservation,
    code: RouteDegradationCode,
) -> RouteDegradation {
    RouteDegradation {
        code,
        last_observed_stage: emission.stage,
        detail: format!(
            "request {} code {} stage {}",
            emission.identity.mcp_request_id,
            code.as_str(),
            emission.stage.as_str(),
        ),
    }
}

/// Derives typed, bounded recovery from state plus dispositions.
///
/// Recovery order is per-cause, never a common list: healthy completion
/// recovers nothing; pending states recover nothing; a directly observed local
/// emission failure is a local fact and recovers nothing host-facing; possible
/// or unknown canonical outcomes reconcile read-only first; same-operation
/// replay appears only from an owner-validated binding whose approved options
/// include resubmission in a lawful retry state. Every evidenced route-fault
/// recovery terminates in bounded escalation with the correlation record
/// attached.
pub(crate) fn derive_recovery(
    identity_digest: &str,
    state: CorrelationAssessmentState,
    operation_binding: Option<&OwnerValidatedOperationBinding>,
    canonical: &CanonicalDisposition,
    ui_confirmed_stale: bool,
) -> Option<RecoveryDirective> {
    let resubmit_allowed = operation_binding
        .is_some_and(|binding| binding.allows(RecoveryAction::ResubmitSameOperationIdentity));
    let mut actions = match state {
        CorrelationAssessmentState::HostCompleted => {
            if ui_confirmed_stale {
                vec![RecoveryAction::RefreshDesktopView]
            } else {
                return None;
            }
        }
        CorrelationAssessmentState::HostReportedInvocationError
        | CorrelationAssessmentState::EmissionSucceededAwaitingHostObservation
        | CorrelationAssessmentState::HostObservationUnavailableOrGapped
        | CorrelationAssessmentState::TransportOutcomeUnknown
        | CorrelationAssessmentState::EliotEmissionFailed => return None,
        CorrelationAssessmentState::ResponseMisclassifiedByHost => {
            misclassified_recovery(canonical, resubmit_allowed)
        }
        CorrelationAssessmentState::TransportLostAfterFlush => {
            let mut actions = vec![RecoveryAction::ReconnectStdioRoute];
            if matches!(canonical, CanonicalDisposition::RolledBack) && resubmit_allowed {
                actions.push(RecoveryAction::ResubmitSameOperationIdentity);
            } else if canonical.needs_reconciliation_first() {
                actions.push(RecoveryAction::QueryStatusTool);
            }
            actions
        }
        CorrelationAssessmentState::HostRespondingStuckAfterDeadline => {
            let mut actions = Vec::new();
            if canonical.needs_reconciliation_first() {
                actions.push(RecoveryAction::QueryStatusTool);
            }
            actions.push(RecoveryAction::RefreshDesktopView);
            actions
        }
    };
    // Every arm above is an evidenced fault state or a stale completion: each
    // terminates in bounded escalation, so a proven fault never prescribes
    // nothing. A pending state and a local emission failure reach no arm and
    // recover nothing.
    actions.push(RecoveryAction::EscalateWithCorrelationEvidence);
    Some(RecoveryDirective {
        actions,
        evidence_hint: format!("attach {CORRELATION_SCHEMA_ID} record {identity_digest}"),
    })
}

/// Recovery for a host error on a proven success envelope.
fn misclassified_recovery(
    canonical: &CanonicalDisposition,
    resubmit_allowed: bool,
) -> Vec<RecoveryAction> {
    if matches!(canonical, CanonicalDisposition::RolledBack) && resubmit_allowed {
        vec![RecoveryAction::ResubmitSameOperationIdentity]
    } else if canonical.needs_reconciliation_first() {
        vec![RecoveryAction::QueryStatusTool]
    } else {
        Vec::new()
    }
}

/// One append-only assessment revision under a logical correlation.
///
/// The immediate emission observation stays immutable; a later host
/// completion or fault appends a linked revision under the same identity
/// digest. Revisions never rewrite history and never leave a false
/// degradation current beside a healthy completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AssessmentRevision {
    /// Identity digest of the logical correlation this revises.
    pub(crate) identity_digest: String,
    /// Monotonic revision number, assigned at append.
    pub(crate) revision: u32,
    /// Previous revision number this supersedes, when one exists.
    pub(crate) supersedes: Option<u32>,
    /// Derived assessment carried by this revision.
    pub(crate) assessment: Assessment,
}

/// Bounded append-only log of assessment revisions for one invocation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AssessmentLog {
    /// Identity digest every revision must share, once set.
    identity_digest: Option<String>,
    /// Revisions in append order.
    revisions: Vec<AssessmentRevision>,
}

/// Why an assessment revision append was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AssessmentLogError {
    /// The revision belongs to a different logical correlation.
    IdentityMismatch,
    /// The bounded log is full.
    LogFull,
}

impl std::fmt::Display for AssessmentLogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityMismatch => {
                formatter.write_str("assessment revision identity does not match the log")
            }
            Self::LogFull => formatter.write_str("assessment revision log is full"),
        }
    }
}

impl std::error::Error for AssessmentLogError {}

impl AssessmentLog {
    /// Appends one assessment, assigning its revision number. Fails closed.
    ///
    /// Rejects revisions for a different identity digest and refuses to grow
    /// past [`MAX_ASSESSMENT_REVISIONS`]; existing revisions are never
    /// mutated or removed.
    pub(crate) fn append(
        &mut self,
        identity_digest: &str,
        assessment: Assessment,
    ) -> Result<&AssessmentRevision, AssessmentLogError> {
        if let Some(held) = &self.identity_digest
            && held != identity_digest
        {
            return Err(AssessmentLogError::IdentityMismatch);
        }
        if self.revisions.len() >= MAX_ASSESSMENT_REVISIONS {
            return Err(AssessmentLogError::LogFull);
        }
        let revision =
            u32::try_from(self.revisions.len()).map_err(|_| AssessmentLogError::LogFull)?;
        let supersedes = revision.checked_sub(1);
        self.identity_digest = Some(identity_digest.to_owned());
        self.revisions.push(AssessmentRevision {
            identity_digest: identity_digest.to_owned(),
            revision,
            supersedes,
            assessment,
        });
        self.revisions.last().ok_or(AssessmentLogError::LogFull)
    }

    /// Revisions in append order.
    pub(crate) fn revisions(&self) -> &[AssessmentRevision] {
        &self.revisions
    }

    /// Host evidence this correlation has already accepted, read back from its
    /// own retained revision chain.
    ///
    /// This is the correlation's own record, never a caller assertion: the
    /// bridge join compares a later host event against the evidence recorded
    /// here, so a caller cannot present an empty expected set and have a
    /// correlation close once per event.
    pub(crate) fn latest_host_evidence(&self) -> Option<&HostObservationEvidence> {
        self.revisions
            .iter()
            .rev()
            .find_map(|revision| revision.assessment.evidence.host_event.as_ref())
    }

    /// Latest revision, when one exists.
    pub(crate) fn latest(&self) -> Option<&AssessmentRevision> {
        self.revisions.last()
    }
}

/// Bounded pending/completed/degraded counts plus missing evidence.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AssessmentSummary {
    /// Revisions in a pending state.
    pub(crate) pending: u32,
    /// Revisions attesting healthy host completion.
    pub(crate) completed: u32,
    /// Revisions in a fault state.
    pub(crate) degraded: u32,
    /// Bounded exact-missing-evidence tags across the revisions.
    pub(crate) missing_evidence: Vec<String>,
}

impl AssessmentSummary {
    /// Summarizes caller-held revisions without prescribing fault recovery.
    pub(crate) fn summarize(revisions: &[AssessmentRevision]) -> Self {
        let mut summary = Self::default();
        for revision in revisions {
            let state = revision.assessment.state;
            if state.is_pending() {
                summary.pending += 1;
            } else if state.is_completed() {
                summary.completed += 1;
            } else {
                summary.degraded += 1;
            }
            for tag in missing_evidence_tags(revision) {
                if summary.missing_evidence.len() >= MAX_SUMMARY_EVIDENCE {
                    break;
                }
                if !summary.missing_evidence.contains(&tag) {
                    summary.missing_evidence.push(tag);
                }
            }
        }
        summary
    }
}

/// Exact missing evidence for one revision, as stable identifier tags.
fn missing_evidence_tags(revision: &AssessmentRevision) -> Vec<String> {
    let state = revision.assessment.state.as_str().to_owned();
    match revision.assessment.state {
        CorrelationAssessmentState::EmissionSucceededAwaitingHostObservation => {
            vec![format!("{state}:host_terminal_event")]
        }
        CorrelationAssessmentState::HostObservationUnavailableOrGapped => {
            vec![format!("{state}:contiguous_host_interval")]
        }
        CorrelationAssessmentState::TransportOutcomeUnknown => {
            let cause =
                revision
                    .assessment
                    .evidence
                    .coverage
                    .as_ref()
                    .map_or("unknown", |coverage| match coverage {
                        CoverageProof::Indeterminate { cause } => cause.as_str(),
                        CoverageProof::NoEventYet
                        | CoverageProof::CursorGap { .. }
                        | CoverageProof::CompleteInterval { .. } => coverage.as_str(),
                    });
            vec![format!("{state}:coverage_denominator:{cause}")]
        }
        CorrelationAssessmentState::HostCompleted
        | CorrelationAssessmentState::HostReportedInvocationError
        | CorrelationAssessmentState::HostRespondingStuckAfterDeadline
        | CorrelationAssessmentState::ResponseMisclassifiedByHost
        | CorrelationAssessmentState::TransportLostAfterFlush
        | CorrelationAssessmentState::EliotEmissionFailed => Vec::new(),
    }
}
