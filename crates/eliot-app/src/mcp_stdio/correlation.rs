//! ELIOT-side stdio boundary for one MCP invocation (#2899).
//!
//! This is the producer half of the correlation and it owns exactly the facts
//! the stdio boundary can measure for itself: the JSON-RPC request identity,
//! the method and tool, the receive/handler/frame/emission stages, the exact
//! byte and flush receipt, and the typed handler outcome. It then freezes those
//! into the owner's immutable [`EliotEmissionObservation`] and emits it.
//!
//! Three things this module deliberately does NOT do, each because the issue
//! is precisely about getting them wrong:
//!
//! 1. It never classifies a healthy emission as route degradation. A
//!    successful emission yields the pending state
//!    [`CorrelationAssessmentState::EmissionSucceededAwaitingHostObservation`]
//!    with no degradation code and no recovery directive.
//! 2. It never derives a host terminal state. Host/UI state is outside this
//!    process; the record carries the explicit `PartialUnknown` coverage
//!    denominator instead, and only a later admitted host event can resolve
//!    the correlation.
//! 3. It never authorizes resubmission from caller text. `write_id` and
//!    `idempotency_key` are preserved as untrusted diagnostic hints only; retry
//!    authority requires an owner-minted [`OwnerValidatedOperationBinding`].
//!
//! The vocabulary and the host-event join live in the event owner
//! (`eliot_agent_bridge_core`), which is the only holder of the live journal a
//! later host event can be joined against. This module produces the immutable
//! observation that join consumes; it holds no correlation table of its own,
//! because a correlation that existed only in this process could never be
//! joined by a later event.

use anyhow::Context as _;
use eliot_agent_bridge_core::{
    AssessmentInputs, CorrelationIdentity, CorrelationIdentityParts, CorrelationStage,
    EliotEmissionObservation, EmissionCause, HandlerOutcome, HostTerminalObservation,
    ObservationWindow, OperationIdentity, OwnerValidatedOperationBinding, StdioEmissionReceipt,
    assess_correlation,
};
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

/// Schema identity of the structured record this boundary emits.
pub const CORRELATION_SCHEMA_ID: &str = eliot_agent_bridge_core::CORRELATION_SCHEMA_ID;

/// Version of the logical correlation identity bound into every record.
pub const CORRELATION_IDENTITY_VERSION: u32 = eliot_agent_bridge_core::CORRELATION_IDENTITY_VERSION;

/// Fails closed when the emission did not provably reach the pipe.
///
/// Callers propagate the error exactly as the previous bare `?` on
/// `write_all`/`flush` did; the receipt only adds the typed stage.
#[must_use]
pub fn emission_into_result(
    receipt: StdioEmissionReceipt,
    mcp_request_id: &str,
) -> anyhow::Result<usize> {
    if receipt.flushed && matches!(receipt.cause, EmissionCause::Emitted) {
        Ok(receipt.bytes)
    } else {
        let cause = receipt.cause.as_str();
        let bytes = receipt.bytes;
        let flushed = receipt.flushed;
        anyhow::bail!(
            "STDIO_EMISSION_FAILED: request_id={mcp_request_id} cause={cause} bytes={bytes} flushed={flushed}"
        )
    }
}

/// Writes one already-framed response to stdout and captures the disposition.
///
/// The frame must include its trailing newline. The outcome is reported as a
/// receipt instead of `Result` so the caller always observes the exact stage,
/// then fails closed through [`emission_into_result`].
#[must_use]
pub fn emit_stdout_frame(frame: &[u8]) -> StdioEmissionReceipt {
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
pub fn check_response_correlation(
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
pub struct McpInvocationCorrelation {
    /// Schema identity of this record.
    pub schema: &'static str,
    /// Stringified JSON-RPC request id.
    pub mcp_request_id: String,
    /// JSON-RPC method name.
    pub method: String,
    /// Tool name for `tools/call`, when present.
    pub tool_name: Option<String>,
    /// Untrusted operation identity hints carried by the call arguments.
    pub operation: OperationIdentity,
    /// Owner-validated operation binding, when a tool owner minted one.
    pub operation_binding: Option<OwnerValidatedOperationBinding>,
    /// Authenticated session that served the request, when known.
    pub session_id: Option<String>,
    /// Integration/host access profile that served the request, when observed.
    pub route_profile: Option<String>,
    /// Runtime instance identity, when observed.
    pub route_runtime_id: Option<String>,
    /// Authority generation of the serving route/process, when observed.
    pub route_auth_generation: Option<String>,
    /// Time the request line was received.
    pub received_at: OffsetDateTime,
    /// Latest observed ELIOT-side stage.
    pub stage: CorrelationStage,
    /// Typed handler outcome observed on this path.
    pub handler_outcome: HandlerOutcome,
    /// Whether the request was rejected before any handler ran.
    pub failed_before_handler: bool,
    /// JSON-RPC error code of the produced envelope, when it is an error.
    pub error_code: Option<i64>,
    /// Canonical receipt write id observed in the result, when present.
    pub receipt_write_id: Option<String>,
    /// Owner-issued canonical receipt id observed in the result, when present.
    pub receipt_id: Option<String>,
    /// Exact framed response bytes, once framed.
    pub response_bytes: Option<usize>,
    /// Stdout emission disposition, once emitted or failed.
    pub emission: Option<StdioEmissionReceipt>,
    /// Append-only assessment revisions for this invocation.
    pub assessments: eliot_agent_bridge_core::AssessmentLog,
}

impl McpInvocationCorrelation {
    /// Binds a received request envelope to its correlation carriers.
    #[must_use]
    pub fn receive(request: &Value, method: &str) -> Self {
        let params = request.get("params").unwrap_or(&Value::Null);
        let operation = if method == "tools/call" {
            let arguments = params.get("arguments").unwrap_or(&Value::Null);
            OperationIdentity::from_hints(
                arguments
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                arguments
                    .get("write_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )
        } else {
            OperationIdentity::default()
        };
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
            operation,
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
            receipt_id: None,
            response_bytes: None,
            emission: None,
            assessments: eliot_agent_bridge_core::AssessmentLog::default(),
        }
    }

    /// Records the authenticated session that served this invocation.
    pub fn observe_session(&mut self, session_id: &str) {
        self.session_id = Some(session_id.to_owned());
    }

    /// Records the serving route context for the correlation identity.
    ///
    /// The profile names the integration/host access path; the runtime id and
    /// authority generation pin the exact serving route/process generation so
    /// a later host observation can prove it belongs to this invocation.
    pub fn observe_route_context(
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
    pub fn observe_owner_operation_binding(&mut self, binding: OwnerValidatedOperationBinding) {
        self.operation_binding = Some(binding);
    }

    /// Records handler completion and extracts receipt correlation, if any.
    ///
    /// Reads only the stable receipt carrier the canonical write owner emits in
    /// the tool result — `structuredContent.write_receipt`, the
    /// owner-issued `{receipt_id, write_id}` reference — and records both
    /// handles verbatim. Other results leave it absent, which is itself the
    /// honest record for read-only invocations. Nothing here is caller text: a
    /// caller-supplied `write_id` hint never reaches this path, so the
    /// owner-issued handle in the record can only have come from the canonical
    /// owner that admitted the operation.
    pub fn observe_handler_result(&mut self, result: &Result<Value, anyhow::Error>) {
        self.stage = CorrelationStage::HandlerCompleted;
        if let Ok(value) = result {
            self.handler_outcome = HandlerOutcome::CompletedOk;
            let receipt = value.pointer("/structuredContent/write_receipt");
            self.receipt_id = receipt
                .and_then(|receipt| receipt.get("receipt_id"))
                .and_then(receipt_text);
            self.receipt_write_id = receipt
                .and_then(|receipt| receipt.get("write_id"))
                .and_then(receipt_text);
        } else {
            self.handler_outcome = HandlerOutcome::InternalFailure;
            self.error_code = Some(-32603);
        }
    }

    /// Records a typed handler error code for early-rejection envelopes.
    ///
    /// Early rejection runs before any tool handler, so the invocation failed
    /// before any mutating stage could execute.
    pub fn observe_error_code(&mut self, code: i64) {
        self.stage = CorrelationStage::HandlerCompleted;
        self.handler_outcome = HandlerOutcome::JsonRpcError { code };
        self.failed_before_handler = true;
        self.error_code = Some(code);
    }

    /// Records response framing.
    pub fn observe_framed(&mut self, bytes: usize) {
        self.stage = CorrelationStage::Framed;
        self.response_bytes = Some(bytes);
    }

    /// Records stdout emission disposition.
    pub fn observe_emission(&mut self, receipt: &StdioEmissionReceipt) {
        self.stage = if receipt.flushed && matches!(receipt.cause, EmissionCause::Emitted) {
            CorrelationStage::Emitted
        } else {
            CorrelationStage::EmissionFailed
        };
        self.emission = Some(*receipt);
    }

    /// Whether ELIOT provably wrote and flushed exactly one response frame.
    #[must_use]
    pub const fn emitted_exactly_once(&self) -> bool {
        matches!(self.stage, CorrelationStage::Emitted)
    }

    /// Assembles the versioned logical identity for this invocation.
    #[must_use]
    pub fn identity(&self) -> CorrelationIdentity {
        CorrelationIdentity::assemble(&CorrelationIdentityParts {
            mcp_request_id: self.mcp_request_id.clone(),
            method: self.method.clone(),
            tool_name: self.tool_name.clone(),
            host_profile: self.route_profile.clone(),
            session_id: self.session_id.clone(),
            runtime_id: self.route_runtime_id.clone(),
            auth_generation: self.route_auth_generation.clone(),
            operation_binding: self.operation_binding.clone(),
        })
    }

    /// Freezes this boundary's observations into the immutable record a later
    /// host event is joined against.
    #[must_use]
    pub fn emission_observation(&self) -> EliotEmissionObservation {
        EliotEmissionObservation::observe(
            self.identity(),
            self.stage,
            self.handler_outcome,
            self.response_bytes,
            self.emission,
        )
    }

    /// Derives the canonical disposition provable from facade evidence alone.
    ///
    /// The facade owns its protocol-method handlers (known reads) and observes
    /// early rejection (failed before any handler) and canonical receipt
    /// carriers. It never observes exact readback, so committed-with-readback
    /// and rolled-back dispositions stay with the canonical owner.
    #[must_use]
    pub fn facade_canonical_disposition(&self) -> eliot_agent_bridge_core::CanonicalDisposition {
        let commit = eliot_agent_bridge_core::CommitEvidence {
            canonical_receipt_write_id: self.receipt_write_id.clone(),
            exact_readback_match: None,
        };
        eliot_agent_bridge_core::CanonicalDisposition::from_facade_evidence(
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
    pub fn emit(&mut self) {
        let observation = self.emission_observation();
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
            // This boundary cannot confirm a stale Desktop UI: it never reads
            // one. Asserting it here would offer refresh-the-UI on evidence
            // this process does not have, so it stays false and the recovery
            // stays withheld (issue #2899 W10.3).
            ui_confirmed_stale: false,
        };
        let assessment = assess_correlation(&inputs);
        let digest = observation.identity.identity_digest.clone();
        if self.assessments.append(&digest, assessment).is_err() {
            return;
        }
        let summary = eliot_agent_bridge_core::AssessmentSummary::summarize(&self.assessments);
        let missing: Vec<&str> = summary
            .missing_evidence
            .iter()
            .map(String::as_str)
            .collect();
        // Read the correlation's CURRENT assessment, not every revision it ever
        // held (#2899 W9.3): a degradation superseded by a later healthy
        // completion stays in the chain as history but must never be reported as
        // the current one. `supersedes_earlier` is the positive evidence that
        // this correlation was re-assessed.
        let Some(current) = self.assessments.current() else {
            return;
        };
        let latest = current.revision;
        let assessment_state = current.state().as_str();
        let assessment_revision = latest.revision;
        let host_terminal_state = match host {
            HostTerminalObservation::Observed { state, .. } => state.as_str(),
            HostTerminalObservation::PartialUnknown(_) => "",
        };
        let coverage_proof = window.coverage.as_str();
        let route_degradation = current
            .degradation()
            .map_or("", |degradation| degradation.code.as_str());
        let recovery_actions = latest.assessment.recovery.as_ref().map_or_else(
            String::new,
            eliot_agent_bridge_core::mcp_correlation::RecoveryDirective::action_names,
        );
        let superseded_codes = summary
            .superseded_degradation_codes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        tracing::info!(
            schema = self.schema,
            mcp_request_id = %self.mcp_request_id,
            identity_digest = %digest,
            identity_version = CORRELATION_IDENTITY_VERSION,
            method = %self.method,
            tool_name = self.tool_name.as_deref().unwrap_or(""),
            operation_present = !self.operation.is_empty(),
            idempotency_key_present = self.operation.idempotency_key.is_some(),
            // #2899 item 12: the caller hint is UNVALIDATED text read straight
            // out of `params.arguments`, so only its presence is recorded. The
            // value itself stays out of the record, exactly as the owner-side
            // producer already records `operation_hint_present` and
            // `idempotency_key_present` without the values.
            operation_write_id_present = self.operation.write_id.is_some(),
            owner_operation_bound = self.operation_binding.is_some(),
            receipt_write_id = self.receipt_write_id.as_deref().unwrap_or(""),
            owner_receipt_id = self.receipt_id.as_deref().unwrap_or(""),
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
            assessment_supersedes_earlier = current.supersedes_earlier,
            route_degradation = route_degradation,
            recovery_actions = %recovery_actions,
            recovery_canonical_rule = latest
                .assessment
                .recovery
                .as_ref()
                .map_or("", |recovery| recovery.canonical_rule.as_str()),
            pending_count = summary.pending,
            completed_count = summary.completed,
            degraded_count = summary.degraded,
            superseded_degradation_count = summary.superseded_degradations,
            superseded_degradation_codes = ?superseded_codes,
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

/// Reads one owner-issued receipt handle, preserving the owner's own JSON form.
fn receipt_text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| serde_json::to_string(value).ok())
}
