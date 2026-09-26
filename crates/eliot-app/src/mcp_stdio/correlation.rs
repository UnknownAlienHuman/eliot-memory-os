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
//! Carriers only: nothing here changes wire payloads, canonical write
//! semantics, finish semantics, or host UI expectations. Structured events
//! carry identifiers, stages, byte counts, and outcome classes; they never
//! carry tool payloads, host secrets, or private conversation content, per
//! `docs/integrations/claude/CLAUDE_INTEGRATION_SECURITY.md`.

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

/// Stable schema identity for ELIOT-side MCP invocation correlation records.
pub(crate) const CORRELATION_SCHEMA_ID: &str = "eliot.mcp-stdio-correlation.v1";

/// Identity of the idempotent operation a `tools/call` request carries, if any.
///
/// Extracted read-only from call arguments (`write_id`, `idempotency_key`).
/// The MCP request id is transport correlation; this is operation correlation.
/// The two are bound here and must never be conflated with host/UI state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct OperationIdentity {
    /// Caller-supplied retry-stable idempotency key, when the tool defines one.
    pub(crate) idempotency_key: Option<String>,
    /// Caller-supplied retry-stable write id, when the tool defines one.
    pub(crate) write_id: Option<String>,
}

impl OperationIdentity {
    /// Extracts operation identity from `tools/call` params without validation.
    ///
    /// Validation stays with the owning tool handler; this only preserves the
    /// correlation carrier so a later stage can bind request to operation.
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

    /// Whether the call carried any operation identity at all.
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
    /// Operation identity carried by the call arguments, if any.
    pub(crate) operation: OperationIdentity,
    /// Authenticated session that served the request, when known.
    pub(crate) session_id: Option<String>,
    /// Time the request line was received.
    pub(crate) received_at: OffsetDateTime,
    /// Latest observed ELIOT-side stage.
    pub(crate) stage: CorrelationStage,
    /// JSON-RPC error code of the produced envelope, when it is an error.
    pub(crate) error_code: Option<i64>,
    /// Canonical receipt write id observed in the result, when present.
    pub(crate) receipt_write_id: Option<String>,
    /// Exact framed response bytes, once framed.
    pub(crate) response_bytes: Option<usize>,
    /// Stdout emission disposition, once emitted or failed.
    pub(crate) emission: Option<StdioEmissionReceipt>,
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
            session_id: None,
            received_at: OffsetDateTime::now_utc(),
            stage: CorrelationStage::Received,
            error_code: None,
            receipt_write_id: None,
            response_bytes: None,
            emission: None,
        }
    }

    /// Records the authenticated session that served this invocation.
    pub(crate) fn observe_session(&mut self, session_id: &str) {
        self.session_id = Some(session_id.to_owned());
    }

    /// Records handler completion and extracts receipt correlation, if any.
    ///
    /// Reads only the stable receipt carrier (`result.write_receipt.write_id`)
    /// emitted by committing tools; other results leave it absent, which is
    /// itself the honest record for read-only invocations.
    pub(crate) fn observe_handler_result(&mut self, result: &Result<Value, anyhow::Error>) {
        self.stage = CorrelationStage::HandlerCompleted;
        match result {
            Ok(value) => {
                self.receipt_write_id = value
                    .get("write_receipt")
                    .and_then(|receipt| receipt.get("write_id"))
                    .and_then(|write_id| {
                        write_id
                            .as_str()
                            .map(str::to_owned)
                            .or_else(|| serde_json::to_string(write_id).ok())
                    });
            }
            Err(_) => {
                self.error_code = Some(-32603);
            }
        }
    }

    /// Records a typed handler error code for early-rejection envelopes.
    pub(crate) fn observe_error_code(&mut self, code: i64) {
        self.stage = CorrelationStage::HandlerCompleted;
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

    /// Emits one structured correlation event for TEST-PHASE evidence capture.
    ///
    /// Fields are identifiers, stages, counts, and outcome classes only.
    /// Request/response payloads are never logged. Every event honestly
    /// declares its host/UI coverage ceiling: ELIOT-side stages are observed,
    /// host/UI terminal state stays `partial_unknown` until a live run
    /// observes it out of band. When ELIOT provably emitted exactly once, the
    /// event also carries the typed route degradation and recovery directive
    /// so a stuck host indicator can be triaged without inventing canonical
    /// outcome; otherwise those fields stay empty.
    pub(crate) fn emit(&self) {
        let coverage = PartialObservation::stdio_boundary();
        let gaps: Vec<&str> = coverage.missing.iter().map(|gap| gap.as_str()).collect();
        let route = RouteDegradation::emitted_but_unobserved(self);
        let recovery_actions = route.as_ref().map_or_else(String::new, |(_, directive)| {
            directive
                .actions
                .iter()
                .map(|action| action.as_str())
                .collect::<Vec<_>>()
                .join(",")
        });
        tracing::info!(
            schema = self.schema,
            mcp_request_id = %self.mcp_request_id,
            method = %self.method,
            tool_name = self.tool_name.as_deref().unwrap_or(""),
            operation_present = !self.operation.is_empty(),
            idempotency_key_present = self.operation.idempotency_key.is_some(),
            operation_write_id = self.operation.write_id.as_deref().unwrap_or(""),
            receipt_write_id = self.receipt_write_id.as_deref().unwrap_or(""),
            session_id = self.session_id.as_deref().unwrap_or(""),
            received_at = %self.received_at,
            stage = self.stage.as_str(),
            error_code = self.error_code.unwrap_or(0),
            response_bytes = self.response_bytes.unwrap_or(0),
            emission_cause = self.emission.map_or("", |receipt| receipt.cause.as_str()),
            emitted_exactly_once = self.emitted_exactly_once(),
            route_degradation =
                route.as_ref().map_or("", |(degradation, _)| degradation.code.as_str()),
            route_degradation_detail =
                route.as_ref().map_or("", |(degradation, _)| degradation.detail.as_str()),
            recovery_actions = %recovery_actions,
            recovery_evidence_hint =
                route.as_ref().map_or("", |(_, directive)| directive.evidence_hint.as_str()),
            host_observation = "partial_unknown",
            coverage_gaps = ?gaps,
            coverage_note = %coverage.coverage_note,
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

/// Host/UI terminal state that ELIOT cannot observe from inside the facade.
///
/// Desktop bridge completion and the visible responding indicator live outside
/// ELIOT's process. Missing host/UI observability is `PARTIAL/UNKNOWN`, never
/// inferred success or failure.
#[allow(
    dead_code,
    reason = "TEST-PHASE hook: constructed from out-of-band live-run evidence (#7)"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostTerminalObservation {
    /// A TEST-PHASE run observed the host/UI terminal state out of band.
    Observed {
        /// What the host visibly reached.
        state: HostTerminalState,
        /// Which evidence source attests the observation (run artifact, not prose).
        evidence_ref: String,
    },
    /// Host/UI terminal state is not observable from this boundary.
    PartialUnknown(PartialObservation),
}

/// Visible terminal states a host invocation can reach.
#[allow(
    dead_code,
    reason = "TEST-PHASE hook: constructed from out-of-band live-run evidence (#7)"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostTerminalState {
    /// The host completed the invocation and cleared the responding indicator.
    InvocationCompleted,
    /// The host surfaced an invocation error.
    InvocationError,
    /// The host still shows a responding indicator after ELIOT emission.
    RespondingStuck,
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

/// Typed degradation of the MCP route when ELIOT provably emitted a valid
/// response but host completion is unobserved or misclassified.
///
/// This reports route health only. It fabricates neither canonical failure
/// nor canonical success: the canonical operation outcome stays exactly what
/// the committing tool returned.
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
    /// ELIOT wrote and flushed a valid frame; host completion unobserved.
    EmittedButHostCompletionUnobserved,
    /// The host observed bytes but misclassified them (timeout/error/stale).
    #[allow(
        dead_code,
        reason = "TEST-PHASE vocabulary: classified only from out-of-band live-run host evidence (#7)"
    )]
    ResponseMisclassifiedByHost,
    /// The transport was lost after flush; redelivery state is unknown.
    #[allow(
        dead_code,
        reason = "TEST-PHASE vocabulary: classified only from out-of-band live-run host evidence (#7)"
    )]
    TransportLostAfterFlush,
}

impl RouteDegradationCode {
    /// Stable wire name for structured events.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::EmittedButHostCompletionUnobserved => "emitted_but_host_completion_unobserved",
            Self::ResponseMisclassifiedByHost => "response_misclassified_by_host",
            Self::TransportLostAfterFlush => "transport_lost_after_flush",
        }
    }
}

/// Usable recovery directive accompanying a route degradation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RecoveryDirective {
    /// Ordered recovery actions; later actions apply if earlier ones fail.
    pub(crate) actions: Vec<RecoveryAction>,
    /// Which correlation evidence to attach when escalating.
    pub(crate) evidence_hint: String,
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
    /// Resubmit with the same idempotency identity; never a fresh write id.
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

impl RouteDegradation {
    /// Builds the degradation for an emitted-but-unobserved response.
    ///
    /// Requires the ELIOT-side record to show exactly-once emission; anything
    /// else is an ELIOT delivery defect, not a host-route degradation. Called
    /// from [`McpInvocationCorrelation::emit`], which surfaces the record as
    /// structured event fields; this constructor stays a pure builder so one
    /// invocation produces one correlation event.
    pub(crate) fn emitted_but_unobserved(
        correlation: &McpInvocationCorrelation,
    ) -> Option<(Self, RecoveryDirective)> {
        if !correlation.emitted_exactly_once() {
            return None;
        }
        let degradation = Self {
            code: RouteDegradationCode::EmittedButHostCompletionUnobserved,
            last_observed_stage: correlation.stage,
            detail: format!(
                "request {} tool {} emitted {} bytes and flushed; host completion unobserved",
                correlation.mcp_request_id,
                correlation.tool_name.as_deref().unwrap_or("-"),
                correlation.response_bytes.unwrap_or(0),
            ),
        };
        let mut actions = vec![
            RecoveryAction::QueryStatusTool,
            RecoveryAction::RefreshDesktopView,
            RecoveryAction::ReconnectStdioRoute,
        ];
        if !correlation.operation.is_empty() {
            actions.push(RecoveryAction::ResubmitSameOperationIdentity);
        }
        actions.push(RecoveryAction::EscalateWithCorrelationEvidence);
        let directive = RecoveryDirective {
            actions,
            evidence_hint: format!(
                "attach {} record for request {}",
                CORRELATION_SCHEMA_ID, correlation.mcp_request_id
            ),
        };
        Some((degradation, directive))
    }
}

/// Evidence gate for calling a candidate committed (acceptance A3).
///
/// Committed requires both a current canonical receipt and an independent
/// exact readback. A UI-displayed identifier proves neither.
#[allow(
    dead_code,
    reason = "TEST-PHASE hook: evaluated from live-run receipt/readback evidence (#7)"
)]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct CommitEvidence {
    /// Canonical receipt write id resolved independently of any UI, if any.
    pub(crate) canonical_receipt_write_id: Option<String>,
    /// Whether independent exact readback reproduced the committed record.
    pub(crate) exact_readback_match: Option<bool>,
}

#[allow(
    dead_code,
    reason = "TEST-PHASE hook: evaluated from live-run receipt/readback evidence (#7)"
)]
impl CommitEvidence {
    /// Builds the evidence state for a UI-displayed identifier alone.
    ///
    /// A displayed id is an observation lead, not proof: both receipt and
    /// readback stay absent until independently resolved.
    pub(crate) fn from_ui_displayed_id(displayed_id: &str) -> (Self, String) {
        (
            Self::default(),
            format!(
                "UI-displayed id {displayed_id} is not commit proof: canonical receipt and exact readback unresolved"
            ),
        )
    }

    /// True only with a current canonical receipt and exact readback.
    pub(crate) const fn is_committed(&self) -> bool {
        self.canonical_receipt_write_id.is_some() && matches!(self.exact_readback_match, Some(true))
    }
}
