//! Codex provider turn driver (issue #1941 result flow).
//!
//! Drives one provider turn over a live child channel from owner-issued
//! records through real P-03 execution: launch the admitted process, open
//! the turn with `turn/start` on the child's stdin, pump bounded stdout
//! frames, correlate the turn-start acknowledgement, derive the terminal
//! fact from the pumped frames (never taken as input), translate the
//! canonical result, and emit the measured carrier. Every authority fact
//! arrives injected — attach receipt (Q-01 + route + authority + process
//! request), S2 binding, admission, executor, evidence sink, live channel,
//! turn input, owner event identity/clock/handles, usage — and is
//! re-validated at each step; nothing is minted, defaulted, or estimated
//! here.
//!
//! The codex wire is an interactive request/response protocol over stdio
//! (one-shot spawn without stdin cannot run a turn: the adapter's request
//! builders, response correlation, and preflight sequence exist precisely
//! for the session). Session precondition: the server is initialized and
//! the bound thread is live (owner responsibility; the attach receipt
//! binds the thread identity). This driver sends exactly one `turn/start`
//! per call and pumps that turn's frames; it performs no
//! initialize/thread lifecycle.
//!
//! Pump discipline (all fail-closed, all bounded):
//!
//! ```text
//! live reads until terminal, EOF, rejection, or the owner turn deadline
//! → split ASCII newlines; whitespace-only lines skipped (framing artifact)
//! → CodexWireMessage::parse_line per line (per-line bound + shape enforced)
//! → responses: turn-start acknowledgement correlated by request id
//!   (error field ⟹ turn rejected: stop, unknown outcome with precise
//!   reason); other ids skipped; server requests skipped (no server-request
//!   handling in this driver; the deadline bounds the wait)
//! → notifications: thread agreement plus turn agreement (wire turn id ==
//!   bound execution-unit id) else frame quarantined: skipped, never
//!   attributed; later turns reuse no unit (S2 rule), so stale frames from
//!   a previous turn quarantine automatically
//! → item/agentMessage/delta | item/assistantMessage/delta: append first
//!   present text field (delta_text_from key set — the classifier's own
//!   message-delta arms, never reasoning deltas, never invented fields)
//! → turn/completed with terminal status: first frame wins and its exact
//!   bytes are retained for raw-source binding
//! → every other method ignored
//! → malformed line or over-bound accumulation: whole drive fails
//!   (MalformedWire | WireTooLarge) — gapped text must never measure
//! → empty non-EOF reads: bounded poll sleep, then retry within deadline
//! ```
//!
//! Terminal assembly: the retained frame is normalized through
//! [`normalize_codex_event`](crate::normalize_codex_event) with
//! execution-unit lineage over the presented binding and the owner's event
//! identity. Outcome mapping: the pumped output text (empty yields `None`,
//! never synthesized text) plus the derived terminal feed
//! [`translate_result`](crate::translate_result); the measured carrier is
//! attempted only with a terminal present, via
//! [`observe_measured_tool_result`](super::route_tokenizer::observe_measured_tool_result).
//! Measurement-subsystem withholds (unknown/community model, non-text
//! bytes, unavailable tokenizer) yield `measured: None` while the turn
//! receipt stands; linkage/contract failures fail the drive.
//!
//! The driver is stateless: no session/attempt state is stored, and an
//! already-launched attach receipt reuses the running server instead of
//! relaunching (single-take process-request semantics preserved).
//!
//! Unwired status: no production caller supplies the owner inputs yet (the
//! codex route has no live runtime; see CONTROL/1941-result-flow-delivery.md
//! for the seat survey, the stdin-verification verdict, and the per-owner
//! handoff). This module is reachable implementation with genuine proof,
//! not a completion claim.

use std::sync::Arc;
use std::time::{Duration, Instant};

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentResult, ClockReading, EventCursor, EventId,
    ExecutionUnitObservation, HostEventDeliveryDisposition, ProposedEffect,
    ProviderExecutionBinding, ProviderObservationLineage, RestrictedRawSourceHandle,
    RouteContinuationLocator, UsageReceipt,
};
use eliot_process::{
    ChildStdoutChunk, InteractiveChildChannel, ProcessEvidenceSink, ProcessExecutor,
};
use serde_json::Value;

use super::route_tokenizer::{CodexMeasuredToolResult, observe_measured_tool_result};
use crate::{
    CodexAdapter, CodexAdapterError, CodexAttachReceipt, CodexHostEventInput, CodexResultInput,
    CodexWireMessage, WireMessageKind, correlate_response, delta_text_from, normalize_codex_event,
    terminal_status_from, translate_result, validate_wire_message, wire_turn_id,
};

/// Maximum accumulated pumped bytes for one turn (I7.2 hot-path bound:
/// an over-bound window fails closed instead of measuring partial text).
pub const CODEX_TURN_WIRE_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Maximum bytes requested per channel read (bounded syscall windows).
pub const CODEX_TURN_READ_WINDOW_BYTES: usize = 64 * 1024;
/// Bounded poll pause on empty non-EOF reads (spurious wakeups retry
/// within the owner deadline instead of spinning).
const TURN_PUMP_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Message-delta methods that carry turn output text: exactly the
/// classifier's message-delta arms (never reasoning deltas).
const MESSAGE_DELTA_METHODS: [&str; 2] = ["item/agentMessage/delta", "item/assistantMessage/delta"];
/// Turn-completion method carrying the terminal status.
const TURN_COMPLETED_METHOD: &str = "turn/completed";
/// Wire text keys for turn assembly, mirroring the classifier's delta key
/// set (first present wins, same rule as counting).
const DELTA_TEXT_KEYS: [&str; 5] = ["delta", "text", "content", "message", "output"];
/// Precise unknown reason when the provider rejects the turn start: static
/// text only, never provider prose (credential/prose discipline).
const TURN_START_REJECTED_REASON: &str = "turn start rejected by provider";

/// Owner-issued event identity for terminal normalization.
///
/// The post-R1 identity owner supplies every field; the driver never
/// synthesizes cursors, sequences, handles, or clocks. Cross-field
/// agreement (event id against cursor, sequence against lineage) is
/// enforced by normalization, not assumed here.
#[derive(Clone, Debug)]
pub struct TurnOwnerEvent {
    /// Event identity from the post-R1 owner.
    pub event_id: EventId,
    /// Resume cursor from the post-R1 owner.
    pub cursor: EventCursor,
    /// Monotonic sequence within the bound stream.
    pub sequence: u64,
    /// Previous sequence observed by the owner (`None` for the first event).
    pub previous_sequence: Option<u64>,
    /// Causal predecessor event identities.
    pub predecessors: Vec<EventId>,
    /// Typed observation time from the owner clock. Unknown stays unknown;
    /// a terminal claim with unknown time withholds measurement.
    pub observed_at: ClockReading,
    /// Restricted handle addressing the immutable raw source record.
    pub raw_source_handle: RestrictedRawSourceHandle,
    /// Delivery/coverage disposition of this observation.
    pub delivery: HostEventDeliveryDisposition,
}

/// Owner-issued inputs for one driven turn.
///
/// The P-03 executor, the live channel, the attach receipt (Q-01 +
/// authority + process request), the S2 binding, the admission, the
/// evidence sink, the turn input, and every turn-assembly fact arrive from
/// their owners. Missing launch inputs fail closed; an already-launched
/// receipt reuses the running server.
pub struct CodexTurnDriverInputs<'a, E> {
    /// Injected P-03 executor; remains the lifecycle owner.
    pub executor: Arc<E>,
    /// Live stdin/stdout channel to the admitted child (P-04 implements;
    /// duplex fakes prove against this contract).
    pub channel: Arc<dyn InteractiveChildChannel>,
    /// Owner-attached admission (single-take process request consumed on
    /// first launch; route/session/authority read on every drive).
    pub attached: &'a mut CodexAttachReceipt,
    /// Owner-issued S2 execution binding the wire must attribute to.
    pub binding: &'a ProviderExecutionBinding,
    /// Owner-issued admission the observation must link against.
    pub admission: &'a AdmittedRouteReceipt,
    /// Owner evidence sink for the launch. Required exactly when the
    /// process request is still present (first launch); ignored once the
    /// server is running.
    pub evidence_sink: Option<Arc<dyn ProcessEvidenceSink>>,
    /// Owner turn directive content, sent as the `turn/start` input over
    /// the live channel (never pre-recorded as a result).
    pub turn_input: Value,
    /// Owner turn deadline: bounds the whole pump for terminal evidence.
    pub turn_timeout: Duration,
    /// Owner event identity for terminal normalization.
    pub owner_event: TurnOwnerEvent,
    /// Owner turn-level usage record. Retained, never read as a result cost.
    pub usage: UsageReceipt,
    /// Owner continuation locator (`None` claims no continuation).
    pub continuation: Option<RouteContinuationLocator>,
    /// Owner proposed effects (empty claims none).
    pub proposed_effects: Vec<ProposedEffect>,
    /// Owner cancellation state for this turn.
    pub cancelled: bool,
}

/// Driven turn outcome: the canonical result plus the measured carrier when
/// terminal evidence exists and measures.
#[derive(Clone, Debug)]
pub struct CodexTurnDrive {
    /// Launch receipt when this call launched (`None` when reusing the
    /// already-launched server).
    pub launch: Option<crate::CodexLaunchReceipt>,
    /// Canonical turn result (terminal, partial, cancelled, or unknown).
    pub result: AgentResult,
    /// Measured carrier when a terminal fact exists and the bytes measure.
    /// `None` preserves honest unavailability: never estimated, never zero.
    pub measured: Option<CodexMeasuredToolResult>,
}

/// Turn-start acknowledgement state within one pump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TurnStartAck {
    Pending,
    Accepted,
    Rejected,
}

/// Incremental pump state over one live turn window.
struct TurnPump<'a> {
    output: String,
    terminal_frame: Option<(CodexWireMessage, Vec<u8>)>,
    ack: TurnStartAck,
    request_id: &'a str,
    thread_id: &'a str,
    bound_turn: &'a str,
}

impl TurnPump<'_> {
    /// Pumps one parsed wire line: correlation, quarantine, accumulation,
    /// and terminal retention per the module discipline.
    fn pump_line(&mut self, raw_line: &[u8]) -> Result<(), CodexAdapterError> {
        let message = CodexWireMessage::parse_line(raw_line)?;
        let kind = validate_wire_message(&message)?;
        if kind == WireMessageKind::Request {
            return Ok(());
        }
        if kind == WireMessageKind::Response {
            let actual = message.id.as_ref().and_then(Value::as_str);
            if actual != Some(self.request_id) {
                return Ok(());
            }
            if message.error.is_some() {
                self.ack = TurnStartAck::Rejected;
                return Ok(());
            }
            correlate_response(&message, self.request_id)?;
            self.ack = TurnStartAck::Accepted;
            return Ok(());
        }
        let Some(method) = message.method.as_deref() else {
            return Ok(());
        };
        let params = message.params.clone().unwrap_or(Value::Null);
        if validate_wire_session_against_binding_params(&params, self.thread_id).is_err() {
            return Ok(());
        }
        if wire_turn_id(&params) != Some(self.bound_turn) {
            return Ok(());
        }
        if MESSAGE_DELTA_METHODS.contains(&method) {
            if let Some(text) = delta_text_from(&params, &DELTA_TEXT_KEYS) {
                self.output.push_str(text);
            }
        } else if method == TURN_COMPLETED_METHOD
            && self.terminal_frame.is_none()
            && terminal_status_from(&params).is_some()
        {
            self.terminal_frame = Some((message, raw_line.to_vec()));
        }
        Ok(())
    }

    /// Parses complete lines from the buffer head. On EOF the trailing
    /// partial line (if non-blank) closes as the final frame: stream end
    /// terminates framing, never silently drops bytes. Returns whether any
    /// line was parsed.
    fn drain_buffer(
        &mut self,
        buffer: &mut Vec<u8>,
        end_of_stream: bool,
    ) -> Result<bool, CodexAdapterError> {
        let take_to = if end_of_stream {
            buffer.len()
        } else {
            match buffer.iter().rposition(|byte| *byte == b'\n') {
                Some(position) => position + 1,
                None => 0,
            }
        };
        if take_to == 0 {
            return Ok(false);
        }
        let taken: Vec<u8> = buffer.drain(..take_to).collect();
        let mut parsed_any = false;
        for raw_line in taken.split(|byte| *byte == b'\n') {
            if raw_line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            parsed_any = true;
            self.pump_line(raw_line)?;
            if self.terminal_frame.is_some() || self.ack == TurnStartAck::Rejected {
                break;
            }
        }
        Ok(parsed_any)
    }
}

/// Thread agreement for one pumped frame: the frame's thread identity must
/// equal the attached session thread. Absent thread fields cannot
/// corroborate and fail the frame (quarantine), unlike the binding-level
/// check which tolerates absent fields on uncorroborated paths.
fn validate_wire_session_against_binding_params(
    params: &Value,
    thread_id: &str,
) -> Result<(), CodexAdapterError> {
    let Some(object) = params.as_object() else {
        return Err(CodexAdapterError::SessionMismatch);
    };
    let mut corroborated = false;
    for key in ["threadId", "thread_id"] {
        if let Some(value) = object.get(key) {
            let matches = value.as_str() == Some(thread_id);
            if !matches {
                return Err(CodexAdapterError::SessionMismatch);
            }
            corroborated = true;
        }
    }
    if corroborated {
        Ok(())
    } else {
        Err(CodexAdapterError::SessionMismatch)
    }
}

/// Drives one provider turn: launch, open, pump, translate, measure.
///
/// See the module documentation for positions, discipline, and unwired
/// status. All authority facts arrive injected and are re-validated by the
/// callee that owns each check; this function adds no defaults and mints
/// no records. The prepared-session precondition holds: the server is
/// initialized and the attached thread is live (owner responsibility).
///
/// # Errors
///
/// Returns contract errors for linkage/evidence failures
/// (`BindingMismatch`, `SessionMismatch`, `MalformedWire`, digest
/// failures), [`CodexAdapterError::WireTooLarge`] for an over-bound
/// window, [`CodexAdapterError::InvalidInput`] for a missing launch sink,
/// or the P-03 [`CodexAdapterError::Process`] failure. Measurement-only
/// withholds surface as `measured: None`, never as errors.
pub async fn drive_codex_turn<E: ProcessExecutor + 'static>(
    inputs: CodexTurnDriverInputs<'_, E>,
) -> Result<CodexTurnDrive, CodexAdapterError> {
    let CodexTurnDriverInputs {
        executor,
        channel,
        attached,
        binding,
        admission,
        evidence_sink,
        turn_input,
        turn_timeout,
        owner_event,
        usage,
        continuation,
        proposed_effects,
        cancelled,
    } = inputs;
    let launch = match attached.process_request() {
        Some(_) => {
            let sink = evidence_sink.ok_or(CodexAdapterError::InvalidInput(
                "evidence sink required for launch",
            ))?;
            let adapter = CodexAdapter::new(Arc::clone(&executor));
            Some(adapter.launch(attached, sink).await?)
        }
        None => None,
    };
    let operation_id = attached.operation_id().clone();
    let thread_id = attached.session().thread_id.clone();
    let bound_turn = binding.execution_unit.unit_id.as_str().to_owned();
    let request_id = format!("{bound_turn}-start");
    let turn_start = CodexWireMessage::turn_start(&request_id, &thread_id, &turn_input);
    let turn_start_bytes = serde_json::to_vec(&turn_start)
        .map_err(|_| CodexAdapterError::MalformedWire("turn start serialization"))?;
    let written = channel
        .write_child_stdin(operation_id.clone(), turn_start_bytes.clone())
        .await
        .map_err(CodexAdapterError::Process)?;
    if written != turn_start_bytes.len() {
        return Err(CodexAdapterError::Process(
            eliot_process::ProcessExecutionError::Unavailable("short stdin write".to_owned()),
        ));
    }
    let mut pump = TurnPump {
        output: String::new(),
        terminal_frame: None,
        ack: TurnStartAck::Pending,
        request_id: &request_id,
        thread_id: &thread_id,
        bound_turn: &bound_turn,
    };
    let started = Instant::now();
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        if pump.terminal_frame.is_some() || pump.ack == TurnStartAck::Rejected {
            break;
        }
        if started.elapsed() >= turn_timeout {
            break;
        }
        if pump.output.len() + buffer.len() >= CODEX_TURN_WIRE_MAX_BYTES {
            return Err(CodexAdapterError::WireTooLarge);
        }
        let remaining = turn_timeout.saturating_sub(started.elapsed());
        let chunk: ChildStdoutChunk = channel
            .read_child_stdout(&operation_id, CODEX_TURN_READ_WINDOW_BYTES, remaining)
            .await
            .map_err(CodexAdapterError::Process)?;
        if buffer.len() + pump.output.len() + chunk.bytes.len() > CODEX_TURN_WIRE_MAX_BYTES {
            return Err(CodexAdapterError::WireTooLarge);
        }
        let chunk_empty = chunk.bytes.is_empty();
        let end_of_stream = chunk.end_of_stream;
        buffer.extend_from_slice(&chunk.bytes);
        let parsed_any = pump.drain_buffer(&mut buffer, end_of_stream)?;
        if end_of_stream {
            break;
        }
        if !chunk_empty || parsed_any {
            continue;
        }
        tokio::time::sleep(TURN_PUMP_POLL_INTERVAL).await;
    }
    let terminal = match pump.terminal_frame {
        Some((message, frame_bytes)) => {
            let lineage = ProviderObservationLineage::ExecutionUnitObservation(Box::new(
                ExecutionUnitObservation {
                    binding: binding.clone(),
                    cursor: owner_event.cursor.clone(),
                    sequence: owner_event.sequence,
                },
            ));
            let (envelope, _receipt) = normalize_codex_event(CodexHostEventInput {
                message: &message,
                lineage,
                event_id: owner_event.event_id.clone(),
                cursor: owner_event.cursor.clone(),
                sequence: owner_event.sequence,
                previous_sequence: owner_event.previous_sequence,
                predecessors: owner_event.predecessors.clone(),
                raw_source_bytes: &frame_bytes,
                raw_source_handle: owner_event.raw_source_handle.clone(),
                observed_at: owner_event.observed_at,
                delivery: owner_event.delivery,
                admission: Some(admission),
            })?;
            Some(envelope)
        }
        None => None,
    };
    let output_text = pump.output.clone();
    let unknown_reason = match pump.ack {
        TurnStartAck::Rejected if terminal.is_none() => Some(TURN_START_REJECTED_REASON.to_owned()),
        _ => None,
    };
    let result = translate_result(
        CodexResultInput {
            route: attached.route().clone(),
            session: attached.session().clone(),
            output: if output_text.is_empty() {
                None
            } else {
                Some(output_text.clone())
            },
            terminal_observation: terminal.clone(),
            cancelled,
            unknown_reason,
            usage,
            continuation,
            proposed_effects,
        },
        binding,
        admission,
        &attached.authority().effect_ceiling,
    )?;
    let measured = match terminal {
        None => None,
        Some(envelope) => {
            match observe_measured_tool_result(
                output_text.as_bytes(),
                &envelope,
                binding,
                admission,
            ) {
                Ok(carrier) => Some(carrier),
                Err(
                    CodexAdapterError::UnknownTokenizerModel { .. }
                    | CodexAdapterError::UncountableBytes
                    | CodexAdapterError::TokenizerUnavailable(..),
                ) => None,
                Err(other) => return Err(other),
            }
        }
    };
    Ok(CodexTurnDrive {
        launch,
        result,
        measured,
    })
}
