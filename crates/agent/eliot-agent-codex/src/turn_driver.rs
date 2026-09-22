//! Codex provider turn driver (issue #1941 result flow).
//!
//! Drives one provider turn from owner-issued records through real P-03
//! execution: launch the admitted process, pump the bounded evidence byte
//! window as JSONL, derive the terminal fact from the pumped frames (never
//! taken as input), translate the canonical result, and emit the measured
//! carrier. Every authority fact arrives injected — attach receipt (Q-01 +
//! route + authority + process request), S2 binding, admission, owner event
//! identity/clock/handles, turn-level usage, and the P-03 executor — and is
//! re-validated at each step; nothing is minted, defaulted, or estimated
//! here.
//!
//! Position in the chain: owner runtime (holds executor + evidence sink
//! infrastructure) → this driver (spawn + pump + assemble) → carrier toward
//! the bridge receipt join. The driver is stateless: no session/attempt
//! state is stored, and an already-launched attach receipt reuses the
//! running server instead of relaunching (single-take process-request
//! semantics preserved).
//!
//! Pump discipline (all fail-closed, all bounded):
//!
//! ```text
//! window bytes (owner-pumped stdout, at most CODEX_TURN_WIRE_MAX_BYTES)
//! → split ASCII newlines; whitespace-only lines skipped (framing artifact)
//! → CodexWireMessage::parse_line per line (per-line bound + shape enforced)
//! → notifications only (requests/responses are correlation traffic, skipped)
//! → thread agreement (validate_wire_session_against_binding) else frame
//!   quarantined: skipped, caller retains the raw window
//! → turn agreement (wire_turn_id == bound execution-unit id) else skipped
//! → item/agentMessage/delta | item/assistantMessage/delta: append first
//!   present text field (delta_text_from key set — the classifier's own
//!   message-delta arms, never reasoning deltas, never invented fields)
//! → turn/completed with terminal status: first frame wins and its exact
//!   bytes are retained for raw-source binding; later duplicates ignored
//! → every other method ignored (started events, usage observations,
//!   session frames — not turn output or terminal evidence)
//! → malformed line: whole drive fails MalformedWire (a gapped window must
//!   never measure partial text as the turn)
//! ```
//!
//! Terminal assembly: the retained frame is normalized through
//! [`normalize_codex_event`](crate::normalize_codex_event) with
//! execution-unit lineage over the presented binding and the owner's event
//! identity (event id, cursor, sequence, predecessors), clock, restricted
//! handle, and delivery. No terminal ever enters as input.
//!
//! Outcome mapping: the pumped output text (empty window or no deltas yields
//! `None`, never synthesized text) plus the derived terminal feed
//! [`translate_result`](crate::translate_result); the measured carrier is
//! attempted only with a terminal present, via
//! [`observe_measured_tool_result`](super::route_tokenizer::observe_measured_tool_result).
//! Measurement-subsystem withholds (unknown/community model, non-text
//! bytes, unavailable tokenizer) yield `measured: None` while the turn
//! receipt stands; linkage/contract failures fail the drive.
//!
//! Unwired status: no production caller supplies the owner inputs yet (the
//! codex route has no live runtime; see CONTROL/1941-result-flow-delivery.md
//! for the seat survey and the per-owner handoff). This module is reachable
//! implementation with genuine proof, not a completion claim.

use std::sync::Arc;

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentResult, ClockReading, EventCursor, EventId,
    ExecutionUnitObservation, HostEventDeliveryDisposition, ProposedEffect,
    ProviderExecutionBinding, ProviderObservationLineage, RestrictedRawSourceHandle,
    RouteContinuationLocator, UsageReceipt,
};
use eliot_process::{ProcessEvidenceSink, ProcessExecutor};
use serde_json::Value;

use super::route_tokenizer::{CodexMeasuredToolResult, observe_measured_tool_result};
use crate::{
    CodexAdapter, CodexAdapterError, CodexAttachReceipt, CodexHostEventInput, CodexResultInput,
    CodexWireMessage, WireMessageKind, delta_text_from, normalize_codex_event,
    terminal_status_from, translate_result, validate_wire_message,
    validate_wire_session_against_binding, wire_turn_id,
};

/// Maximum pumped evidence-window bytes for one turn (I7.2 hot-path bound:
/// turn frames are small bounded projections; an over-bound window fails
/// closed instead of measuring partial text).
pub const CODEX_TURN_WIRE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Message-delta methods that carry turn output text: exactly the
/// classifier's message-delta arms (never reasoning deltas).
const MESSAGE_DELTA_METHODS: [&str; 2] = ["item/agentMessage/delta", "item/assistantMessage/delta"];
/// Turn-completion method carrying the terminal status.
const TURN_COMPLETED_METHOD: &str = "turn/completed";
/// Wire text keys for turn assembly, mirroring the classifier's delta key
/// set (first present wins, same rule as counting).
const DELTA_TEXT_KEYS: [&str; 5] = ["delta", "text", "content", "message", "output"];

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
/// The P-03 executor, the evidence sink, the attach receipt (Q-01 +
/// authority + process request), the S2 binding, the admission, the pumped
/// wire window, and every turn-assembly fact arrive from their owners.
/// Missing launch inputs fail closed; an already-launched receipt reuses
/// the running server.
pub struct CodexTurnDriverInputs<'a, E> {
    /// Injected P-03 executor; remains the lifecycle owner.
    pub executor: Arc<E>,
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
    /// Owner-pumped stdout window for this turn, bounded by
    /// [`CODEX_TURN_WIRE_MAX_BYTES`]. Must be the launched operation's
    /// evidence; operation agreement beyond thread/turn/binding filtering
    /// stays with the evidence supplier.
    pub wire_bytes: &'a [u8],
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

/// Pumped turn facts: assembled output text plus the retained terminal
/// frame.
struct PumpedTurn {
    output: Option<String>,
    terminal_frame: Option<(CodexWireMessage, Vec<u8>)>,
}

/// Pumps one bounded wire window into turn facts.
///
/// Pure over bytes plus the presented binding: no executor, no owner
/// event identity, no admission. Foreign or malformed content never
/// becomes turn evidence (see module docs).
fn pump_turn_window(
    wire_bytes: &[u8],
    binding: &ProviderExecutionBinding,
) -> Result<PumpedTurn, CodexAdapterError> {
    if wire_bytes.len() > CODEX_TURN_WIRE_MAX_BYTES {
        return Err(CodexAdapterError::WireTooLarge);
    }
    let bound_turn = binding.execution_unit.unit_id.as_str();
    let mut output = String::new();
    let mut terminal_frame: Option<(CodexWireMessage, Vec<u8>)> = None;
    for raw_line in wire_bytes.split(|byte| *byte == b'\n') {
        if raw_line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let message = CodexWireMessage::parse_line(raw_line)?;
        if validate_wire_message(&message)? != WireMessageKind::Notification {
            continue;
        }
        let Some(method) = message.method.as_deref() else {
            continue;
        };
        let params = message.params.clone().unwrap_or(Value::Null);
        if validate_wire_session_against_binding(&params, binding).is_err() {
            continue;
        }
        if wire_turn_id(&params) != Some(bound_turn) {
            continue;
        }
        if MESSAGE_DELTA_METHODS.contains(&method) {
            if let Some(text) = delta_text_from(&params, &DELTA_TEXT_KEYS) {
                output.push_str(text);
            }
        } else if method == TURN_COMPLETED_METHOD
            && terminal_frame.is_none()
            && terminal_status_from(&params).is_some()
        {
            terminal_frame = Some((message, raw_line.to_vec()));
        }
    }
    let output = if output.is_empty() {
        None
    } else {
        Some(output)
    };
    Ok(PumpedTurn {
        output,
        terminal_frame,
    })
}

/// Drives one provider turn: launch, pump, translate, measure.
///
/// See the module documentation for positions, discipline, and unwired
/// status. All authority facts arrive injected and are re-validated by the
/// callee that owns each check; this function adds no defaults and mints
/// no records.
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
        attached,
        binding,
        admission,
        evidence_sink,
        wire_bytes,
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
    let pumped = pump_turn_window(wire_bytes, binding)?;
    let terminal = match pumped.terminal_frame {
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
    let output_text = pumped.output.clone().unwrap_or_default();
    let result = translate_result(
        CodexResultInput {
            route: attached.route().clone(),
            session: attached.session().clone(),
            output: pumped.output,
            terminal_observation: terminal.clone(),
            cancelled,
            unknown_reason: None,
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
