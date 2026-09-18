//! Native-worker durable-replay route (T9-03, issue #22).
//!
//! Authenticated Kernel transport over the owner-backed replay stream: the
//! five `DurableReplayPort` methods map 1:1 onto the `native_worker_replay`
//! wire family through this route, with persistence owned by the ORS replay
//! tables and admission owned by the wire owner (`admit_replay_request`).
//! Executable currency reuses the T9-02 claim gate (recomputed, never
//! trusted by value).
//!
//! Per-call admission proof (bins hold no replay state): every frame carries
//! the currently-admitted `claim` + `registration` halves beside the replay
//! `binding`. The route re-runs the pure T9-02 claim gate
//! (`validate_native_worker_claim`, `validate_presented_under_registration`,
//! `build_executable_expectation`, `enforce_claim_executable_binding` —
//! validation only, never staging) and loads the durable ORS claim record.
//! The presented executable digest is verified by recomputation against
//! owner inputs, never trusted by value. Only then does the wire
//! `admit_replay_request` run, and only then does the route delegate to ORS.
//!
//! Authority rules enforced here:
//!
//! - This module holds no durable state itself. Persistence is owned by the
//!   ORS replay tables (`lookup/begin/append/replay_stream/acknowledge`);
//!   admission by the wire owner (`admit_replay_request`); executable
//!   currency by the T9-02 gate. This route translates the frame JSON
//!   boundary into those typed owners and seals their verdicts into
//!   receipts. It never fabricates persistence, admission, or a receipt.
//! - Generation authorization splits reads from acquires, per M3:
//!   `lookup`/`replay` may address old-generation history (a new generation
//!   reads history under its own current epoch); `begin`/`append`/
//!   `acknowledge` require exactly the current generation, because they
//!   claim identity or mutate durable cursor state. The split is enforced
//!   twice: by the wire `admit_replay_request` against the owner-current
//!   expectation, and by the ORS claim binding on every mutating path.
//! - `UNKNOWN` acks never advance a cursor and never release retention; the
//!   phase is preserved end to end into the ack reply, with the advance
//!   flags derived from the phase alone at the type level.
//! - `RECEIVED`-phase acks are refused at this boundary (`Shape`): a
//!   transport-only receipt is not durable evidence, and acknowledging only
//!   happens after persistence. The producer sends `DURABLE` once the owner
//!   journal holds the event.
//! - A terminal claim revokes replay authority (`revoked` expectation): every
//!   operation on it fences until a new admission.
//! - Transport error mapping is mechanical: shape, digest, fence, epoch,
//!   service-gate, and storage failures fail closed as `SessionFenced`; a
//!   changed fingerprint under a known `(stream, request)` identity is
//!   `IdentityConflict`; an unknown claim identity is `UnknownRequest`; an
//!   elapsed binding window is `Timeout`.
//!
//! Payload shape: every frame carries `binding` (the wire stream binding),
//! `claim` + `registration` (the current admission proof halves, same shape
//! as the claim operation), and the method inputs (`request_id` +
//! `fingerprint` for lookup/begin, `draft` for append, `after_sequence` +
//! `limit` for replay, `receipt` for acknowledge). Wire `wire_id`/`version`
//! are asserted server-side from the real constants, never trusted from
//! the presenter.

use super::{
    KernelComposition, KernelFrameAction, KernelServiceState,
    native_worker_lifecycle_route::{NativeWorkerRouteConflict, NativeWorkerRouteError},
    status_frame, unix_ms,
};
use eliot_contracts::{EpochId, StateFence, sha256_hex};
use eliot_ipc::{Session, TransportError};
use eliot_kernel_service::{
    NATIVE_WORKER_REPLAY_MAX_PAGE, NATIVE_WORKER_REPLAY_WIRE_ID, NATIVE_WORKER_REPLAY_WIRE_VERSION,
    NativeWorkerReplayAckPhase, NativeWorkerReplayAckReceipt, NativeWorkerReplayAcknowledgeReply,
    NativeWorkerReplayAcknowledgeRequest, NativeWorkerReplayAppendReply,
    NativeWorkerReplayAppendRequest, NativeWorkerReplayAuthority, NativeWorkerReplayBeginReply,
    NativeWorkerReplayBeginRequest, NativeWorkerReplayDecision, NativeWorkerReplayDeliveryClass,
    NativeWorkerReplayEnvelope, NativeWorkerReplayEventDraft, NativeWorkerReplayExpectation,
    NativeWorkerReplayLookupReply, NativeWorkerReplayLookupRequest, NativeWorkerReplayPage,
    NativeWorkerReplayReplayReply, NativeWorkerReplayReplayRequest,
    NativeWorkerReplayStreamBinding, NativeWorkerReplayStreamPosition,
};
use eliot_ors::{
    NativeWorkerClaimRecord, WorkerReplayAck, WorkerReplayBegin,
    WorkerReplayDeliveryClass as OrsDeliveryClass, WorkerReplayDraft, WorkerReplayEvent,
    WorkerReplayPhase as OrsPhase, WorkerReplayRequestDecision,
};
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Wire operations.
// ---------------------------------------------------------------------------

/// Looks up one durable replay identity without claiming it.
pub(crate) const NATIVE_WORKER_REPLAY_LOOKUP_OPERATION: &str = "native_worker.replay_lookup";
/// Atomically claims one durable replay identity.
pub(crate) const NATIVE_WORKER_REPLAY_BEGIN_OPERATION: &str = "native_worker.replay_begin";
/// Appends one opaque event to the current stream.
pub(crate) const NATIVE_WORKER_REPLAY_APPEND_OPERATION: &str = "native_worker.replay_append";
/// Reads one bounded history page past a cursor.
pub(crate) const NATIVE_WORKER_REPLAY_OPERATION: &str = "native_worker.replay";
/// Acknowledges one durable event, advancing only its phase cursor.
pub(crate) const NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION: &str =
    "native_worker.replay_acknowledge";

/// Returns true for the five native-worker replay operations owned here.
///
/// Paired with the worker-side replay client (T9-06); both lists must stay
/// identical. Lifecycle operations stay behind
/// `native_worker_lifecycle_route::is_native_worker_operation`.
#[must_use]
pub(crate) fn is_native_worker_replay_operation(operation: &str) -> bool {
    matches!(
        operation,
        NATIVE_WORKER_REPLAY_LOOKUP_OPERATION
            | NATIVE_WORKER_REPLAY_BEGIN_OPERATION
            | NATIVE_WORKER_REPLAY_APPEND_OPERATION
            | NATIVE_WORKER_REPLAY_OPERATION
            | NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION
    )
}

/// Maximum length of bounded replay text fields, in UTF-8 bytes.
const MAX_REPLAY_TEXT_LEN: usize = 1_024;

// ---------------------------------------------------------------------------
// Small JSON readers (same bounded-text semantics as the lifecycle route).
// ---------------------------------------------------------------------------

fn replay_json_str(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<String, NativeWorkerRouteError> {
    let text = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(NativeWorkerRouteError::Shape { field })?;
    if text.is_empty() || text.len() > MAX_REPLAY_TEXT_LEN || text.chars().any(char::is_control) {
        return Err(NativeWorkerRouteError::Shape { field });
    }
    Ok(text.to_owned())
}

fn replay_json_u64(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<u64, NativeWorkerRouteError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or(NativeWorkerRouteError::Shape { field })
}

fn replay_json_u16(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<u16, NativeWorkerRouteError> {
    let number = replay_json_u64(value, field)?;
    u16::try_from(number).map_err(|_| NativeWorkerRouteError::Shape { field })
}

// ---------------------------------------------------------------------------
// Wire <-> owner mapping (mechanical, no policy).
// ---------------------------------------------------------------------------

fn map_delivery_class(class: NativeWorkerReplayDeliveryClass) -> OrsDeliveryClass {
    match class {
        NativeWorkerReplayDeliveryClass::DurableControl => OrsDeliveryClass::DurableControl,
        NativeWorkerReplayDeliveryClass::DurableObservation => OrsDeliveryClass::DurableObservation,
        NativeWorkerReplayDeliveryClass::BestEffortTelemetry => {
            OrsDeliveryClass::BestEffortTelemetry
        }
    }
}

fn map_ack_phase(phase: NativeWorkerReplayAckPhase) -> Result<OrsPhase, NativeWorkerRouteError> {
    match phase {
        NativeWorkerReplayAckPhase::Received => Err(NativeWorkerRouteError::Shape {
            field: "receipt.phase",
        }),
        NativeWorkerReplayAckPhase::Durable => Ok(OrsPhase::Durable),
        NativeWorkerReplayAckPhase::Normalized => Ok(OrsPhase::Normalized),
        NativeWorkerReplayAckPhase::Applied => Ok(OrsPhase::Applied),
        NativeWorkerReplayAckPhase::Rejected => Ok(OrsPhase::Rejected),
        NativeWorkerReplayAckPhase::Unknown => Ok(OrsPhase::Unknown),
    }
}

fn map_envelope(event: &WorkerReplayEvent) -> NativeWorkerReplayEnvelope {
    NativeWorkerReplayEnvelope {
        stream_id: event.stream_id.clone(),
        producer_id: event.producer_id.clone(),
        producer_generation: event.producer_generation,
        event_id: event.event_id.clone(),
        sequence: event.sequence,
        request_id: event.request_id.clone(),
        fingerprint: event.fingerprint.clone(),
        payload_type: event.payload_type.clone(),
        payload_digest: sha256_hex(event.payload.as_bytes()),
        payload: event.payload.clone(),
        causal_predecessor_refs: event.causal_predecessor_refs.clone(),
        trace_context: event.trace_context.clone(),
        delivery_class: match event.delivery_class {
            OrsDeliveryClass::DurableControl => NativeWorkerReplayDeliveryClass::DurableControl,
            OrsDeliveryClass::DurableObservation => {
                NativeWorkerReplayDeliveryClass::DurableObservation
            }
            OrsDeliveryClass::BestEffortTelemetry => {
                NativeWorkerReplayDeliveryClass::BestEffortTelemetry
            }
        },
        ack_required: event.ack_required,
        disposition: event.disposition.clone(),
    }
}

// ---------------------------------------------------------------------------
// Sealed receipts.
// ---------------------------------------------------------------------------

/// Sealed per-operation replay receipt.
///
/// The `reply` object is the authoritative wire verdict; the top-level
/// echoes bind it to the exact submission. Extra digests ride the same
/// canonical seal so they cannot be stripped without detection.
#[derive(Clone, Debug, Serialize)]
struct NativeWorkerReplayReceipt {
    kind: &'static str,
    operation: &'static str,
    claim_id: String,
    stream_id: String,
    worker_generation: u64,
    reply: serde_json::Value,
    decided_at_unix_ms: u64,
    receipt_digest: String,
}

impl NativeWorkerReplayReceipt {
    fn seal(
        operation: &'static str,
        claim_id: &str,
        stream_id: &str,
        worker_generation: u64,
        reply: serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let decided_at_unix_ms = unix_ms();
        let digest = super::sha256_json(&serde_json::json!({
            "kind": "native_worker_replay",
            "operation": operation,
            "claim_id": claim_id,
            "stream_id": stream_id,
            "worker_generation": worker_generation,
            "reply": reply,
            "decided_at_unix_ms": decided_at_unix_ms,
        }))
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })?;
        let receipt = Self {
            kind: "native_worker_replay",
            operation,
            claim_id: claim_id.to_owned(),
            stream_id: stream_id.to_owned(),
            worker_generation,
            reply,
            decided_at_unix_ms,
            receipt_digest: digest,
        };
        serde_json::to_value(&receipt)
            .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })
    }
}

// ---------------------------------------------------------------------------
// Dispatch entry point.
// ---------------------------------------------------------------------------

impl KernelComposition {
    /// Dispatches one native-worker replay frame.
    ///
    /// The caller ([`crate::KernelComposition::dispatch_frame`]) has already
    /// gated service readiness and peer authentication mirroring the Process
    /// gate; those gates are re-checked here so direct callers cannot bypass
    /// them. Unknown or stale claims fence the session, never authority.
    pub(crate) fn dispatch_native_worker_replay_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?
            != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let request_id = frame
            .request_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let identity = frame
            .request_identity
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let identity_value =
            serde_json::to_value(identity).map_err(|_| TransportError::SessionFenced)?;
        let presented_fence: StateFence = identity_value
            .get("request")
            .and_then(|request| request.get("state_fence"))
            .cloned()
            .and_then(|fence| serde_json::from_value(fence).ok())
            .ok_or(TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&presented_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        let operation = payload
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if !is_native_worker_replay_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        let receipt = match operation {
            NATIVE_WORKER_REPLAY_LOOKUP_OPERATION => {
                self.handle_replay_lookup(session, &identity_value, &payload)
            }
            NATIVE_WORKER_REPLAY_BEGIN_OPERATION => {
                self.handle_replay_begin(session, &identity_value, &payload)
            }
            NATIVE_WORKER_REPLAY_APPEND_OPERATION => {
                self.handle_replay_append(session, &identity_value, &payload)
            }
            NATIVE_WORKER_REPLAY_OPERATION => {
                self.handle_replay_read(session, &identity_value, &payload)
            }
            NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION => {
                self.handle_replay_acknowledge(session, &identity_value, &payload)
            }
            _ => Err(NativeWorkerRouteError::Shape { field: "operation" }),
        }
        .map_err(NativeWorkerRouteError::into_transport)?;
        let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, receipt)?;
        frame.request_id = Some(request_id);
        frame
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(KernelFrameAction::Reply(frame))
    }

    /// Re-runs the pure T9-02 claim gate for one replay frame and loads the
    /// durable claim record.
    ///
    /// Validation only, never staging: the claim + registration halves prove
    /// the presenter holds a currently-admitted executable binding (shape,
    /// live lease, resource agreement, deadline, message identity,
    /// registration binding, recomputed executable digest). The ORS record
    /// proves the admission is durable. Returns the record, the live epoch,
    /// and the verified executable digest.
    fn admit_replay_presenter(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
        now: u64,
    ) -> Result<(NativeWorkerClaimRecord, EpochId, String), NativeWorkerRouteError> {
        let (claim, registration) = Self::split_claim_presentation(payload)?;
        Self::validate_native_worker_registration(registration)?;
        let lease_expires_at_unix_ms =
            Self::replay_require_nonzero_u64(registration, "lease_expires_at_unix_ms")?;
        if lease_expires_at_unix_ms <= now {
            return Err(NativeWorkerRouteError::Fence {
                field: "lease_expires_at_unix_ms",
            });
        }
        Self::require_claim_registration_resource_binding(claim, registration)?;
        let (claim_id, _binding_digest, _generation) = Self::validate_native_worker_claim(claim)?;
        Self::require_message_identity(identity, &claim_id)?;
        Self::require_claim_deadline(claim, now)?;
        // R2 single shape (Implements #22): the replay frame already carries
        // the registration half, so the request projects the envelope from
        // it by construction — the same halves the child submits admit here.
        let request = Self::build_single_shape_request(claim, registration)?;
        let registration_fence: StateFence =
            serde_json::from_value(registration.get("state_fence").cloned().ok_or(
                NativeWorkerRouteError::Shape {
                    field: "state_fence",
                },
            )?)
            .map_err(|_| NativeWorkerRouteError::Shape {
                field: "state_fence",
            })?;
        request
            .validate_presented_under_registration(
                &Self::replay_require_op_id(registration, "registration_id")?,
                Self::replay_require_nonzero_u64(registration, "worker_generation")?,
                registration_fence.authority_epoch.clone(),
                &registration_fence,
            )
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "registration_binding",
            })?;
        let service = self.service_guard()?;
        let live_epoch = service.authority_epoch();
        let expectation = Self::build_executable_expectation(
            request.executable_binding.as_ref(),
            registration,
            &registration_fence,
            &live_epoch,
        )?;
        Self::enforce_claim_executable_binding(&request, &expectation, now)?;
        let verified_digest = request
            .executable_binding
            .as_ref()
            .map(|join| join.executable_binding_digest.clone())
            .ok_or(NativeWorkerRouteError::Fence {
                field: "executable_binding",
            })?;
        drop(service);
        let record = self.load_claim_record(&claim_id)?;
        // Bind the presentation to the durable admission: the presented
        // claim digest must equal the staged digest, so a re-cut join under
        // the known claim identity cannot ride this transport. The T9-02
        // gate above already proved the presented claim internally
        // consistent (recomputed digest over the presented join); this step
        // proves it is the admitted bytes. A changed binding under the
        // known identity is `IdentityConflict`, never a silent promotion.
        if request.binding_digest != record.binding_digest {
            return Err(NativeWorkerRouteError::Conflict(
                NativeWorkerRouteConflict::new(
                    claim_id.clone(),
                    record.binding_digest.clone(),
                    request.binding_digest.clone(),
                    vec!["claim_binding".to_owned()],
                ),
            ));
        }
        if request.worker_generation != record.worker_generation {
            return Err(NativeWorkerRouteError::Fence {
                field: "worker_generation",
            });
        }
        Ok((record, live_epoch, verified_digest))
    }

    /// Builds the owner-current replay expectation from the durable claim
    /// record, the live epoch, the session fence, and the verified
    /// executable digest.
    ///
    /// A terminal claim revokes replay authority: every operation on it
    /// fences until a new admission. Currency is claim-scoped — the record
    /// is the durable truth for its claim — with the live epoch as the
    /// cutover fence: after a cutover the record epoch disagrees with live
    /// and every acquire fails at one layer or the other.
    fn replay_expectation(
        record: &NativeWorkerClaimRecord,
        live_epoch: &EpochId,
        session_fence: &StateFence,
        verified_digest: &str,
    ) -> NativeWorkerReplayExpectation {
        NativeWorkerReplayExpectation {
            current: NativeWorkerReplayAuthority {
                claim_id: record.claim_id.as_str().to_owned(),
                worker_generation: record.worker_generation,
                authority_epoch: live_epoch.clone(),
                state_fence: session_fence.clone(),
                executable_binding_digest: verified_digest.to_owned(),
            },
            revoked: record.state.is_terminal(),
        }
    }

    /// Parses the wire stream binding from one frame payload.
    fn replay_binding(
        payload: &serde_json::Value,
    ) -> Result<NativeWorkerReplayStreamBinding, NativeWorkerRouteError> {
        serde_json::from_value(
            payload
                .get("binding")
                .cloned()
                .ok_or(NativeWorkerRouteError::Shape { field: "binding" })?,
        )
        .map_err(|_| NativeWorkerRouteError::Shape { field: "binding" })
    }

    /// Maps one owner lookup/begin decision onto the wire decision.
    ///
    /// An acquired-but-eventless identity maps to `New` with the live head
    /// position: no history exists for the request yet, and an empty
    /// `Replay` page is never a decision. A changed fingerprint maps to
    /// `Conflict` carrying the retained fingerprint as evidence.
    fn map_request_decision(
        &self,
        stream_id: &str,
        request_id: &str,
        presented_fingerprint: &str,
        decision: WorkerReplayRequestDecision,
    ) -> Result<NativeWorkerReplayDecision, NativeWorkerRouteError> {
        match decision {
            WorkerReplayRequestDecision::New => {
                let next_sequence = self
                    .generation_gateway
                    .ors
                    .load_replay_stream_head(stream_id)
                    .map_err(|_| NativeWorkerRouteError::Fence { field: "ors_load" })?
                    .map_or(1, |head| head.next_sequence);
                Ok(NativeWorkerReplayDecision::New(
                    NativeWorkerReplayStreamPosition {
                        stream_id: stream_id.to_owned(),
                        next_sequence,
                    },
                ))
            }
            WorkerReplayRequestDecision::Replay(events) => {
                if events.is_empty() {
                    let next_sequence = self
                        .generation_gateway
                        .ors
                        .load_replay_stream_head(stream_id)
                        .map_err(|_| NativeWorkerRouteError::Fence { field: "ors_load" })?
                        .map_or(1, |head| head.next_sequence);
                    return Ok(NativeWorkerReplayDecision::New(
                        NativeWorkerReplayStreamPosition {
                            stream_id: stream_id.to_owned(),
                            next_sequence,
                        },
                    ));
                }
                let envelopes = events
                    .iter()
                    .map(map_envelope)
                    .collect::<Vec<NativeWorkerReplayEnvelope>>();
                Ok(NativeWorkerReplayDecision::Replay(NativeWorkerReplayPage {
                    stream_id: stream_id.to_owned(),
                    after_sequence: 0,
                    events: envelopes,
                }))
            }
            WorkerReplayRequestDecision::Conflict => {
                let retained = self
                    .generation_gateway
                    .ors
                    .load_replay_request_record(stream_id, request_id)
                    .map_err(|_| NativeWorkerRouteError::Fence { field: "ors_load" })?
                    .ok_or(NativeWorkerRouteError::Fence { field: "ors_load" })?;
                Err(NativeWorkerRouteError::Conflict(
                    NativeWorkerRouteConflict::new(
                        stream_id.to_owned(),
                        retained.fingerprint.clone(),
                        presented_fingerprint.to_owned(),
                        vec!["fingerprint".to_owned()],
                    ),
                ))
            }
        }
    }

    /// Seals one wire reply into a replay receipt value.
    fn seal_replay_reply(
        operation: &'static str,
        binding: &NativeWorkerReplayStreamBinding,
        reply: serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let receipt = NativeWorkerReplayReceipt::seal(
            operation,
            &binding.claim_id,
            &binding.stream_id,
            binding.worker_generation,
            reply,
        )?;
        serde_json::to_value(&receipt)
            .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })
    }

    fn handle_replay_lookup(
        &self,
        session: &Session,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let now = unix_ms();
        let (record, live_epoch, verified_digest) =
            self.admit_replay_presenter(identity, payload, now)?;
        let binding = Self::replay_binding(payload)?;
        let request_id = replay_json_str(payload, "request_id")?;
        let fingerprint = replay_json_str(payload, "fingerprint")?;
        let expected = Self::replay_expectation(
            &record,
            &live_epoch,
            &session.module_generation.state_fence,
            &verified_digest,
        );
        let request = NativeWorkerReplayLookupRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            request_id: request_id.clone(),
            fingerprint: fingerprint.clone(),
        };
        request
            .admit(&expected)
            .map_err(|error| Self::map_replay_service_error(&error))?;
        let decision = self
            .generation_gateway
            .ors
            .lookup_replay_request(&binding.stream_id, &request_id, &fingerprint)
            .map_err(|_| NativeWorkerRouteError::Fence { field: "ors_load" })?;
        let wire =
            self.map_request_decision(&binding.stream_id, &request_id, &fingerprint, decision)?;
        let reply = NativeWorkerReplayLookupReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            stream_id: binding.stream_id.clone(),
            decision: wire,
        };
        reply
            .validate()
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "reply_shape",
            })?;
        Self::seal_replay_reply(
            NATIVE_WORKER_REPLAY_LOOKUP_OPERATION,
            &binding,
            serde_json::to_value(&reply)
                .map_err(|_| NativeWorkerRouteError::Shape { field: "reply" })?,
        )
    }

    fn handle_replay_begin(
        &self,
        session: &Session,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let now = unix_ms();
        let (record, live_epoch, verified_digest) =
            self.admit_replay_presenter(identity, payload, now)?;
        let binding = Self::replay_binding(payload)?;
        let request_id = replay_json_str(payload, "request_id")?;
        let fingerprint = replay_json_str(payload, "fingerprint")?;
        let expected = Self::replay_expectation(
            &record,
            &live_epoch,
            &session.module_generation.state_fence,
            &verified_digest,
        );
        let request = NativeWorkerReplayBeginRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            request_id: request_id.clone(),
            fingerprint: fingerprint.clone(),
        };
        request
            .admit(&expected)
            .map_err(|error| Self::map_replay_service_error(&error))?;
        let fence_digest = Self::presenting_fence_digest(&session.module_generation.state_fence)?;
        let begin = WorkerReplayBegin {
            stream_id: binding.stream_id.clone(),
            request_id: request_id.clone(),
            fingerprint: fingerprint.clone(),
            producer_generation: binding.worker_generation,
            authority_epoch: live_epoch.sequence.get(),
            fence_digest,
        };
        let decision = self
            .generation_gateway
            .ors
            .begin_replay_request(&begin)
            .map_err(|error| {
                self.map_replay_store_error(&error, &binding.stream_id, &request_id, &fingerprint)
            })?;
        let wire =
            self.map_request_decision(&binding.stream_id, &request_id, &fingerprint, decision)?;
        let reply = NativeWorkerReplayBeginReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            stream_id: binding.stream_id.clone(),
            decision: wire,
        };
        reply
            .validate()
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "reply_shape",
            })?;
        Self::seal_replay_reply(
            NATIVE_WORKER_REPLAY_BEGIN_OPERATION,
            &binding,
            serde_json::to_value(&reply)
                .map_err(|_| NativeWorkerRouteError::Shape { field: "reply" })?,
        )
    }

    fn handle_replay_append(
        &self,
        session: &Session,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let now = unix_ms();
        let (record, live_epoch, verified_digest) =
            self.admit_replay_presenter(identity, payload, now)?;
        let binding = Self::replay_binding(payload)?;
        let draft: NativeWorkerReplayEventDraft = serde_json::from_value(
            payload
                .get("draft")
                .cloned()
                .ok_or(NativeWorkerRouteError::Shape { field: "draft" })?,
        )
        .map_err(|_| NativeWorkerRouteError::Shape { field: "draft" })?;
        let expected = Self::replay_expectation(
            &record,
            &live_epoch,
            &session.module_generation.state_fence,
            &verified_digest,
        );
        let request = NativeWorkerReplayAppendRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            draft: draft.clone(),
        };
        request
            .admit(&expected)
            .map_err(|error| Self::map_replay_service_error(&error))?;
        let fence_digest = Self::presenting_fence_digest(&session.module_generation.state_fence)?;
        let owner_draft = WorkerReplayDraft {
            stream_id: draft.stream_id.clone(),
            producer_id: draft.producer_id.clone(),
            producer_generation: draft.producer_generation,
            authority_epoch: live_epoch.sequence.get(),
            fence_digest,
            request_id: draft.request_id.clone(),
            causal_predecessor_refs: draft.causal_predecessor_refs.clone(),
            delivery_class: map_delivery_class(draft.delivery_class),
            ack_required: draft.ack_required,
            payload_type: draft.payload_type.clone(),
            payload: draft.payload.clone(),
            disposition: draft.disposition.clone(),
            trace_context: draft.trace_context.clone(),
        };
        let event = self
            .generation_gateway
            .ors
            .append_replay_event(&owner_draft)
            .map_err(|error| {
                self.map_replay_store_error(&error, &binding.stream_id, &draft.request_id, "")
            })?;
        let reply = NativeWorkerReplayAppendReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            stream_id: binding.stream_id.clone(),
            envelope: map_envelope(&event),
        };
        reply
            .validate()
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "reply_shape",
            })?;
        Self::seal_replay_reply(
            NATIVE_WORKER_REPLAY_APPEND_OPERATION,
            &binding,
            serde_json::to_value(&reply)
                .map_err(|_| NativeWorkerRouteError::Shape { field: "reply" })?,
        )
    }

    fn handle_replay_read(
        &self,
        session: &Session,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let now = unix_ms();
        let (record, live_epoch, verified_digest) =
            self.admit_replay_presenter(identity, payload, now)?;
        let binding = Self::replay_binding(payload)?;
        let after_sequence = replay_json_u64(payload, "after_sequence")?;
        let limit = replay_json_u16(payload, "limit")?;
        if limit == 0 || limit > NATIVE_WORKER_REPLAY_MAX_PAGE {
            return Err(NativeWorkerRouteError::Shape { field: "limit" });
        }
        let expected = Self::replay_expectation(
            &record,
            &live_epoch,
            &session.module_generation.state_fence,
            &verified_digest,
        );
        let request = NativeWorkerReplayReplayRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            after_sequence,
            limit,
        };
        request
            .admit(&expected)
            .map_err(|error| Self::map_replay_service_error(&error))?;
        let suffix = self
            .generation_gateway
            .ors
            .replay_stream(&binding.stream_id, after_sequence)
            .map_err(|error| self.map_replay_store_error(&error, &binding.stream_id, "", ""))?;
        let take = usize::from(limit).min(suffix.len());
        let events = suffix[..take]
            .iter()
            .map(map_envelope)
            .collect::<Vec<NativeWorkerReplayEnvelope>>();
        let page = NativeWorkerReplayPage {
            stream_id: binding.stream_id.clone(),
            after_sequence,
            events,
        };
        page.validate().map_err(|_| NativeWorkerRouteError::Fence {
            field: "reply_shape",
        })?;
        let reply = NativeWorkerReplayReplayReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            page,
        };
        reply
            .validate()
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "reply_shape",
            })?;
        Self::seal_replay_reply(
            NATIVE_WORKER_REPLAY_OPERATION,
            &binding,
            serde_json::to_value(&reply)
                .map_err(|_| NativeWorkerRouteError::Shape { field: "reply" })?,
        )
    }

    fn handle_replay_acknowledge(
        &self,
        session: &Session,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let now = unix_ms();
        let (record, live_epoch, verified_digest) =
            self.admit_replay_presenter(identity, payload, now)?;
        let binding = Self::replay_binding(payload)?;
        let receipt: NativeWorkerReplayAckReceipt = serde_json::from_value(
            payload
                .get("receipt")
                .cloned()
                .ok_or(NativeWorkerRouteError::Shape { field: "receipt" })?,
        )
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })?;
        let expected = Self::replay_expectation(
            &record,
            &live_epoch,
            &session.module_generation.state_fence,
            &verified_digest,
        );
        let request = NativeWorkerReplayAcknowledgeRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            receipt: receipt.clone(),
        };
        request
            .admit(&expected)
            .map_err(|error| Self::map_replay_service_error(&error))?;
        let phase = map_ack_phase(receipt.phase)?;
        let fence_digest = Self::presenting_fence_digest(&session.module_generation.state_fence)?;
        let ack = WorkerReplayAck {
            stream_id: receipt.stream_id.clone(),
            event_id: receipt.event_id.clone(),
            sequence: receipt.sequence,
            producer_generation: receipt.producer_generation,
            authority_epoch: live_epoch.sequence.get(),
            fence_digest,
            phase,
        };
        let _cursors = self
            .generation_gateway
            .ors
            .acknowledge_replay_event(&ack)
            .map_err(|error| self.map_replay_store_error(&error, &binding.stream_id, "", ""))?;
        // The reply advance flags are declared from the phase alone (the
        // wire contract): a reordered duplicate ack of an already-advanced
        // event still reports the phase-derived flag even though the owner
        // `max()` holds the cursor. The flags are commit proof, not a
        // cursor readback; readers observe exact cursors via the stream
        // head.
        let reply = NativeWorkerReplayAcknowledgeReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            stream_id: binding.stream_id.clone(),
            event_id: receipt.event_id.clone(),
            sequence: receipt.sequence,
            phase: receipt.phase,
            producer_cursor_advanced: receipt.phase.advances_producer_cursor(),
            consumer_cursor_advanced: receipt.phase.advances_consumer_cursor(),
        };
        reply
            .validate()
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "reply_shape",
            })?;
        Self::seal_replay_reply(
            NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION,
            &binding,
            serde_json::to_value(&reply)
                .map_err(|_| NativeWorkerRouteError::Shape { field: "reply" })?,
        )
    }

    /// Maps one wire admission refusal into route vocabulary.
    ///
    /// Malformed shapes and stale/foreign/unknown bindings fail closed as
    /// `SessionFenced`; revocation fences too (a new admission is needed,
    /// never a local repair). No new error kind is invented: the mapping
    /// mirrors `map_executable_error` in the lifecycle route.
    fn map_replay_service_error(
        error: &eliot_kernel_service::KernelServiceError,
    ) -> NativeWorkerRouteError {
        use eliot_kernel_service::KernelServiceError as ServiceError;
        match error {
            ServiceError::InvalidField { .. } => NativeWorkerRouteError::Shape {
                field: "replay_binding",
            },
            _ => NativeWorkerRouteError::Fence {
                field: "replay_binding",
            },
        }
    }

    /// Maps one ORS replay failure into route vocabulary.
    ///
    /// A changed fingerprint under a known identity is `IdentityConflict`
    /// carrying the retained fingerprint as evidence; an unknown claim
    /// identity stays unknown; every storage, binding, staleness, or
    /// incompleteness failure fences the session fail-closed.
    fn map_replay_store_error(
        &self,
        error: &eliot_ors::OrsError,
        stream_id: &str,
        request_id: &str,
        presented_fingerprint: &str,
    ) -> NativeWorkerRouteError {
        use eliot_ors::OrsError as StoreError;
        match error {
            StoreError::WorkerReplayIdentityConflict { .. } => {
                let retained = self
                    .generation_gateway
                    .ors
                    .load_replay_request_record(stream_id, request_id)
                    .ok()
                    .flatten()
                    .map(|record| record.fingerprint)
                    .unwrap_or_default();
                NativeWorkerRouteError::Conflict(NativeWorkerRouteConflict::new(
                    stream_id.to_owned(),
                    retained,
                    presented_fingerprint.to_owned(),
                    vec!["fingerprint".to_owned()],
                ))
            }
            StoreError::ReservationNotFound => NativeWorkerRouteError::Unknown {
                identity: format!("{stream_id}/{request_id}"),
            },
            _ => NativeWorkerRouteError::Fence {
                field: "ors_replay",
            },
        }
    }

    fn replay_require_op_id(
        value: &serde_json::Value,
        field: &'static str,
    ) -> Result<String, NativeWorkerRouteError> {
        replay_json_str(value, field)
    }

    fn replay_require_nonzero_u64(
        value: &serde_json::Value,
        field: &'static str,
    ) -> Result<u64, NativeWorkerRouteError> {
        let number = replay_json_u64(value, field)?;
        if number == 0 {
            return Err(NativeWorkerRouteError::Shape { field });
        }
        Ok(number)
    }
}

#[cfg(test)]
#[path = "tests/native_worker_replay_route.rs"]
mod native_worker_replay_route_tests;
