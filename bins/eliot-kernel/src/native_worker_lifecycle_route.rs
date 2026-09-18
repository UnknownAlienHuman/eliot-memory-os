//! Native-worker lifecycle route (Waves B+C, issue #872).
//!
//! Per-operation `validate → service-gate → ORS-stage → receipt` handlers for
//! registration, claim, ready, heartbeat, checkpoint, result submission, and
//! cancellation observation. Ordering mirrors
//! [`crate::KernelComposition::admit_host_request_envelope`] (admit, cancel,
//! reconcile, rehydrate): the durable record is staged before any receipt is
//! returned, an exact replay returns the same receipt, and a changed binding
//! under one identity conflicts before effect.
//!
//! Authority rules enforced here:
//!
//! - This module holds no durable state itself. Persistence is owned by the
//!   ORS claim table (`stage/load/advance_native_worker_claim`) and admission
//!   by the Kernel service owner (`admit_native_worker_claim`,
//!   `mark_native_worker_ready`); this route translates the frame JSON
//!   boundary into those typed owners and translates their typed verdicts
//!   back into sealed receipts. It never fabricates persistence, admission,
//!   readiness, or a receipt.
//! - Heartbeat returns a [`NativeWorkerLivenessReceipt`] only. That type
//!   carries no admission, authority, permit, readiness, or completion field
//!   and is never accepted as input by any handler in this file, so liveness
//!   cannot create progress, success, authority, or completion.
//! - Cancellation fences the exact attempt, preserves possible work/result
//!   state (the staged record moves to `cancelling`, never to a terminal
//!   state here), and drives bounded descendant cleanup through the existing
//!   #100 [`ProcessExecutionRequest::Cancel`] path. No new process mechanics.
//! - Unknown or stale worker generations fence the session; they are never
//!   granted authority, admission, or a receipt.
//! - Wire identity comes from the real Wave-A constants re-exported at the
//!   `eliot_kernel_service` root; claim shapes are rebuilt as the typed
//!   [`NativeWorkerClaimRequest`] and re-validated by the service owner, so a
//!   tampered presentation fails there even if it passed the boundary parse.
//!
//! Registration is a validated verdict, not a durable row: the ORS owner
//! persists claims (the unit of admission), while the registration lease is
//! enforced per message (expiry, renewal distinctness, generation/epoch/fence
//! agreement with the claim). A registration replay table belongs to a later
//! wave and is recorded as a residual, not faked here.
//!
//! Transport error mapping is mechanical: shape, digest, fence, service-gate,
//! and storage failures fail closed as `SessionFenced`; a changed binding
//! under a known identity is `IdentityConflict`; an unknown claim identity is
//! `UnknownRequest`; an elapsed absolute deadline is `Timeout`.

use super::{
    KernelComposition, KernelFrameAction, KernelServiceState, ProcessExecutionRequest,
    caller_binding, native_worker_reconcile_route::NATIVE_WORKER_RECONCILE_OPERATION, sha256_json,
    status_frame, unix_ms,
};
use eliot_contracts::{EpochId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_ipc::{Session, TransportError};
use eliot_kernel_service::{
    KernelServiceError, NATIVE_WORKER_CLAIM_WIRE_ID, NATIVE_WORKER_CLAIM_WIRE_VERSION,
    NATIVE_WORKER_CLAIM_WIRE_VERSION_V1, NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
    NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION, NATIVE_WORKER_PROTOCOL_VERSION,
    NativeWorkerClaimBudget, NativeWorkerClaimRequest, NativeWorkerClaimResponse,
    NativeWorkerExecutableBinding, NativeWorkerExecutableExpectation,
};
use eliot_ors::{NativeWorkerClaimRecord, NativeWorkerClaimState, OperationIdentity, OrsError};
use eliot_process::OperationId;
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Wire operations and Wave-A identity mirrors.
// ---------------------------------------------------------------------------

/// Registers (or renews, with a fresh renewal identity) one worker generation.
pub(crate) const NATIVE_WORKER_REGISTRATION_OPERATION: &str = "native_worker.registration";
/// Claims exactly one Kernel-owned execution unit under a registration.
pub(crate) const NATIVE_WORKER_CLAIM_OPERATION: &str = "native_worker.claim";
/// Submits one typed ready-or-blocked verdict for an admitted claim.
pub(crate) const NATIVE_WORKER_READY_OPERATION: &str = "native_worker.ready";
/// Observes generation liveness under an exact binding; never authority.
pub(crate) const NATIVE_WORKER_HEARTBEAT_OPERATION: &str = "native_worker.heartbeat";
/// Stores one checkpoint reference under an exact binding.
pub(crate) const NATIVE_WORKER_CHECKPOINT_OPERATION: &str = "native_worker.checkpoint";
/// Submits one result digest under an exact binding; not acceptance.
pub(crate) const NATIVE_WORKER_RESULT_SUBMIT_OPERATION: &str = "native_worker.result_submit";
/// Observes cancellation for one exact attempt and fences it.
pub(crate) const NATIVE_WORKER_CANCEL_OBSERVE_OPERATION: &str = "native_worker.cancel_observe";

/// Returns true for the eight native-worker operations (seven lifecycle
/// operations owned here plus reconciliation owned by the sibling
/// `native_worker_reconcile_route` module).
///
/// Paired with the worker-side operation constants in
/// `bins/eliot-native-worker/src/kernel_admission_client.rs`; both lists must
/// stay identical.
pub(crate) fn is_native_worker_operation(operation: &str) -> bool {
    matches!(
        operation,
        NATIVE_WORKER_REGISTRATION_OPERATION
            | NATIVE_WORKER_CLAIM_OPERATION
            | NATIVE_WORKER_READY_OPERATION
            | NATIVE_WORKER_HEARTBEAT_OPERATION
            | NATIVE_WORKER_CHECKPOINT_OPERATION
            | NATIVE_WORKER_RESULT_SUBMIT_OPERATION
            | NATIVE_WORKER_CANCEL_OBSERVE_OPERATION
            | NATIVE_WORKER_RECONCILE_OPERATION
    )
}

/// Maximum length of bounded claim/registration text fields, in UTF-8 bytes.
const MAX_CLAIM_TEXT_LEN: usize = 1_024;
/// Maximum length of one native-worker operation identity, in UTF-8 bytes.
const MAX_OPERATION_IDENTITY_LEN: usize = 256;
/// Maximum entries admitted in one registration invalidation set.
const MAX_INVALIDATION_ENTRIES: usize = 64;
/// Maximum credential references admitted in one readiness report.
const MAX_CREDENTIAL_REFERENCES: usize = 64;
/// Maximum changed-field entries admitted in one conflict report.
const MAX_CONFLICT_FIELDS: usize = 32;

// ---------------------------------------------------------------------------
// Receipts.
// ---------------------------------------------------------------------------

/// Explicit non-authority liveness receipt for one heartbeat.
///
/// Carries no admission, authority, permit, readiness, or completion field by
/// construction. No handler in this file accepts this shape as input, so a
/// liveness receipt can never be replayed as admission proof.
#[derive(Clone, Debug, Serialize)]
struct NativeWorkerLivenessReceipt {
    kind: &'static str,
    heartbeat_id: String,
    claim_id: String,
    worker_generation: u64,
    observed_at_unix_ms: u64,
    receipt_digest: String,
}

impl NativeWorkerLivenessReceipt {
    fn seal(
        heartbeat_id: &str,
        claim_id: &str,
        worker_generation: u64,
        observed_at_unix_ms: u64,
    ) -> Result<serde_json::Value, TransportError> {
        let body = serde_json::json!({
            "kind": "native_worker_liveness",
            "heartbeat_id": heartbeat_id,
            "claim_id": claim_id,
            "worker_generation": worker_generation,
            "observed_at_unix_ms": observed_at_unix_ms,
        });
        let digest = sha256_json(&body).map_err(|_| TransportError::SessionFenced)?;
        let mut receipt = body;
        receipt["receipt_digest"] = serde_json::Value::String(digest);
        Ok(receipt)
    }
}

/// Seals one route receipt body with its canonical digest.
pub(crate) fn seal_route_receipt(
    mut body: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let digest = sha256_json(&body).map_err(|_| TransportError::SessionFenced)?;
    body["receipt_digest"] = serde_json::Value::String(digest);
    Ok(body)
}

// ---------------------------------------------------------------------------
// Typed route errors (mechanical TransportError mapping at the boundary).
// ---------------------------------------------------------------------------

/// Changed-work conflict under one claim identity.
///
/// Constructed from the ORS owner's identity-conflict signal when the same
/// identity is presented with changed bound work.
#[derive(Clone, Debug)]
pub(crate) struct NativeWorkerRouteConflict {
    identity: String,
    expected_digest: String,
    observed_digest: String,
    changed_fields: Vec<String>,
}

impl NativeWorkerRouteConflict {
    /// Builds one changed-work conflict under a known identity.
    pub(crate) fn new(
        identity: String,
        expected_digest: String,
        observed_digest: String,
        changed_fields: Vec<String>,
    ) -> Self {
        Self {
            identity,
            expected_digest,
            observed_digest,
            changed_fields,
        }
    }
}

/// Typed failure for one native-worker lifecycle operation.
#[derive(Clone, Debug)]
pub(crate) enum NativeWorkerRouteError {
    /// A bounded shape check failed for the named field.
    Shape { field: &'static str },
    /// Epoch, fence, or generation binding failed for the named field.
    Fence { field: &'static str },
    /// The claim identity has no staged record.
    Unknown { identity: String },
    /// The same identity carries changed bound work.
    Conflict(NativeWorkerRouteConflict),
    /// The absolute claim deadline elapsed before admission.
    ExpiredDeadline,
}

impl std::fmt::Display for NativeWorkerRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shape { field } => write!(f, "native-worker shape rejected: {field}"),
            Self::Fence { field } => write!(f, "native-worker fence rejected: {field}"),
            Self::Unknown { identity } => {
                write!(f, "native-worker claim is unknown: {identity}")
            }
            Self::Conflict(conflict) => write!(
                f,
                "native-worker binding conflict under {} (expected {}, observed {}, changed {})",
                conflict.identity,
                conflict.expected_digest,
                conflict.observed_digest,
                conflict.changed_fields.join(","),
            ),
            Self::ExpiredDeadline => write!(f, "native-worker claim deadline elapsed"),
        }
    }
}

impl NativeWorkerRouteError {
    pub(crate) fn into_transport(self) -> TransportError {
        match self {
            Self::Shape { .. } | Self::Fence { .. } => TransportError::SessionFenced,
            Self::Unknown { .. } => TransportError::UnknownRequest,
            Self::Conflict(_) => TransportError::IdentityConflict,
            Self::ExpiredDeadline => TransportError::Timeout,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared JSON field readers (single validation semantics for this route).
// ---------------------------------------------------------------------------

/// Reads one bounded text field: present, string, non-blank, control-free.
pub(crate) fn native_worker_json_str(
    value: &serde_json::Value,
    field: &'static str,
    max_len: usize,
) -> Result<String, NativeWorkerRouteError> {
    let text = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(NativeWorkerRouteError::Shape { field })?;
    if text.trim().is_empty() || text.chars().any(char::is_control) || text.len() > max_len {
        return Err(NativeWorkerRouteError::Shape { field });
    }
    Ok(text.to_owned())
}

/// Reads one bounded operation-identity field.
pub(crate) fn require_op_id(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<String, NativeWorkerRouteError> {
    native_worker_json_str(value, field, MAX_OPERATION_IDENTITY_LEN)
}

/// Reads one bounded claim/registration text field.
pub(crate) fn require_claim_text(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<String, NativeWorkerRouteError> {
    native_worker_json_str(value, field, MAX_CLAIM_TEXT_LEN)
}

/// Reads one numeric-or-numeric-string scalar as `u64`.
pub(crate) fn native_worker_json_u64(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<u64, NativeWorkerRouteError> {
    if let Some(number) = value.get(field).and_then(serde_json::Value::as_u64) {
        return Ok(number);
    }
    if let Some(text) = value.get(field).and_then(serde_json::Value::as_str)
        && let Ok(number) = text.parse::<u64>()
    {
        return Ok(number);
    }
    Err(NativeWorkerRouteError::Shape { field })
}

/// Reads one numeric-or-numeric-string scalar as `u16` with range check.
fn native_worker_json_u16(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<u16, NativeWorkerRouteError> {
    let number = native_worker_json_u64(value, field)?;
    u16::try_from(number).map_err(|_| NativeWorkerRouteError::Shape { field })
}

/// Reads one numeric-or-numeric-string scalar as `u32` with range check.
fn native_worker_json_u32(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<u32, NativeWorkerRouteError> {
    let number = native_worker_json_u64(value, field)?;
    u32::try_from(number).map_err(|_| NativeWorkerRouteError::Shape { field })
}

/// Reads one nonzero `u64` field.
pub(crate) fn require_nonzero_u64(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<u64, NativeWorkerRouteError> {
    let number = native_worker_json_u64(value, field)?;
    if number == 0 {
        return Err(NativeWorkerRouteError::Shape { field });
    }
    Ok(number)
}

/// Reads one lowercase SHA-256 digest field.
pub(crate) fn require_digest(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<String, NativeWorkerRouteError> {
    let digest = native_worker_json_str(value, field, MAX_CLAIM_TEXT_LEN)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(NativeWorkerRouteError::Shape { field });
    }
    Ok(digest)
}

/// Checks one `authority_epoch` field against its fence, accepting both wire
/// contours on the single shape (Implements #22 R2).
///
/// The Kernel-service wire carries the epoch as a scalar sequence
/// (`Implements #64` bridge: sequence must equal the fence tuple sequence,
/// lineage via the fence). The worker-core single shape
/// (`ClaimAdmissionRequest`) carries the full `EpochId` object, which must be
/// the exact same authority as the fence epoch (`is_same_authority`, never a
/// raw sequence compare). Both enforce the exact-tuple rule; mixed
/// representations fail closed.
fn check_authority_epoch_against_fence(
    container: &serde_json::Value,
    field: &'static str,
    fence: &StateFence,
) -> Result<(), NativeWorkerRouteError> {
    let epoch_value = container
        .get(field)
        .ok_or(NativeWorkerRouteError::Shape { field })?;
    if epoch_value.is_number() || epoch_value.is_string() {
        let sequence = native_worker_json_u64(container, field)?;
        if fence.authority_epoch.sequence.get() != sequence {
            return Err(NativeWorkerRouteError::Fence {
                field: "epoch_fence",
            });
        }
        return Ok(());
    }
    if epoch_value.is_object() {
        let epoch: EpochId = serde_json::from_value(epoch_value.clone())
            .map_err(|_| NativeWorkerRouteError::Shape { field })?;
        if !epoch.is_same_authority(&fence.authority_epoch) {
            return Err(NativeWorkerRouteError::Fence {
                field: "epoch_fence",
            });
        }
        return Ok(());
    }
    Err(NativeWorkerRouteError::Shape { field })
}

/// Compares two `authority_epoch` halves for the split binding, accepting both
/// contours (scalar-scalar, object-object via exact-tuple, or mixed via
/// sequence). A lineage mismatch on object-object fails closed.
fn check_split_epoch_agreement(
    claim: &serde_json::Value,
    registration: &serde_json::Value,
) -> Result<(), NativeWorkerRouteError> {
    let claim_epoch = claim
        .get("authority_epoch")
        .ok_or(NativeWorkerRouteError::Shape {
            field: "authority_epoch",
        })?;
    let registration_epoch =
        registration
            .get("authority_epoch")
            .ok_or(NativeWorkerRouteError::Shape {
                field: "authority_epoch",
            })?;
    if claim_epoch == registration_epoch {
        // Same JSON (scalar-scalar or identical objects) binds. For objects
        // this already implies the exact tuple; the fence equality below
        // re-proves lineage.
        return Ok(());
    }
    // Mixed or differing representations: fall back to sequence agreement so
    // the single shape stays interoperable during the transition. Object
    // halves additionally require lineage agreement via their fences (checked
    // by the caller through fence equality plus the fence-epoch checks).
    let claim_sequence = if claim_epoch.is_number() || claim_epoch.is_string() {
        native_worker_json_u64(claim, "authority_epoch")?
    } else if claim_epoch.is_object() {
        serde_json::from_value::<EpochId>(claim_epoch.clone())
            .map_err(|_| NativeWorkerRouteError::Shape {
                field: "authority_epoch",
            })?
            .sequence
            .get()
    } else {
        return Err(NativeWorkerRouteError::Shape {
            field: "authority_epoch",
        });
    };
    let registration_sequence = if registration_epoch.is_number() || registration_epoch.is_string()
    {
        native_worker_json_u64(registration, "authority_epoch")?
    } else if registration_epoch.is_object() {
        serde_json::from_value::<EpochId>(registration_epoch.clone())
            .map_err(|_| NativeWorkerRouteError::Shape {
                field: "authority_epoch",
            })?
            .sequence
            .get()
    } else {
        return Err(NativeWorkerRouteError::Shape {
            field: "authority_epoch",
        });
    };
    if claim_sequence != registration_sequence {
        return Err(NativeWorkerRouteError::Fence {
            field: "epoch_fence",
        });
    }
    Ok(())
}

/// Exact lifecycle binding every heartbeat/checkpoint/result/cancel message
/// must carry (Wave-A `NativeLifecycleBinding` projection).
#[derive(Clone, Debug)]
struct NativeWorkerBindingView {
    claim_id: String,
    attempt_id: String,
    operation_id: String,
    worker_generation: u64,
    route_class: String,
    predecessor_revision: String,
    authority_epoch: u64,
    fence: StateFence,
}

impl NativeWorkerBindingView {
    fn parse(value: &serde_json::Value) -> Result<Self, NativeWorkerRouteError> {
        let binding = value
            .get("binding")
            .filter(|binding| binding.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "binding" })?;
        let fence_value = binding
            .get("state_fence")
            .filter(|fence| fence.is_object())
            .ok_or(NativeWorkerRouteError::Shape {
                field: "binding.state_fence",
            })?;
        let fence: StateFence = serde_json::from_value(fence_value.clone()).map_err(|_| {
            NativeWorkerRouteError::Shape {
                field: "binding.state_fence",
            }
        })?;
        let authority_epoch = native_worker_json_u64(binding, "authority_epoch")?;
        if fence.authority_epoch.sequence.get() != authority_epoch {
            return Err(NativeWorkerRouteError::Fence {
                field: "binding.epoch_fence",
            });
        }
        Ok(Self {
            claim_id: require_op_id(binding, "claim_id")?,
            attempt_id: require_claim_text(binding, "attempt_id")?,
            operation_id: require_claim_text(binding, "operation_id")?,
            worker_generation: require_nonzero_u64(binding, "worker_generation")?,
            route_class: require_claim_text(binding, "route_class")?,
            predecessor_revision: require_claim_text(binding, "predecessor_revision")?,
            authority_epoch,
            fence,
        })
    }
}

// ---------------------------------------------------------------------------
// Durable backends: the ORS claim table through its owning API.
// ---------------------------------------------------------------------------

impl KernelComposition {
    /// Loads one claim record by exact identity. Unknown identities are
    /// `Unknown` (records are never invented here); storage or corruption
    /// failures fence the session fail-closed.
    pub(crate) fn load_claim_record(
        &self,
        claim_id: &str,
    ) -> Result<NativeWorkerClaimRecord, NativeWorkerRouteError> {
        let identity = OperationIdentity::new(claim_id)
            .map_err(|_| NativeWorkerRouteError::Shape { field: "claim_id" })?;
        self.generation_gateway
            .ors
            .load_native_worker_claim(&identity)
            .map_err(|_| NativeWorkerRouteError::Fence { field: "ors_load" })?
            .ok_or_else(|| NativeWorkerRouteError::Unknown {
                identity: claim_id.to_owned(),
            })
    }

    /// Advances one staged claim to its next mechanical state.
    ///
    /// The ORS transition table owns the anti-downgrade fence (`Terminal` is
    /// absorbing, `Unknown` only becomes `Reconciling`, nothing returns to
    /// `Requested`). An illegal step — for example lifecycle work on a
    /// terminal claim — fences; an unknown identity stays unknown; any other
    /// mechanical failure fences. No admission evidence is ever attached
    /// here: only the admission path binds receipts.
    fn advance_claim(
        &self,
        claim_id: &str,
        target: NativeWorkerClaimState,
    ) -> Result<NativeWorkerClaimRecord, NativeWorkerRouteError> {
        let identity = OperationIdentity::new(claim_id)
            .map_err(|_| NativeWorkerRouteError::Shape { field: "claim_id" })?;
        self.generation_gateway
            .ors
            .advance_native_worker_claim(&identity, target, None)
            .map_err(|error| match error {
                OrsError::InvalidTransition => NativeWorkerRouteError::Fence { field: "state" },
                _ => NativeWorkerRouteError::Fence {
                    field: "ors_advance",
                },
            })?
            .ok_or_else(|| NativeWorkerRouteError::Unknown {
                identity: claim_id.to_owned(),
            })
    }

    /// Requires the durable lifecycle state to admit the requested operation.
    fn require_claim_state(
        state: NativeWorkerClaimState,
        allowed: &[NativeWorkerClaimState],
    ) -> Result<(), NativeWorkerRouteError> {
        if allowed.contains(&state) {
            Ok(())
        } else {
            Err(NativeWorkerRouteError::Fence { field: "state" })
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch entry point.
// ---------------------------------------------------------------------------

impl KernelComposition {
    /// Dispatches one native-worker lifecycle frame.
    ///
    /// The caller ([`crate::KernelComposition::dispatch_frame`]) has already
    /// gated service readiness and peer authentication mirroring the Process
    /// gate; those gates are re-checked here so direct callers cannot bypass
    /// them. Unknown or stale generations fence the session, never authority.
    pub(crate) fn dispatch_native_worker_frame(
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
        if !is_native_worker_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        if operation == NATIVE_WORKER_RECONCILE_OPERATION {
            return self.dispatch_native_worker_reconcile(session, frame);
        }
        if operation == NATIVE_WORKER_CANCEL_OBSERVE_OPERATION {
            let (operation_id, session_binding) = self
                .stage_native_worker_cancellation(session, &identity_value, &payload)
                .map_err(NativeWorkerRouteError::into_transport)?;
            return Ok(KernelFrameAction::Process {
                request_id,
                request: ProcessExecutionRequest::Cancel { operation_id },
                session_binding,
            });
        }
        let receipt = match operation {
            NATIVE_WORKER_REGISTRATION_OPERATION => {
                self.handle_native_worker_registration(&identity_value, &payload)
            }
            NATIVE_WORKER_CLAIM_OPERATION => {
                self.handle_native_worker_claim(&identity_value, &payload)
            }
            NATIVE_WORKER_READY_OPERATION => {
                self.handle_native_worker_ready(&identity_value, &payload)
            }
            NATIVE_WORKER_HEARTBEAT_OPERATION => {
                self.handle_native_worker_heartbeat(&identity_value, &payload)
            }
            NATIVE_WORKER_CHECKPOINT_OPERATION => {
                self.handle_native_worker_checkpoint(&identity_value, &payload)
            }
            NATIVE_WORKER_RESULT_SUBMIT_OPERATION => {
                self.handle_native_worker_result(&identity_value, &payload)
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

    /// Requires the frame idempotency key to equal the message's distinct
    /// operation identity, binding replay protection to the exact message.
    pub(crate) fn require_message_identity(
        identity: &serde_json::Value,
        operation_id: &str,
    ) -> Result<(), NativeWorkerRouteError> {
        let key = identity
            .get("idempotency_key")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerRouteError::Shape {
                field: "idempotency_key",
            })?;
        if key != operation_id {
            return Err(NativeWorkerRouteError::Shape {
                field: "idempotency_key",
            });
        }
        Ok(())
    }

    /// Fails with [`NativeWorkerRouteError::ExpiredDeadline`] when the claim's
    /// absolute deadline elapsed before `now`.
    pub(crate) fn require_claim_deadline(
        payload: &serde_json::Value,
        now: u64,
    ) -> Result<u64, NativeWorkerRouteError> {
        let deadline = require_nonzero_u64(payload, "deadline_unix_ms")?;
        if deadline <= now {
            return Err(NativeWorkerRouteError::ExpiredDeadline);
        }
        Ok(deadline)
    }

    /// Validates one registration (or renewal, with a fresh renewal identity).
    pub(crate) fn validate_native_worker_registration(
        payload: &serde_json::Value,
    ) -> Result<(String, u64), NativeWorkerRouteError> {
        let registration_id = require_op_id(payload, "registration_id")?;
        let protocol = payload
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerRouteError::Shape {
                field: "protocol_version",
            })?;
        if protocol != NATIVE_WORKER_PROTOCOL_VERSION {
            return Err(NativeWorkerRouteError::Shape {
                field: "protocol_version",
            });
        }
        if native_worker_json_u16(payload, "execution_unit_schema_version")?
            != NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION
        {
            return Err(NativeWorkerRouteError::Shape {
                field: "execution_unit_schema_version",
            });
        }
        for (field, digest) in [
            (
                "worker_artifact_digest",
                require_digest(payload, "worker_artifact_digest"),
            ),
            (
                "worker_config_digest",
                require_digest(payload, "worker_config_digest"),
            ),
            (
                "process_image_digest",
                require_digest(payload, "process_image_digest"),
            ),
        ] {
            digest.map_err(|_| NativeWorkerRouteError::Shape { field })?;
        }
        for field in [
            "installation_id",
            "principal_ref",
            "connection_id",
            "lease_id",
        ] {
            require_claim_text(payload, field)?;
        }
        require_op_id(payload, "renewal_id")?;
        let worker_generation = require_nonzero_u64(payload, "worker_generation")?;
        require_nonzero_u64(payload, "process_id")?;
        require_nonzero_u64(payload, "process_start_100ns")?;
        require_nonzero_u64(payload, "lease_expires_at_unix_ms")?;
        let limits = payload
            .get("resource_limits")
            .filter(|limits| limits.is_object())
            .ok_or(NativeWorkerRouteError::Shape {
                field: "resource_limits",
            })?;
        for field in ["wall_timeout_ms", "stdout_bytes", "stderr_bytes"] {
            require_nonzero_u64(limits, field)?;
        }
        let invalidations = payload
            .get("invalidation_set")
            .and_then(serde_json::Value::as_array)
            .ok_or(NativeWorkerRouteError::Shape {
                field: "invalidation_set",
            })?;
        if invalidations.len() > MAX_INVALIDATION_ENTRIES {
            return Err(NativeWorkerRouteError::Shape {
                field: "invalidation_set",
            });
        }
        for entry in invalidations {
            let text = entry.as_str().ok_or(NativeWorkerRouteError::Shape {
                field: "invalidation_set",
            })?;
            if text.trim().is_empty()
                || text.chars().any(char::is_control)
                || text.len() > MAX_CLAIM_TEXT_LEN
            {
                return Err(NativeWorkerRouteError::Shape {
                    field: "invalidation_set",
                });
            }
        }
        let fence_value =
            payload
                .get("state_fence")
                .cloned()
                .ok_or(NativeWorkerRouteError::Shape {
                    field: "state_fence",
                })?;
        let fence: StateFence =
            serde_json::from_value(fence_value).map_err(|_| NativeWorkerRouteError::Shape {
                field: "state_fence",
            })?;
        check_authority_epoch_against_fence(payload, "authority_epoch", &fence)?;
        Ok((registration_id, worker_generation))
    }

    /// Admits one registration: validate, Ready-gate, lease check, verdict.
    ///
    /// The verdict is deliberately not a durable row: the ORS owner persists
    /// claims (the unit of admission). The lease is enforced per message
    /// (nonzero expiry strictly in the future, distinct renewal identity);
    /// registration replay detection belongs to a later wave.
    fn handle_native_worker_registration(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let (registration_id, worker_generation) =
            Self::validate_native_worker_registration(payload)?;
        Self::require_message_identity(identity, &registration_id)?;
        if self
            .service_state()
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "service_state",
            })?
            != KernelServiceState::Ready
        {
            return Err(NativeWorkerRouteError::Fence {
                field: "service_state",
            });
        }
        let lease_expires_at_unix_ms = require_nonzero_u64(payload, "lease_expires_at_unix_ms")?;
        if lease_expires_at_unix_ms <= unix_ms() {
            return Err(NativeWorkerRouteError::Fence {
                field: "lease_expires_at_unix_ms",
            });
        }
        seal_route_receipt(serde_json::json!({
            "kind": "native_worker_registration",
            "registration_id": registration_id,
            "worker_generation": worker_generation,
            "lease_expires_at_unix_ms": lease_expires_at_unix_ms,
            "durable": false,
            "decided_at_unix_ms": unix_ms(),
        }))
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })
    }

    /// Validates the closed claim shape: wire, digests, texts, budget, fence.
    ///
    /// Single-shape contour (Implements #22 R2): validates the SAME claim
    /// shape the child submits (`ClaimAdmissionRequest` worker-core halves).
    /// Kernel-service-only envelope fields (`wire_id`, `protocol_version`,
    /// `execution_unit_schema_version`, `installation_id`,
    /// `worker_artifact_digest`, `worker_config_digest`, `request_digest`)
    /// are required when present (old wire) and sourced from the presenting
    /// registration when absent (worker-core single shape, by construction).
    /// Budget, fence, epoch exact-tuple, and v1/v2 executable-join rules run
    /// identically on both contours.
    ///
    /// Both claim-wire revisions parse here (Implements #22): wire v1 carries
    /// no executable join and is refused later at the executable gate with the
    /// typed `u1_old_wire_without_executable_binding` disposition, never
    /// promoted; wire v2 must carry the join (checked in
    /// [`Self::build_single_shape_request`]).
    pub(crate) fn validate_native_worker_claim(
        payload: &serde_json::Value,
    ) -> Result<(String, String, u64), NativeWorkerRouteError> {
        // `wire_id` is required on the old wire and implicit on the single
        // shape (worker-core carries no wire id; the route pins it).
        if let Some(wire) = payload.get("wire_id").and_then(serde_json::Value::as_str) {
            if wire != NATIVE_WORKER_CLAIM_WIRE_ID {
                return Err(NativeWorkerRouteError::Shape { field: "wire" });
            }
        }
        let wire_version = native_worker_json_u16(payload, "wire_version")?;
        if wire_version != NATIVE_WORKER_CLAIM_WIRE_VERSION
            && wire_version != NATIVE_WORKER_CLAIM_WIRE_VERSION_V1
        {
            return Err(NativeWorkerRouteError::Shape { field: "wire" });
        }
        // Protocol/schema pins ride the registration on the single shape;
        // when the claim carries them (old wire) they must agree.
        if let Some(protocol) = payload
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
        {
            if protocol != NATIVE_WORKER_PROTOCOL_VERSION {
                return Err(NativeWorkerRouteError::Shape {
                    field: "protocol_version",
                });
            }
        }
        if let Some(schema) = payload.get("execution_unit_schema_version") {
            let version = native_worker_json_u16(payload, "execution_unit_schema_version")?;
            if version != NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION {
                return Err(NativeWorkerRouteError::Shape {
                    field: "execution_unit_schema_version",
                });
            }
            let _ = schema;
        }
        let claim_id = require_op_id(payload, "claim_id")?;
        for field in [
            "registration_id",
            "parent_job_id",
            "task_id",
            "work_scope_id",
            "decision_id",
            "attempt_id",
            "operation_id",
            "route_class",
            "cancellation_policy_id",
            "expected_result_schema",
            "predecessor_revision",
        ] {
            require_claim_text(payload, field)?;
        }
        // Single-shape optionals: present on the old wire, absent on
        // worker-core (sourced from the registration by construction).
        if payload.get("installation_id").is_some() {
            require_claim_text(payload, "installation_id")?;
        }
        for field in ["worker_artifact_digest", "worker_config_digest"] {
            if payload.get(field).is_some() {
                require_digest(payload, field)?;
            }
        }
        // `binding_digest` is always required (the strongest local anchor);
        // `request_digest` only on the old wire (computed by the single-shape
        // builder).
        require_digest(payload, "binding_digest")?;
        if payload.get("request_digest").is_some() {
            require_digest(payload, "request_digest")?;
        }
        let worker_generation = require_nonzero_u64(payload, "worker_generation")?;
        require_nonzero_u64(payload, "expected_result_schema_version")?;
        let budget = payload
            .get("budget")
            .filter(|budget| budget.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "budget" })?;
        for field in [
            "context_tokens",
            "wall_time_ms",
            "output_bytes",
            "cost_microunits",
            "max_depth",
        ] {
            require_nonzero_u64(budget, field)?;
        }
        let fence_value =
            payload
                .get("state_fence")
                .cloned()
                .ok_or(NativeWorkerRouteError::Shape {
                    field: "state_fence",
                })?;
        let fence: StateFence =
            serde_json::from_value(fence_value).map_err(|_| NativeWorkerRouteError::Shape {
                field: "state_fence",
            })?;
        check_authority_epoch_against_fence(payload, "authority_epoch", &fence)?;
        let binding_digest = require_digest(payload, "binding_digest")?;
        Ok((claim_id, binding_digest, worker_generation))
    }

    /// Locks the Kernel service owner for one admission verdict.
    pub(crate) fn service_guard(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, eliot_kernel_service::KernelService>,
        NativeWorkerRouteError,
    > {
        self.service
            .lock()
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "service_state",
            })
    }

    /// Seals one admission-decision receipt around the service owner's typed
    /// verdict. The top-level echoes let the worker bind the reply to its
    /// exact submission; the `decision` object is the authoritative verdict
    /// (`ADMITTED`, `REJECTED`, or `CONFLICT`). Extra echoes are sealed into
    /// the same digest so they cannot be stripped without detection.
    fn seal_decision(
        kind: &'static str,
        claim_id: &str,
        binding_digest: &str,
        worker_generation: u64,
        extra_echo: &[(&str, &str)],
        decision: &NativeWorkerClaimResponse,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let decision_value = serde_json::to_value(decision)
            .map_err(|_| NativeWorkerRouteError::Shape { field: "decision" })?;
        let mut body = serde_json::json!({
            "kind": kind,
            "claim_id": claim_id,
            "binding_digest": binding_digest,
            "worker_generation": worker_generation,
            "decision": decision_value,
            "decided_at_unix_ms": unix_ms(),
        });
        for (field, echo) in extra_echo {
            body[field] = serde_json::Value::String((*echo).to_owned());
        }
        seal_route_receipt(body).map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })
    }

    /// Builds the typed service request from the single shape the child
    /// submits (Implements #22 R2).
    ///
    /// The child submits `ClaimAdmissionRequest` worker-core halves
    /// (`{claim, registration}` with full `EpochId` objects and no
    /// Kernel-service envelope duplication). The service owner needs the full
    /// `NativeWorkerClaimRequest` (wire id, installation/artifact/config,
    /// protocol/schema, request digest). Those ride the presenting
    /// registration on the single shape and are projected here by
    /// construction; when the claim carries them (old wire) they must equal
    /// the registration (resource binding, checked by the caller). The epoch
    /// accepts both contours (scalar via the fence lineage, object via exact
    /// tuple). Budget, fence, v1/v2 join, and binding rules are the single
    /// enforcement point for both contours; the request digest is computed (it
    /// covers the projected envelope and is not carried on the single shape).
    pub(crate) fn build_single_shape_request(
        claim: &serde_json::Value,
        registration: &serde_json::Value,
    ) -> Result<NativeWorkerClaimRequest, NativeWorkerRouteError> {
        let budget_value = claim
            .get("budget")
            .filter(|budget| budget.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "budget" })?;
        let budget = NativeWorkerClaimBudget {
            context_tokens: require_nonzero_u64(budget_value, "context_tokens")?,
            wall_time_ms: require_nonzero_u64(budget_value, "wall_time_ms")?,
            output_bytes: require_nonzero_u64(budget_value, "output_bytes")?,
            cost_microunits: require_nonzero_u64(budget_value, "cost_microunits")?,
            max_depth: native_worker_json_u16(budget_value, "max_depth").and_then(|depth| {
                if depth == 0 {
                    Err(NativeWorkerRouteError::Shape { field: "max_depth" })
                } else {
                    Ok(depth)
                }
            })?,
            max_descendants: native_worker_json_u32(budget_value, "max_descendants")?,
        };
        let fence_value =
            claim
                .get("state_fence")
                .cloned()
                .ok_or(NativeWorkerRouteError::Shape {
                    field: "state_fence",
                })?;
        let fence: StateFence =
            serde_json::from_value(fence_value).map_err(|_| NativeWorkerRouteError::Shape {
                field: "state_fence",
            })?;
        check_authority_epoch_against_fence(claim, "authority_epoch", &fence)?;
        // Exact-tuple authority: object contour carries the full `EpochId`;
        // scalar contour carries only the sequence (lineage via the fence).
        let authority_epoch = match claim.get("authority_epoch") {
            Some(value) if value.is_object() => {
                serde_json::from_value(value.clone()).map_err(|_| {
                    NativeWorkerRouteError::Shape {
                        field: "authority_epoch",
                    }
                })?
            }
            _ => fence.authority_epoch.clone(),
        };
        let wire_version = native_worker_json_u16(claim, "wire_version")?;
        let executable_binding = match claim.get("executable_binding") {
            None | Some(serde_json::Value::Null) => {
                if wire_version == NATIVE_WORKER_CLAIM_WIRE_VERSION_V1 {
                    None
                } else {
                    return Err(NativeWorkerRouteError::Shape {
                        field: "executable_binding",
                    });
                }
            }
            Some(join_value) => {
                if wire_version == NATIVE_WORKER_CLAIM_WIRE_VERSION_V1 {
                    return Err(NativeWorkerRouteError::Shape {
                        field: "executable_binding",
                    });
                }
                let join: NativeWorkerExecutableBinding =
                    serde_json::from_value(join_value.clone()).map_err(|_| {
                        NativeWorkerRouteError::Shape {
                            field: "executable_binding",
                        }
                    })?;
                Some(join)
            }
        };
        // Wire id: pinned on the single shape, checked on the old wire.
        let wire_id = match claim.get("wire_id").and_then(serde_json::Value::as_str) {
            Some(wire) => {
                if wire != NATIVE_WORKER_CLAIM_WIRE_ID {
                    return Err(NativeWorkerRouteError::Shape { field: "wire" });
                }
                wire.to_owned()
            }
            None => NATIVE_WORKER_CLAIM_WIRE_ID.to_owned(),
        };
        // Resource envelope: projected from the registration on the single
        // shape; on the old wire the claim duplicates it and must agree.
        let installation_id = require_claim_text(registration, "installation_id")?;
        if let Some(presented) = claim
            .get("installation_id")
            .and_then(serde_json::Value::as_str)
        {
            if presented != installation_id {
                return Err(NativeWorkerRouteError::Fence {
                    field: "installation_binding",
                });
            }
        }
        let worker_artifact_digest = require_digest(registration, "worker_artifact_digest")?;
        if let Some(presented) = claim
            .get("worker_artifact_digest")
            .and_then(serde_json::Value::as_str)
        {
            if presented != worker_artifact_digest {
                return Err(NativeWorkerRouteError::Fence {
                    field: "artifact_binding",
                });
            }
        }
        let worker_config_digest = require_digest(registration, "worker_config_digest")?;
        if let Some(presented) = claim
            .get("worker_config_digest")
            .and_then(serde_json::Value::as_str)
        {
            if presented != worker_config_digest {
                return Err(NativeWorkerRouteError::Fence {
                    field: "config_binding",
                });
            }
        }
        let protocol_version = require_claim_text(registration, "protocol_version")?;
        if let Some(presented) = claim
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
        {
            if presented != protocol_version {
                return Err(NativeWorkerRouteError::Shape {
                    field: "protocol_version",
                });
            }
        }
        let execution_unit_schema_version =
            native_worker_json_u16(registration, "execution_unit_schema_version")?;
        if claim.get("execution_unit_schema_version").is_some() {
            let presented = native_worker_json_u16(claim, "execution_unit_schema_version")?;
            if presented != execution_unit_schema_version {
                return Err(NativeWorkerRouteError::Shape {
                    field: "execution_unit_schema_version",
                });
            }
        }
        let mut request = NativeWorkerClaimRequest {
            wire_id,
            wire_version,
            claim_id: require_op_id(claim, "claim_id")?,
            registration_id: require_op_id(claim, "registration_id")?,
            worker_generation: require_nonzero_u64(claim, "worker_generation")?,
            installation_id,
            worker_artifact_digest,
            worker_config_digest,
            protocol_version,
            execution_unit_schema_version,
            parent_job_id: require_claim_text(claim, "parent_job_id")?,
            task_id: require_claim_text(claim, "task_id")?,
            work_scope_id: require_claim_text(claim, "work_scope_id")?,
            decision_id: require_claim_text(claim, "decision_id")?,
            attempt_id: require_claim_text(claim, "attempt_id")?,
            operation_id: require_claim_text(claim, "operation_id")?,
            route_class: require_claim_text(claim, "route_class")?,
            budget,
            deadline_unix_ms: require_nonzero_u64(claim, "deadline_unix_ms")?,
            cancellation_policy_id: require_claim_text(claim, "cancellation_policy_id")?,
            expected_result_schema: require_claim_text(claim, "expected_result_schema")?,
            expected_result_schema_version: native_worker_json_u16(
                claim,
                "expected_result_schema_version",
            )?,
            predecessor_revision: require_claim_text(claim, "predecessor_revision")?,
            authority_epoch,
            state_fence: fence,
            executable_binding,
            binding_digest: require_digest(claim, "binding_digest")?,
            request_digest: String::new(),
        };
        let computed =
            request
                .canonical_request_digest()
                .map_err(|_| NativeWorkerRouteError::Shape {
                    field: "request_digest",
                })?;
        // Old wire carries its own envelope digest: it must equal the
        // recomputed canonical digest, otherwise a tampered presentation
        // fails here before any owner sees it.
        if let Some(presented) = claim
            .get("request_digest")
            .and_then(serde_json::Value::as_str)
        {
            if presented != computed {
                return Err(NativeWorkerRouteError::Shape {
                    field: "request_digest",
                });
            }
        }
        request.request_digest = computed;
        Ok(request)
    }

    /// Builds the current owner-record expectation for the executable gate.
    ///
    /// The owner-produced executable fields ride the presented v2 join (the
    /// only owner-record carrier in these paths; tamper-evident through the
    /// claim binding digest the gate recomputes). Every currentness anchor
    /// comes from a live record, never from caller strings: the admitted
    /// worker-configuration identity from the presenting registration record,
    /// the generation and immutable fence from the validated registration
    /// fence, and the authority epoch from the live service epoch record
    /// (compared inside the gate via `is_same_authority`, never by raw
    /// sequence). `revoked` stays false: no revocation feed exists in these
    /// paths, so withdrawal is observed only as digest/currentness
    /// disagreement (a Governor revocation feed belongs to a later wave).
    ///
    /// Wire v1 carries no owner record: the anchors below still come from the
    /// same live records while the owner-produced strings stay empty by
    /// construction. Those placeholders are never inspected — the real gate
    /// refuses old wire first with typed
    /// `u1_old_wire_without_executable_binding` — and exist only so the
    /// refusal is the service owner's typed disposition instead of a local
    /// invention.
    pub(crate) fn build_executable_expectation(
        presented: Option<&NativeWorkerExecutableBinding>,
        registration: &serde_json::Value,
        registration_fence: &StateFence,
        live_epoch: &EpochId,
    ) -> Result<NativeWorkerExecutableExpectation, NativeWorkerRouteError> {
        let config_digest = require_digest(registration, "worker_config_digest")?;
        let current = match presented {
            Some(join) => NativeWorkerExecutableBinding {
                route_ref: join.route_ref.clone(),
                adapter_id: join.adapter_id.clone(),
                adapter_revision: join.adapter_revision,
                config_digest,
                facet_manifest_ref: join.facet_manifest_ref.clone(),
                grant_graph_revision: join.grant_graph_revision,
                replay_stream_id: join.replay_stream_id.clone(),
                launch_nonce: join.launch_nonce.clone(),
                process_invocation_digest: join.process_invocation_digest.clone(),
                authority_epoch: live_epoch.clone(),
                generation: registration_fence.resource_generation,
                state_fence: registration_fence.clone(),
                deadline_unix_ms: join.deadline_unix_ms,
                expires_at_unix_ms: join.expires_at_unix_ms,
                executable_wire_version: join.executable_wire_version,
                executable_binding_digest: join.executable_binding_digest.clone(),
            },
            None => NativeWorkerExecutableBinding {
                route_ref: String::new(),
                adapter_id: String::new(),
                adapter_revision: 0,
                config_digest,
                facet_manifest_ref: String::new(),
                grant_graph_revision: 0,
                replay_stream_id: String::new(),
                launch_nonce: String::new(),
                process_invocation_digest: String::new(),
                authority_epoch: live_epoch.clone(),
                generation: registration_fence.resource_generation,
                state_fence: registration_fence.clone(),
                deadline_unix_ms: 0,
                expires_at_unix_ms: 0,
                executable_wire_version: NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
                executable_binding_digest: String::new(),
            },
        };
        Ok(NativeWorkerExecutableExpectation {
            current,
            revoked: false,
        })
    }

    /// Runs the real executable gate and maps its verdict into route vocabulary.
    ///
    /// No new stage is invented: malformed or old-wire presentations are
    /// `Shape` (fail closed as `SessionFenced`); a changed route, adapter,
    /// config, facet, grant, nonce, stream, invocation digest, owner digest,
    /// or withdrawn binding under the known claim identity is `Conflict`
    /// (`IdentityConflict`, mirroring the reconcile-route identity semantics);
    /// epoch, generation, or fence disagreement is `Fence` (`SessionFenced`);
    /// an elapsed binding window is `ExpiredDeadline` (`Timeout`).
    pub(crate) fn enforce_claim_executable_binding(
        request: &NativeWorkerClaimRequest,
        expectation: &NativeWorkerExecutableExpectation,
        now: u64,
    ) -> Result<(), NativeWorkerRouteError> {
        request
            .require_executable_binding(expectation, now)
            .map_err(|error| {
                let presented_digest = request
                    .executable_binding
                    .as_ref()
                    .map(|join| join.executable_binding_digest.as_str())
                    .unwrap_or_default();
                Self::map_executable_error(
                    &error,
                    &request.claim_id,
                    presented_digest,
                    &expectation.current.executable_binding_digest,
                )
            })
    }

    /// Maps one executable-gate failure into the existing route vocabulary.
    fn map_executable_error(
        error: &KernelServiceError,
        claim_id: &str,
        presented_digest: &str,
        current_digest: &str,
    ) -> NativeWorkerRouteError {
        match error {
            KernelServiceError::InvalidField { .. } => NativeWorkerRouteError::Shape {
                field: "executable_binding",
            },
            KernelServiceError::HandshakeMismatch { field } if field.ends_with(".expired") => {
                NativeWorkerRouteError::ExpiredDeadline
            }
            KernelServiceError::HandshakeMismatch { field }
                if field.ends_with(".route_ref")
                    || field.ends_with(".adapter")
                    || field.ends_with(".config_digest")
                    || field.ends_with(".facet_manifest_ref")
                    || field.ends_with(".grant_graph_revision")
                    || field.ends_with(".replay_stream_id")
                    || field.ends_with(".launch_nonce")
                    || field.ends_with(".process_invocation_digest")
                    || field.ends_with(".executable_binding_digest")
                    || field.ends_with(".executable_wire_version")
                    || *field == "native_worker_claim.executable_binding_revoked" =>
            {
                let changed = field
                    .strip_prefix("native_worker_claim.")
                    .unwrap_or(field)
                    .to_owned();
                NativeWorkerRouteError::Conflict(NativeWorkerRouteConflict {
                    identity: claim_id.to_owned(),
                    expected_digest: current_digest.to_owned(),
                    observed_digest: presented_digest.to_owned(),
                    changed_fields: vec![changed],
                })
            }
            _ => NativeWorkerRouteError::Fence {
                field: "executable_binding",
            },
        }
    }

    /// Splits one claim presentation into its claim and registration halves
    /// and checks their cross-binding exactly as the worker-side
    /// `ClaimAdmissionRequest::validate_binding` does: same registration,
    /// same generation, same epoch, same fence. A claim rewired onto a
    /// different registration fails here before any owner sees it.
    pub(crate) fn split_claim_presentation(
        payload: &serde_json::Value,
    ) -> Result<(&serde_json::Value, &serde_json::Value), NativeWorkerRouteError> {
        let claim = payload
            .get("claim")
            .filter(|claim| claim.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "claim" })?;
        let registration = payload
            .get("registration")
            .filter(|registration| registration.is_object())
            .ok_or(NativeWorkerRouteError::Shape {
                field: "registration",
            })?;
        if require_op_id(claim, "registration_id")?
            != require_op_id(registration, "registration_id")?
        {
            return Err(NativeWorkerRouteError::Shape {
                field: "registration_binding",
            });
        }
        if require_nonzero_u64(claim, "worker_generation")?
            != require_nonzero_u64(registration, "worker_generation")?
        {
            return Err(NativeWorkerRouteError::Shape {
                field: "generation_binding",
            });
        }
        check_split_epoch_agreement(claim, registration)?;
        if claim.get("state_fence") != registration.get("state_fence") {
            return Err(NativeWorkerRouteError::Fence {
                field: "state_fence",
            });
        }
        Ok((claim, registration))
    }

    /// Requires the claim's worker resource identity to exactly match its
    /// presenting registration.
    ///
    /// The split above binds registration identity, generation, epoch, and
    /// fence. This binds the resource envelope the service owner persists as
    /// an opaque digest: installation, artifact, and configuration identity.
    /// A claim rewired onto a foreign worker generation fails here before any
    /// owner stages it, so fresh work is never admitted merely because its
    /// digest shape is well-formed.
    ///
    /// Single-shape (R2): the worker-core claim carries no resource envelope
    /// (installation/artifact/config live only in the registration and are
    /// projected into the service request by construction). When the claim
    /// omits them, there is nothing to rewire, so the binding holds by
    /// construction after the registration shape check; when the claim
    /// carries them (old wire) they must equal the registration.
    pub(crate) fn require_claim_registration_resource_binding(
        claim: &serde_json::Value,
        registration: &serde_json::Value,
    ) -> Result<(), NativeWorkerRouteError> {
        // Installation: required on old wire, implicit on single shape.
        if claim.get("installation_id").is_some() || registration.get("installation_id").is_some() {
            let claim_installation = claim
                .get("installation_id")
                .and_then(serde_json::Value::as_str);
            let registration_installation = registration
                .get("installation_id")
                .and_then(serde_json::Value::as_str);
            match (claim_installation, registration_installation) {
                (Some(left), Some(right)) => {
                    if require_claim_text(claim, "installation_id")?
                        != require_claim_text(registration, "installation_id")?
                    {
                        let _ = (left, right);
                        return Err(NativeWorkerRouteError::Fence {
                            field: "installation_binding",
                        });
                    }
                }
                (None, None) => {}
                // Single shape: claim omits the envelope by construction.
                (None, Some(_)) => {}
                (Some(_), None) => {
                    return Err(NativeWorkerRouteError::Fence {
                        field: "installation_binding",
                    });
                }
            }
        }
        for (field, fence_field) in [
            ("worker_artifact_digest", "artifact_binding"),
            ("worker_config_digest", "config_binding"),
        ] {
            match (claim.get(field), registration.get(field)) {
                (Some(_), Some(_)) => {
                    if require_digest(claim, field)? != require_digest(registration, field)? {
                        return Err(NativeWorkerRouteError::Fence { field: fence_field });
                    }
                }
                (None, None) => {}
                // Single shape: claim omits the envelope by construction.
                (None, Some(_)) => {}
                (Some(_), None) => {
                    return Err(NativeWorkerRouteError::Fence { field: fence_field });
                }
            }
        }
        Ok(())
    }

    /// Computes the canonical fence digest for one presenting fence.
    ///
    /// Uses the same canonical JSON procedure the service owner uses for the
    /// durable `fence_digest`, so a retained receipt presented under a
    /// different fence fails the equality check in [`Self::load_and_bind`]
    /// even when the epoch value alone still matches.
    pub(crate) fn presenting_fence_digest(
        fence: &StateFence,
    ) -> Result<String, NativeWorkerRouteError> {
        canonical_json_bytes(fence)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "state_fence",
            })
    }

    /// Validates that credential references carry only provider/key references.
    ///
    /// Each entry must be exactly `{ "provider", "key" }`: two bounded
    /// reference texts and no other key. Any extra key — including a
    /// `secret`, `value`, `bytes`, or `material` field — fails closed so
    /// secret material can never smuggle through a reference list into a
    /// receipt or log.
    pub(crate) fn validate_credential_refs_shape(
        refs: &[serde_json::Value],
    ) -> Result<(), NativeWorkerRouteError> {
        if refs.len() > MAX_CREDENTIAL_REFERENCES {
            return Err(NativeWorkerRouteError::Shape {
                field: "credential_refs",
            });
        }
        for reference in refs {
            let object = reference.as_object().ok_or(NativeWorkerRouteError::Shape {
                field: "credential_refs",
            })?;
            if object.len() != 2 || !object.contains_key("provider") || !object.contains_key("key")
            {
                return Err(NativeWorkerRouteError::Shape {
                    field: "credential_refs",
                });
            }
            require_claim_text(reference, "provider")?;
            require_claim_text(reference, "key")?;
        }
        Ok(())
    }

    /// Admits one claim: validate, deadline, typed service admission, receipt.
    ///
    /// Persistence happens inside the service owner's
    /// `admit_native_worker_claim` (persist-before-ack): an exact replay
    /// returns the stored receipt unchanged, and a changed binding under the
    /// same claim identity returns `CONFLICT` and takes no effect.
    ///
    /// The presenting registration is validated as a live registration here
    /// (shape, future lease, resource-identity agreement with the claim) so
    /// a stale or foreign registration cannot sponsor a claim, even when the
    /// claim half alone is shape-valid. Admission itself stays with the typed
    /// service owner; this route never fabricates persistence or a receipt,
    /// and never mints a `ProcessRequest`, permit, or grant: the only
    /// `ProcessExecutionRequest` in this file is the existing #100 `Cancel`
    /// path owned by `stage_native_worker_cancellation`.
    fn handle_native_worker_claim(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let (claim, registration) = Self::split_claim_presentation(payload)?;
        Self::validate_native_worker_registration(registration)?;
        let now = unix_ms();
        let lease_expires_at_unix_ms =
            require_nonzero_u64(registration, "lease_expires_at_unix_ms")?;
        if lease_expires_at_unix_ms <= now {
            return Err(NativeWorkerRouteError::Fence {
                field: "lease_expires_at_unix_ms",
            });
        }
        Self::require_claim_registration_resource_binding(claim, registration)?;
        let (claim_id, binding_digest, worker_generation) =
            Self::validate_native_worker_claim(claim)?;
        Self::require_message_identity(identity, &claim_id)?;
        Self::require_claim_deadline(claim, now)?;
        // Single-shape unification (R2, Implements #22): the request projects
        // the registration envelope (wire/installation/artifact/protocol/
        // schema) by construction, so the SAME worker-core halves the child
        // submits admit here at claim and at ready. There is no second
        // builder: every contour builds through the single-shape projector.
        let request = Self::build_single_shape_request(claim, registration)?;
        // Registration epoch must match its fence tuple exactly on both
        // contours (scalar via sequence, object via exact tuple).
        let registration_fence: StateFence =
            serde_json::from_value(registration.get("state_fence").cloned().ok_or(
                NativeWorkerRouteError::Shape {
                    field: "state_fence",
                },
            )?)
            .map_err(|_| NativeWorkerRouteError::Shape {
                field: "state_fence",
            })?;
        check_authority_epoch_against_fence(registration, "authority_epoch", &registration_fence)?;
        request
            .validate_presented_under_registration(
                &require_op_id(registration, "registration_id")?,
                require_nonzero_u64(registration, "worker_generation")?,
                registration_fence.authority_epoch.clone(),
                &registration_fence,
            )
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "registration_binding",
            })?;
        let service = self.service_guard()?;
        let live_epoch = service.authority_epoch();
        let decision = service
            .admit_native_worker_claim(self.generation_gateway.ors.as_ref(), &request, now)
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "service_state",
            })?;
        // T9-02 executable enforcement (Implements #22): an `Admitted`
        // decision carries no launch authority until the presented v2 join
        // agrees with the current owner record built from the live
        // registration, admission, activation, and epoch records above. A
        // stale or old-wire binding is a typed reject here — `ADMITTED` is
        // never emitted — while `Rejected`/`Conflict` decisions seal
        // unchanged below.
        if matches!(decision, NativeWorkerClaimResponse::Admitted(_)) {
            let expectation = Self::build_executable_expectation(
                request.executable_binding.as_ref(),
                registration,
                &registration_fence,
                &live_epoch,
            )?;
            Self::enforce_claim_executable_binding(&request, &expectation, now)?;
        }
        // The sealed executable digest lets later reconcile observe the exact
        // binding this admission sealed (kind `native_worker_claim` only).
        let executable_echo = request
            .executable_binding
            .as_ref()
            .map(|join| join.executable_binding_digest.clone());
        let extra_echo: Vec<(&str, &str)> = match executable_echo.as_deref() {
            Some(digest) => vec![("executable_binding_digest", digest)],
            None => Vec::new(),
        };
        Self::seal_decision(
            "native_worker_claim",
            &claim_id,
            &binding_digest,
            worker_generation,
            &extra_echo,
            &decision,
        )
    }

    /// Validates one ready-or-blocked submission against its admitted claim.
    fn validate_native_worker_readiness(
        payload: &serde_json::Value,
        now: u64,
    ) -> Result<(String, String, String, u64), NativeWorkerRouteError> {
        let claim = payload
            .get("claim")
            .filter(|claim| claim.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "claim" })?;
        let (claim_id, binding_digest, worker_generation) =
            Self::validate_native_worker_claim(claim)?;
        // Readiness operates on emitted-`ADMITTED` claims only (Implements
        // #22): the claim gate refuses wire v1 before any `ADMITTED` receipt
        // is emitted, so a readiness submission must carry the v2 join. This
        // keeps a refused-but-staged v1 row from ever advancing to `Ready`.
        if native_worker_json_u16(claim, "wire_version")? != NATIVE_WORKER_CLAIM_WIRE_VERSION {
            return Err(NativeWorkerRouteError::Shape { field: "wire" });
        }
        let readiness = payload
            .get("readiness")
            .filter(|readiness| readiness.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "readiness" })?;
        let kind = readiness
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerRouteError::Shape {
                field: "readiness.kind",
            })?;
        let report = readiness
            .get("payload")
            .filter(|report| report.is_object())
            .ok_or(NativeWorkerRouteError::Shape {
                field: "readiness.payload",
            })?;
        let ready_id = require_op_id(report, "ready_id")?;
        if require_op_id(report, "claim_id")? != claim_id
            || require_op_id(report, "registration_id")?
                != require_claim_text(claim, "registration_id")?
        {
            return Err(NativeWorkerRouteError::Shape {
                field: "claim_binding",
            });
        }
        if require_nonzero_u64(report, "worker_generation")? != worker_generation {
            return Err(NativeWorkerRouteError::Shape {
                field: "generation_binding",
            });
        }
        // Single-shape (R2, Implements #22): the report and claim epochs
        // accept both contours (scalar sequence or full `EpochId` object).
        // Each side must agree with its own fence exactly as the claim path
        // proves it (`check_authority_epoch_against_fence`: scalar via the
        // fence lineage, object via exact tuple); the fence equality below
        // then binds both sides together, so a mixed-representation replay
        // with a matching sequence still fails closed on lineage.
        let report_fence: StateFence = report
            .get("state_fence")
            .cloned()
            .and_then(|fence| serde_json::from_value(fence).ok())
            .ok_or(NativeWorkerRouteError::Shape {
                field: "state_fence",
            })?;
        let claim_fence: StateFence = claim
            .get("state_fence")
            .cloned()
            .and_then(|fence| serde_json::from_value(fence).ok())
            .ok_or(NativeWorkerRouteError::Shape {
                field: "state_fence",
            })?;
        check_authority_epoch_against_fence(report, "authority_epoch", &report_fence)?;
        check_authority_epoch_against_fence(claim, "authority_epoch", &claim_fence)?;
        if report_fence != claim_fence {
            return Err(NativeWorkerRouteError::Fence {
                field: "state_fence",
            });
        }
        if require_digest(report, "claim_binding_digest")? != binding_digest {
            return Err(NativeWorkerRouteError::Shape {
                field: "claim_binding",
            });
        }
        match kind {
            "READY" => Self::validate_ready_report_content(report, claim, now)?,
            "BLOCKED" => Self::validate_blocked_report_content(report)?,
            _ => {
                return Err(NativeWorkerRouteError::Shape {
                    field: "readiness.kind",
                });
            }
        }
        Ok((ready_id, claim_id, binding_digest, worker_generation))
    }

    /// Validates the content of one `READY` report: registry revision,
    /// credential references, and a live deadline.
    ///
    /// Credential entries are references only (`provider` + `key`); any extra
    /// key fails closed so secret bytes can never smuggle through the
    /// reference list into a receipt or log.
    fn validate_ready_report_content(
        report: &serde_json::Value,
        claim: &serde_json::Value,
        now: u64,
    ) -> Result<(), NativeWorkerRouteError> {
        require_claim_text(report, "adapter_registry_revision")?;
        let refs = report
            .get("credential_refs")
            .and_then(serde_json::Value::as_array)
            .ok_or(NativeWorkerRouteError::Shape {
                field: "credential_refs",
            })?;
        Self::validate_credential_refs_shape(refs)?;
        let ready_at = require_nonzero_u64(report, "ready_at_unix_ms")?;
        let deadline = require_nonzero_u64(claim, "deadline_unix_ms")?;
        if now == 0 || deadline <= now || ready_at > deadline {
            return Err(NativeWorkerRouteError::ExpiredDeadline);
        }
        Ok(())
    }

    /// Validates the content of one `BLOCKED` report: a known blocking
    /// dimension, a bounded reason, and an observation time.
    fn validate_blocked_report_content(
        report: &serde_json::Value,
    ) -> Result<(), NativeWorkerRouteError> {
        let dimension = report
            .get("dimension")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerRouteError::Shape { field: "dimension" })?;
        if !matches!(
            dimension,
            "GENERATION"
                | "CLAIM_BINDING"
                | "RESOURCES"
                | "ADAPTER_REGISTRY"
                | "CREDENTIALS"
                | "DEADLINE"
                | "FENCE"
        ) {
            return Err(NativeWorkerRouteError::Shape { field: "dimension" });
        }
        require_claim_text(report, "reason")?;
        require_nonzero_u64(report, "observed_at_unix_ms")?;
        Ok(())
    }

    /// Records one readiness verdict: validate, typed Ready-gate, receipt.
    ///
    /// Transport health alone satisfies nothing here: the submission must bind
    /// the exact generation, claim digest, registry revision, credential
    /// references, deadline, and fence. A `READY` verdict goes through the
    /// service owner's `mark_native_worker_ready` (gated on the persisted
    /// `Admitted` record); a `BLOCKED` verdict is a validated observation
    /// that changes no durable state, so a blocked unit can never become
    /// ready by mistake.
    fn handle_native_worker_ready(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let now = unix_ms();
        let (ready_id, claim_id, binding_digest, worker_generation) =
            Self::validate_native_worker_readiness(payload, now)?;
        Self::require_message_identity(identity, &ready_id)?;
        let readiness = payload
            .get("readiness")
            .filter(|readiness| readiness.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "readiness" })?;
        let kind = readiness
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerRouteError::Shape {
                field: "readiness.kind",
            })?;
        if kind == "BLOCKED" {
            let report = readiness.get("payload").cloned().unwrap_or_default();
            let dimension = report
                .get("dimension")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let reason = report
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            return seal_route_receipt(serde_json::json!({
                "kind": "native_worker_blocked",
                "ready_id": ready_id,
                "claim_id": claim_id,
                "binding_digest": binding_digest,
                "worker_generation": worker_generation,
                "dimension": dimension,
                "reason": reason,
                "decided_at_unix_ms": now,
            }))
            .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" });
        }
        let claim = payload
            .get("claim")
            .filter(|claim| claim.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "claim" })?;
        // Single-shape (R2, Implements #22): the readiness presentation
        // must carry its presenting registration (`{claim, registration,
        // readiness}` — the same worker-core halves the child submits at
        // claim time). The request always builds through the single-shape
        // projector, so the SAME shape admits at claim and ready; a
        // registration-less presentation fails closed (there is no legacy
        // contour anymore and no second builder to fall back to).
        let registration = payload
            .get("registration")
            .filter(|registration| registration.is_object())
            .ok_or(NativeWorkerRouteError::Shape {
                field: "registration",
            })?;
        Self::validate_native_worker_registration(registration)?;
        Self::require_claim_registration_resource_binding(claim, registration)?;
        let request = Self::build_single_shape_request(claim, registration)?;
        let report = readiness.get("payload").cloned().unwrap_or_default();
        let ready_registration_id = require_op_id(&report, "registration_id")?;
        let ready_worker_generation = require_nonzero_u64(&report, "worker_generation")?;
        let adapter_registry_revision = require_claim_text(&report, "adapter_registry_revision")?;
        let refs_value = report
            .get("credential_refs")
            .and_then(serde_json::Value::as_array)
            .ok_or(NativeWorkerRouteError::Shape {
                field: "credential_refs",
            })?;
        let mut owned_refs: Vec<(String, String)> = Vec::with_capacity(refs_value.len());
        for reference in refs_value {
            owned_refs.push((
                require_claim_text(reference, "provider")?,
                require_claim_text(reference, "key")?,
            ));
        }
        let borrowed_refs: Vec<(&str, &str)> = owned_refs
            .iter()
            .map(|(provider, key)| (provider.as_str(), key.as_str()))
            .collect();
        let ready_at_unix_ms = require_nonzero_u64(&report, "ready_at_unix_ms")?;
        let service = self.service_guard()?;
        let decision = service
            .mark_native_worker_ready(
                self.generation_gateway.ors.as_ref(),
                &request,
                &ready_id,
                &ready_registration_id,
                ready_worker_generation,
                &adapter_registry_revision,
                &borrowed_refs,
                ready_at_unix_ms,
                now,
            )
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "service_state",
            })?;
        Self::seal_decision(
            "native_worker_ready",
            &claim_id,
            &binding_digest,
            worker_generation,
            &[("ready_id", ready_id.as_str())],
            &decision,
        )
    }

    /// Loads the staged claim record and checks the presenting binding.
    ///
    /// Unknown identities are `Unknown`; stale generations and epochs are
    /// `Fence` (never authority); changed bound work under a known identity
    /// is `Conflict`. The immutable fence itself was fixed at admission (the
    /// record carries its digest and the service owner re-checked agreement
    /// there); here the presenting fence must still agree with the session
    /// fence (enforced at dispatch), the epoch it carries, and the durable
    /// fence digest, so a retained receipt presented under a different fence
    /// is fenced even when the epoch value alone still matches.
    fn load_and_bind(
        &self,
        binding: &NativeWorkerBindingView,
    ) -> Result<NativeWorkerClaimRecord, NativeWorkerRouteError> {
        let staged = self.load_claim_record(&binding.claim_id)?;
        if staged.worker_generation == 0 || staged.worker_generation != binding.worker_generation {
            return Err(NativeWorkerRouteError::Fence {
                field: "worker_generation",
            });
        }
        if staged.authority_epoch != binding.authority_epoch {
            return Err(NativeWorkerRouteError::Fence {
                field: "authority_epoch",
            });
        }
        if binding.fence.authority_epoch.sequence.get() != binding.authority_epoch {
            return Err(NativeWorkerRouteError::Fence {
                field: "epoch_fence",
            });
        }
        if Self::presenting_fence_digest(&binding.fence)? != staged.fence_digest {
            return Err(NativeWorkerRouteError::Fence {
                field: "state_fence",
            });
        }
        let mut changed: Vec<String> = Vec::new();
        for (field, staged_text, presented) in [
            (
                "attempt_id",
                staged.attempt_id.as_str(),
                binding.attempt_id.as_str(),
            ),
            (
                "operation_id",
                staged.operation_id.as_str(),
                binding.operation_id.as_str(),
            ),
            (
                "route_class",
                staged.route_class.as_str(),
                binding.route_class.as_str(),
            ),
            (
                "predecessor_revision",
                staged.predecessor_revision.as_str(),
                binding.predecessor_revision.as_str(),
            ),
        ] {
            if staged_text != presented {
                changed.push(field.to_owned());
            }
        }
        if !changed.is_empty() {
            if changed.len() > MAX_CONFLICT_FIELDS {
                return Err(NativeWorkerRouteError::Shape {
                    field: "changed_fields",
                });
            }
            return Err(NativeWorkerRouteError::Conflict(
                NativeWorkerRouteConflict {
                    identity: binding.claim_id.clone(),
                    expected_digest: staged.binding_digest.clone(),
                    observed_digest: String::new(),
                    changed_fields: changed,
                },
            ));
        }
        Ok(staged)
    }

    /// Observes liveness: validate, bind, and return a liveness receipt only.
    ///
    /// This path performs no service-gate mutation, no ORS advance, and no
    /// staging. It cannot create progress, success, authority, or completion.
    fn handle_native_worker_heartbeat(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let heartbeat_id = require_op_id(payload, "heartbeat_id")?;
        Self::require_message_identity(identity, &heartbeat_id)?;
        let observed_at = require_nonzero_u64(payload, "observed_at_unix_ms")?;
        let binding = NativeWorkerBindingView::parse(payload)?;
        let staged = self.load_and_bind(&binding)?;
        Self::require_claim_state(
            staged.state,
            &[
                NativeWorkerClaimState::Ready,
                NativeWorkerClaimState::Active,
            ],
        )?;
        let receipt = NativeWorkerLivenessReceipt::seal(
            &heartbeat_id,
            &binding.claim_id,
            binding.worker_generation,
            observed_at,
        )
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })?;
        Ok(receipt)
    }

    /// Stores one checkpoint: validate, bind, advance to active, receipt.
    ///
    /// A checkpoint attests live execution, so a `Ready` claim becomes
    /// `Active` (idempotent on `Active`). The checkpoint reference itself is
    /// echoed in the observation receipt; the durable claim row carries the
    /// lifecycle proof and Wave D reconciles it.
    fn handle_native_worker_checkpoint(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let checkpoint_id = require_op_id(payload, "checkpoint_id")?;
        Self::require_message_identity(identity, &checkpoint_id)?;
        let checkpoint_ref = require_claim_text(payload, "checkpoint_ref")?;
        let observed_at = require_nonzero_u64(payload, "observed_at_unix_ms")?;
        let binding = NativeWorkerBindingView::parse(payload)?;
        let staged = self.load_and_bind(&binding)?;
        Self::require_claim_state(
            staged.state,
            &[
                NativeWorkerClaimState::Ready,
                NativeWorkerClaimState::Active,
            ],
        )?;
        let receipt = seal_route_receipt(serde_json::json!({
            "kind": "native_worker_checkpoint",
            "checkpoint_id": checkpoint_id,
            "claim_id": binding.claim_id,
            "checkpoint_ref": checkpoint_ref,
            "worker_generation": binding.worker_generation,
            "observed_at_unix_ms": observed_at,
        }))
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })?;
        self.advance_claim(&binding.claim_id, NativeWorkerClaimState::Active)?;
        Ok(receipt)
    }

    /// Submits one result digest: validate, bind, schema-match, advance.
    ///
    /// Submission is not acceptance: the result is staged under the original
    /// claim and reconciled by Wave D before any reclaim or retry. The
    /// presented claim must digest-equal the admitted binding, which proves
    /// the submitted schema is the admitted schema without storing a second
    /// copy of it. A `Ready` claim passes through `Active` (the submission
    /// attests activity); a `Cancelling` claim keeps its submitted work.
    fn handle_native_worker_result(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let result_id = require_op_id(payload, "result_id")?;
        Self::require_message_identity(identity, &result_id)?;
        let result_schema = require_claim_text(payload, "result_schema")?;
        let result_schema_version = native_worker_json_u16(payload, "result_schema_version")?;
        let result_digest = require_digest(payload, "result_digest")?;
        let submitted_at = require_nonzero_u64(payload, "submitted_at_unix_ms")?;
        let binding = NativeWorkerBindingView::parse(payload)?;
        let staged = self.load_and_bind(&binding)?;
        Self::require_claim_state(
            staged.state,
            &[
                NativeWorkerClaimState::Ready,
                NativeWorkerClaimState::Active,
                NativeWorkerClaimState::Cancelling,
            ],
        )?;
        let presented = payload
            .get("claim")
            .filter(|claim| claim.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "claim" })?;
        let presented_digest = require_digest(presented, "binding_digest")?;
        if presented_digest != staged.binding_digest {
            return Err(NativeWorkerRouteError::Conflict(
                NativeWorkerRouteConflict {
                    identity: binding.claim_id.clone(),
                    expected_digest: staged.binding_digest.clone(),
                    observed_digest: presented_digest,
                    changed_fields: vec!["binding_digest".to_owned()],
                },
            ));
        }
        if require_claim_text(presented, "expected_result_schema")? != result_schema
            || native_worker_json_u16(presented, "expected_result_schema_version")?
                != result_schema_version
        {
            return Err(NativeWorkerRouteError::Conflict(
                NativeWorkerRouteConflict {
                    identity: binding.claim_id.clone(),
                    expected_digest: staged.binding_digest.clone(),
                    observed_digest: result_digest.clone(),
                    changed_fields: vec!["expected_result_schema".to_owned()],
                },
            ));
        }
        if staged.deadline_unix_ms == 0
            || staged.deadline_unix_ms <= unix_ms()
            || submitted_at > staged.deadline_unix_ms
        {
            return Err(NativeWorkerRouteError::ExpiredDeadline);
        }
        let receipt = seal_route_receipt(serde_json::json!({
            "kind": "native_worker_result",
            "result_id": result_id,
            "claim_id": binding.claim_id,
            "result_schema": result_schema,
            "result_schema_version": result_schema_version,
            "result_digest": result_digest,
            "worker_generation": binding.worker_generation,
            "submitted_at_unix_ms": submitted_at,
        }))
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })?;
        if staged.state == NativeWorkerClaimState::Ready {
            self.advance_claim(&binding.claim_id, NativeWorkerClaimState::Active)?;
        }
        self.advance_claim(&binding.claim_id, NativeWorkerClaimState::Submitted)?;
        Ok(receipt)
    }

    /// Stages one cancellation observation and returns the exact operation to
    /// fence through the #100 process-execution path.
    ///
    /// New provider effects stop at the staged `cancelling` transition;
    /// possible work/result state is preserved on the staged record for
    /// reconciliation instead of being discarded. A claim that already
    /// submitted its result keeps the `Submitted` row (the result belongs to
    /// Wave-D reconciliation) while the attempt's execution is still fenced
    /// through the returned `Cancel` operation.
    fn stage_native_worker_cancellation(
        &self,
        session: &Session,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<(OperationId, super::ProcessSessionBinding), NativeWorkerRouteError> {
        let cancellation_id = require_op_id(payload, "cancellation_id")?;
        Self::require_message_identity(identity, &cancellation_id)?;
        require_claim_text(payload, "reason")?;
        require_nonzero_u64(payload, "observed_at_unix_ms")?;
        let binding = NativeWorkerBindingView::parse(payload)?;
        let staged = self.load_and_bind(&binding)?;
        if staged.state == NativeWorkerClaimState::Submitted {
            // A submitted result is preserved for Wave-D reconciliation; the
            // attempt's execution is still fenced through the `Cancel`
            // operation returned below.
        } else {
            Self::require_claim_state(
                staged.state,
                &[
                    NativeWorkerClaimState::Admitted,
                    NativeWorkerClaimState::Ready,
                    NativeWorkerClaimState::Active,
                    NativeWorkerClaimState::Cancelling,
                ],
            )?;
            self.advance_claim(&binding.claim_id, NativeWorkerClaimState::Cancelling)?;
        }
        let operation_id =
            OperationId::new(binding.operation_id).map_err(|_| NativeWorkerRouteError::Shape {
                field: "operation_id",
            })?;
        let (_, session_binding) =
            caller_binding(session).map_err(|_| NativeWorkerRouteError::Fence {
                field: "session_binding",
            })?;
        Ok((operation_id, session_binding))
    }
}

// R2 single-shape proof (Implements #22 DISPATCH-FINISH): the route admits
// the SAME worker-core halves the child submits, with every check on the
// single shape. Claim and ready both build through
// `build_single_shape_request(claim, registration)` only; there is no legacy
// builder and no registration-less contour.
#[cfg(test)]
mod single_shape_proof {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn epoch(sequence: u64) -> EpochId {
        EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("lineage"),
            std::num::NonZeroU64::new(sequence).expect("sequence"),
        )
        .expect("epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(
            epoch(1),
            eliot_contracts::ResourceGeneration::new(1).expect("generation"),
        )
    }

    /// Exact process invocation value the R1 Governor producer canonicalizes.
    ///
    /// The same `canonical_json_bytes` + `sha256_hex` the Governor
    /// `process_invocation_digest_for` helper runs, so the join below carries
    /// the real record digest into the executable gate instead of a
    /// placeholder.
    fn test_invocation(claim_id: &str, operation_id: &str) -> serde_json::Value {
        serde_json::json!({
            "claim_id": claim_id,
            "operation_id": operation_id,
            "argv": ["--check"],
            "fence": {"generation": 1},
        })
    }

    /// Derives the R1 production `process_invocation_digest` from the exact
    /// invocation bytes (never canned).
    fn test_invocation_digest(claim_id: &str, operation_id: &str) -> String {
        let invocation = test_invocation(claim_id, operation_id);
        let bytes =
            eliot_contracts::canonical_json_bytes(&invocation).expect("canonical invocation");
        eliot_contracts::sha256_hex(&bytes)
    }

    /// Derives the opaque owner-produced executable digest from the real
    /// published binding material through the real hash procedure.
    ///
    /// Carried by value and compared for equality only (the route never
    /// recomputes the Governor domain); derived here from the claim-bound
    /// nonce plus the real invocation digest so no stand-in seed remains on
    /// the exercised path.
    fn test_owner_digest(
        claim_id: &str,
        operation_id: &str,
        nonce: &str,
        invocation_digest: &str,
    ) -> String {
        let material = serde_json::json!({
            "claim_id": claim_id,
            "operation_id": operation_id,
            "launch_nonce": nonce,
            "process_invocation_digest": invocation_digest,
        });
        let bytes =
            eliot_contracts::canonical_json_bytes(&material).expect("canonical owner material");
        eliot_contracts::sha256_hex(&bytes)
    }

    /// Builds one envelope-less worker-core `{claim, registration}` pair
    /// plus its binding digest (Implements #22 R2).
    ///
    /// The claim carries the full `EpochId` objects and no Kernel-service
    /// envelope duplication; the registration carries the envelope the
    /// projector sources. Both single-shape proofs share these exact
    /// halves, so the claim and ready paths prove the same shape.
    fn single_shape_pair(
        claim_id: &str,
        registration_id: &str,
        attempt_id: &str,
        operation_id: &str,
        replay_stream_id: &str,
    ) -> (serde_json::Value, serde_json::Value, String) {
        let fence_value = serde_json::to_value(fence()).expect("fence json");
        let epoch_value = serde_json::to_value(epoch(1)).expect("epoch json");
        // R1 Governor-sourced digests: derived from the real binding record
        // through the production canonical procedure, never canned. The
        // wire-v1 `None` branch of `build_executable_expectation` keeps its
        // by-construction empty placeholders (refused typed upstream); only
        // this presented join carries real digests.
        let nonce = "launch-nonce-0123456789abcdef";
        let invocation_digest = test_invocation_digest(claim_id, operation_id);
        let owner_digest = test_owner_digest(claim_id, operation_id, nonce, &invocation_digest);
        let join = serde_json::json!({
            "route_ref": "route://test/full-canonical-route",
            "adapter_id": "adapter-test",
            "adapter_revision": 3,
            "config_digest": "b".repeat(64),
            "facet_manifest_ref": "facet-manifest-7",
            "grant_graph_revision": 5,
            "replay_stream_id": replay_stream_id,
            "launch_nonce": nonce,
            "process_invocation_digest": invocation_digest,
            "authority_epoch": epoch_value,
            "generation": serde_json::to_value(fence().resource_generation).expect("gen"),
            "state_fence": fence_value,
            "deadline_unix_ms": 9_000_000_000_000u64,
            "expires_at_unix_ms": 9_000_000_100_000u64,
            "executable_wire_version": NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
            "executable_binding_digest": owner_digest,
        });
        // Binding digest over the shared 18-field set (same procedure both
        // sides use; envelope-only fields are excluded, so stripping them
        // keeps the digest).
        let draft = serde_json::json!({
            "attempt_id": attempt_id,
            "authority_epoch": epoch_value,
            "budget": {"context_tokens": 8, "wall_time_ms": 1000, "output_bytes": 1024, "cost_microunits": 10, "max_depth": 2, "max_descendants": 4},
            "cancellation_policy_id": "cancel-1",
            "claim_id": claim_id,
            "deadline_unix_ms": 9_000_000_000_000u64,
            "decision_id": "decision-1",
            "executable_binding": join,
            "expected_result_schema": "result-schema",
            "expected_result_schema_version": 1,
            "operation_id": operation_id,
            "parent_job_id": "parent-job-1",
            "predecessor_revision": "rev-1",
            "registration_id": registration_id,
            "route_class": "test-route",
            "state_fence": fence_value,
            "task_id": "task-1",
            "work_scope_id": "scope-1",
            "worker_generation": 1,
        });
        let binding_digest = {
            let bytes = eliot_contracts::canonical_json_bytes(&draft).expect("canonical");
            eliot_contracts::sha256_hex(&bytes)
        };
        let claim = serde_json::json!({
            "claim_id": claim_id,
            "registration_id": registration_id,
            "worker_generation": 1,
            "parent_job_id": "parent-job-1",
            "task_id": "task-1",
            "work_scope_id": "scope-1",
            "decision_id": "decision-1",
            "attempt_id": attempt_id,
            "operation_id": operation_id,
            "route_class": "test-route",
            "budget": {"context_tokens": 8, "wall_time_ms": 1000, "output_bytes": 1024, "cost_microunits": 10, "max_depth": 2, "max_descendants": 4},
            "deadline_unix_ms": 9_000_000_000_000u64,
            "cancellation_policy_id": "cancel-1",
            "expected_result_schema": "result-schema",
            "expected_result_schema_version": 1,
            "predecessor_revision": "rev-1",
            "authority_epoch": epoch_value,
            "state_fence": fence_value,
            "wire_version": NATIVE_WORKER_CLAIM_WIRE_VERSION,
            "executable_binding": draft.get("executable_binding").cloned().unwrap(),
            "binding_digest": binding_digest,
        });
        let registration = serde_json::json!({
            "registration_id": registration_id,
            "installation_id": "installation-1",
            "worker_artifact_digest": "a".repeat(64),
            "worker_config_digest": "b".repeat(64),
            "protocol_version": NATIVE_WORKER_PROTOCOL_VERSION,
            "worker_generation": 1,
            "process_id": 4242,
            "process_start_100ns": 120,
            "process_image_digest": "a".repeat(64),
            "principal_ref": "principal-1",
            "session_id": "session-operation-1",
            "connection_id": "connection-1",
            "authority_epoch": epoch_value,
            "state_fence": fence_value,
            "lease_id": "lease-1",
            "lease_expires_at_unix_ms": 9_000_000_200_000u64,
            "renewal_id": "renewal-1",
            "execution_unit_schema_version": NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION,
            "resource_limits": {"wall_timeout_ms": 30000, "stdout_bytes": 4096, "stderr_bytes": 4096, "max_descendants": 4},
            "invalidation_set": [],
        });
        (claim, registration, binding_digest)
    }

    /// R2: a worker-core single-shape presentation (full `EpochId` objects,
    /// no Kernel-service envelope duplication) validates and builds a service
    /// request whose binding digest equals the presented digest and whose
    /// projected envelope (wire/installation/artifact/protocol/schema)
    /// validates through the service owner. Old-wire envelope duplication,
    /// when present, must agree (resource binding); a rewired envelope fails.
    #[test]
    fn single_shape_claim_admits_with_projected_envelope() {
        let (claim, registration, binding_digest) = single_shape_pair(
            "claim-single-1",
            "reg-single-1",
            "attempt-single-1",
            "op-single-1",
            "stream-single-1/gen-1",
        );
        // Split binds (same registration/generation/epoch/fence).
        let payload = serde_json::json!({"claim": claim, "registration": registration});
        let (split_claim, split_registration) =
            KernelComposition::split_claim_presentation(&payload).expect("split binds");
        KernelComposition::validate_native_worker_registration(split_registration)
            .expect("registration validates");
        KernelComposition::require_claim_registration_resource_binding(
            split_claim,
            split_registration,
        )
        .expect("resource binds by construction on the single shape");
        let (claim_id, digest, generation) =
            KernelComposition::validate_native_worker_claim(split_claim)
                .expect("single-shape claim validates");
        assert_eq!(claim_id, "claim-single-1");
        assert_eq!(digest, binding_digest);
        assert_eq!(generation, 1);
        // Builder projects the envelope and computes the request digest.
        let request =
            KernelComposition::build_single_shape_request(split_claim, split_registration)
                .expect("single-shape builds");
        assert_eq!(request.binding_digest, binding_digest);
        assert_eq!(request.wire_id, NATIVE_WORKER_CLAIM_WIRE_ID);
        assert_eq!(request.installation_id, "installation-1");
        request.validate().expect("built request validates");
        request
            .validate_canonical_digest()
            .expect("built request digest binds");
        // A rewired envelope (claim duplicates a foreign artifact) fails the
        // resource binding even though its shape is well-formed.
        let mut rewired = split_claim.clone();
        rewired["worker_artifact_digest"] = serde_json::Value::String("f".repeat(64));
        assert!(
            KernelComposition::require_claim_registration_resource_binding(
                &rewired,
                split_registration
            )
            .is_err(),
            "foreign artifact must not bind"
        );
        assert!(
            KernelComposition::build_single_shape_request(&rewired, split_registration).is_err(),
            "rewired envelope must not build"
        );
    }

    /// R2 readiness unification: both contours (envelope-less worker-core
    /// halves and old-wire envelope duplication) build through the SAME
    /// single-shape projector when the presenting registration rides along.
    /// A registration-less presentation has no builder anymore: ready
    /// requires the registration, so the ready path can never diverge from
    /// the claim path.
    #[test]
    fn readiness_single_shape_unifies_both_contours() {
        let (claim, registration, binding_digest) = single_shape_pair(
            "claim-ready-1",
            "reg-ready-1",
            "attempt-ready-1",
            "op-ready-1",
            "stream-ready-1/gen-1",
        );
        // Single shape projects the envelope from the presenting registration.
        let projected = KernelComposition::build_single_shape_request(&claim, &registration)
            .expect("readiness claim builds single-shape");
        assert_eq!(projected.binding_digest, binding_digest);
        assert_eq!(projected.installation_id, "installation-1");
        projected.validate().expect("projected request validates");
        // Old-wire duplication that agrees with the registration builds
        // through the SAME projector (envelope-only fields are excluded
        // from the binding digest, so the digest still binds).
        let mut enveloped = claim.clone();
        enveloped["wire_id"] = serde_json::Value::String(NATIVE_WORKER_CLAIM_WIRE_ID.to_owned());
        enveloped["installation_id"] = serde_json::Value::String("installation-1".to_owned());
        enveloped["worker_artifact_digest"] = serde_json::Value::String("a".repeat(64));
        enveloped["worker_config_digest"] = serde_json::Value::String("b".repeat(64));
        enveloped["protocol_version"] =
            serde_json::Value::String(NATIVE_WORKER_PROTOCOL_VERSION.to_owned());
        enveloped["execution_unit_schema_version"] =
            serde_json::Value::from(NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION);
        KernelComposition::validate_native_worker_claim(&enveloped)
            .expect("agreeing old-wire duplication validates");
        let reunified = KernelComposition::build_single_shape_request(&enveloped, &registration)
            .expect("agreeing old-wire duplication reunifies single-shape");
        assert_eq!(reunified.binding_digest, binding_digest);
        assert_eq!(reunified.installation_id, "installation-1");
        // A rewired envelope (claim duplicates a foreign artifact) fails the
        // resource binding and never builds, on either contour.
        let mut rewired = enveloped.clone();
        rewired["worker_artifact_digest"] = serde_json::Value::String("f".repeat(64));
        assert!(
            KernelComposition::require_claim_registration_resource_binding(&rewired, &registration)
                .is_err(),
            "foreign artifact must not bind"
        );
        assert!(
            KernelComposition::build_single_shape_request(&rewired, &registration).is_err(),
            "rewired envelope must not build"
        );
    }

    /// Builds one R1 gate fixture: the typed request plus the live
    /// registration anchors the expectation is built from.
    fn r1_gate_fixture() -> (
        NativeWorkerClaimRequest,
        serde_json::Value,
        StateFence,
        EpochId,
    ) {
        let (claim, registration, _) = single_shape_pair(
            "claim-r1-gate-1",
            "reg-r1-gate-1",
            "attempt-r1-gate-1",
            "op-r1-gate-1",
            "stream-r1-gate-1/gen-1",
        );
        let request = KernelComposition::build_single_shape_request(&claim, &registration)
            .expect("R1 claim builds single-shape");
        request.validate().expect("R1 request validates");
        let fence_value: StateFence = serde_json::from_value(
            registration
                .get("state_fence")
                .cloned()
                .expect("registration fence"),
        )
        .expect("registration fence parses");
        let live_epoch: EpochId = serde_json::from_value(
            registration
                .get("authority_epoch")
                .cloned()
                .expect("registration epoch"),
        )
        .expect("registration epoch parses");
        (request, registration, fence_value, live_epoch)
    }

    /// Recomputes both claim digests after a presented-field mutation so the
    /// executable gate reaches its typed currentness arm instead of stopping
    /// at a stale envelope digest.
    fn r1_rebind(request: &mut NativeWorkerClaimRequest) {
        request.binding_digest = request
            .compute_binding_digest()
            .expect("rebind binding");
        request.request_digest = request
            .canonical_request_digest()
            .expect("rebind envelope");
    }

    /// R1 Governor-sourced digest feed, admit path (Implements #22): the
    /// presented join carries the real invocation digest derived from the
    /// exact invocation bytes, and the gate admits the matching digest.
    #[test]
    fn r1_gate_admits_matching_invocation_digest() {
        let (request, registration, fence_value, live_epoch) = r1_gate_fixture();
        let presented = request
            .executable_binding
            .as_ref()
            .expect("R1 request carries the join");
        let expected_invocation = test_invocation("claim-r1-gate-1", "op-r1-gate-1");
        let expected_bytes =
            eliot_contracts::canonical_json_bytes(&expected_invocation).expect("canonical");
        assert_eq!(
            presented.process_invocation_digest,
            eliot_contracts::sha256_hex(&expected_bytes),
            "join must carry the derived invocation digest"
        );
        let expectation = KernelComposition::build_executable_expectation(
            request.executable_binding.as_ref(),
            &registration,
            &fence_value,
            &live_epoch,
        )
        .expect("R1 expectation builds");
        KernelComposition::enforce_claim_executable_binding(
            &request,
            &expectation,
            9_000_000_050_000u64,
        )
        .expect("matching digest admits");
    }

    /// R1 Governor-sourced digest feed, refuse paths (Implements #22): a
    /// mutated digest is well-formed but `Conflict`s on
    /// `executable_binding.process_invocation_digest`; a missing join
    /// (wire v1) is a typed refusal, never a silent admit. The
    /// `None`-branch empty placeholders stay by construction: the gate
    /// refuses old wire first with typed
    /// `u1_old_wire_without_executable_binding`.
    #[test]
    fn r1_gate_refuses_mutated_and_missing_digest() {
        let (request, registration, fence_value, live_epoch) = r1_gate_fixture();
        let now = 9_000_000_050_000u64;
        let expectation = KernelComposition::build_executable_expectation(
            request.executable_binding.as_ref(),
            &registration,
            &fence_value,
            &live_epoch,
        )
        .expect("R1 expectation builds");
        let presented_digest = request
            .executable_binding
            .as_ref()
            .expect("join present")
            .process_invocation_digest
            .clone();
        // Mutated digest: still well-formed, but the gate Conflicts on the
        // invocation digest field with the current owner digest echoed.
        let mut mutated = request.clone();
        let mutated_invocation = serde_json::json!({
            "claim_id": "claim-r1-gate-1",
            "operation_id": "op-r1-gate-1",
            "argv": ["--mutated"],
            "fence": {"generation": 1},
        });
        let mutated_bytes =
            eliot_contracts::canonical_json_bytes(&mutated_invocation).expect("canonical");
        let mutated_digest = eliot_contracts::sha256_hex(&mutated_bytes);
        assert_ne!(
            mutated_digest, presented_digest,
            "mutated invocation must derive a different digest"
        );
        mutated
            .executable_binding
            .as_mut()
            .expect("mutated carries the join")
            .process_invocation_digest = mutated_digest;
        r1_rebind(&mut mutated);
        mutated.validate().expect("mutated stays shape-valid");
        let error = KernelComposition::enforce_claim_executable_binding(&mutated, &expectation, now)
            .expect_err("mutated digest must not dispatch");
        match error {
            NativeWorkerRouteError::Conflict(conflict) => {
                assert_eq!(conflict.identity, "claim-r1-gate-1");
                assert!(
                    conflict
                        .changed_fields
                        .iter()
                        .any(|field| field.ends_with(".process_invocation_digest")),
                    "conflict must name the invocation digest, got {:?}",
                    conflict.changed_fields
                );
                assert_eq!(
                    conflict.expected_digest, expectation.current.executable_binding_digest,
                    "conflict must echo the current owner digest"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
        // Missing join (wire v1): the `None`-branch placeholders stay empty
        // by construction and the gate refuses typed, never silent.
        let none_expectation = KernelComposition::build_executable_expectation(
            None,
            &registration,
            &fence_value,
            &live_epoch,
        )
        .expect("None expectation builds by construction");
        assert!(
            none_expectation.current.process_invocation_digest.is_empty(),
            "wire-v1 placeholders stay empty by construction"
        );
        assert!(
            none_expectation
                .current
                .executable_binding_digest
                .is_empty(),
            "wire-v1 owner placeholder stays empty by construction"
        );
        let mut old_wire = request.clone();
        old_wire.wire_version = NATIVE_WORKER_CLAIM_WIRE_VERSION_V1;
        old_wire.executable_binding = None;
        r1_rebind(&mut old_wire);
        let old_error = KernelComposition::enforce_claim_executable_binding(
            &old_wire,
            &none_expectation,
            now,
        )
        .expect_err("old wire must not dispatch");
        assert!(
            matches!(
                old_error,
                NativeWorkerRouteError::Shape { .. } | NativeWorkerRouteError::Fence { .. }
            ),
            "missing join must be a typed refusal, got {old_error:?}"
        );
    }
}

// Slice A focused proofs live in `tests/native_worker_claim_plumbing.rs`.
// They are wired here (not via `tests.rs`) so this slice touches only its
// owned files: the lifecycle route, the claim protocol, and the one new test
// file. The sibling Slice B wires its distinctly named test file through the
// reconcile route, keeping both slices disjoint.
#[cfg(test)]
#[path = "tests/native_worker_claim_plumbing.rs"]
mod native_worker_claim_plumbing;
