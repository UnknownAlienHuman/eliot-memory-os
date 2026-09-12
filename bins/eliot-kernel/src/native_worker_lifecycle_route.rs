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
use eliot_contracts::{AuthorityEpoch, StateFence};
use eliot_ipc::{Session, TransportError};
use eliot_kernel_service::{
    NATIVE_WORKER_CLAIM_WIRE_ID, NATIVE_WORKER_CLAIM_WIRE_VERSION,
    NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION, NATIVE_WORKER_PROTOCOL_VERSION,
    NativeWorkerClaimBudget, NativeWorkerClaimRequest, NativeWorkerClaimResponse,
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
fn seal_route_receipt(mut body: serde_json::Value) -> Result<serde_json::Value, TransportError> {
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
    fn into_transport(self) -> TransportError {
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
fn require_op_id(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<String, NativeWorkerRouteError> {
    native_worker_json_str(value, field, MAX_OPERATION_IDENTITY_LEN)
}

/// Reads one bounded claim/registration text field.
fn require_claim_text(
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
fn require_nonzero_u64(
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
fn require_digest(
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
        if fence.authority_epoch.value() != authority_epoch {
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
    fn load_claim_record(
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
    fn require_message_identity(
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
    fn require_claim_deadline(
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
    fn validate_native_worker_registration(
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
        if fence.authority_epoch.value() != native_worker_json_u64(payload, "authority_epoch")? {
            return Err(NativeWorkerRouteError::Fence {
                field: "epoch_fence",
            });
        }
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
    fn validate_native_worker_claim(
        payload: &serde_json::Value,
    ) -> Result<(String, String, u64), NativeWorkerRouteError> {
        let wire = payload
            .get("wire_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerRouteError::Shape { field: "wire_id" })?;
        if wire != NATIVE_WORKER_CLAIM_WIRE_ID
            || native_worker_json_u16(payload, "wire_version")? != NATIVE_WORKER_CLAIM_WIRE_VERSION
        {
            return Err(NativeWorkerRouteError::Shape { field: "wire" });
        }
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
        let claim_id = require_op_id(payload, "claim_id")?;
        for field in [
            "registration_id",
            "installation_id",
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
        for field in [
            "worker_artifact_digest",
            "worker_config_digest",
            "binding_digest",
            "request_digest",
        ] {
            require_digest(payload, field)?;
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
        if fence.authority_epoch.value() != native_worker_json_u64(payload, "authority_epoch")? {
            return Err(NativeWorkerRouteError::Fence {
                field: "epoch_fence",
            });
        }
        let binding_digest = require_digest(payload, "binding_digest")?;
        Ok((claim_id, binding_digest, worker_generation))
    }

    /// Locks the Kernel service owner for one admission verdict.
    fn service_guard(
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

    /// Rebuilds the typed Wave-A claim request from an already
    /// boundary-validated claim object. Every field is re-read here so the
    /// service owner's `validate` + `validate_canonical_digest` run over the
    /// exact admitted shape; a presentation that passed the boundary parse
    /// but disagrees with the typed contract still fails there.
    fn build_claim_request(
        claim: &serde_json::Value,
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
        let authority_epoch =
            AuthorityEpoch::new(native_worker_json_u64(claim, "authority_epoch")?).map_err(
                |_| NativeWorkerRouteError::Fence {
                    field: "authority_epoch",
                },
            )?;
        Ok(NativeWorkerClaimRequest {
            wire_id: require_claim_text(claim, "wire_id")?,
            wire_version: native_worker_json_u16(claim, "wire_version")?,
            claim_id: require_op_id(claim, "claim_id")?,
            registration_id: require_op_id(claim, "registration_id")?,
            worker_generation: require_nonzero_u64(claim, "worker_generation")?,
            installation_id: require_claim_text(claim, "installation_id")?,
            worker_artifact_digest: require_digest(claim, "worker_artifact_digest")?,
            worker_config_digest: require_digest(claim, "worker_config_digest")?,
            protocol_version: require_claim_text(claim, "protocol_version")?,
            execution_unit_schema_version: native_worker_json_u16(
                claim,
                "execution_unit_schema_version",
            )?,
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
            binding_digest: require_digest(claim, "binding_digest")?,
            request_digest: require_digest(claim, "request_digest")?,
        })
    }

    /// Splits one claim presentation into its claim and registration halves
    /// and checks their cross-binding exactly as the worker-side
    /// `ClaimAdmissionRequest::validate_binding` does: same registration,
    /// same generation, same epoch, same fence. A claim rewired onto a
    /// different registration fails here before any owner sees it.
    fn split_claim_presentation(
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
        if native_worker_json_u64(claim, "authority_epoch")?
            != native_worker_json_u64(registration, "authority_epoch")?
        {
            return Err(NativeWorkerRouteError::Fence {
                field: "epoch_fence",
            });
        }
        if claim.get("state_fence") != registration.get("state_fence") {
            return Err(NativeWorkerRouteError::Fence {
                field: "state_fence",
            });
        }
        Ok((claim, registration))
    }

    /// Admits one claim: validate, deadline, typed service admission, receipt.
    ///
    /// Persistence happens inside the service owner's
    /// `admit_native_worker_claim` (persist-before-ack): an exact replay
    /// returns the stored receipt unchanged, and a changed binding under the
    /// same claim identity returns `CONFLICT` and takes no effect.
    fn handle_native_worker_claim(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let (claim, _) = Self::split_claim_presentation(payload)?;
        let (claim_id, binding_digest, worker_generation) =
            Self::validate_native_worker_claim(claim)?;
        Self::require_message_identity(identity, &claim_id)?;
        let now = unix_ms();
        Self::require_claim_deadline(claim, now)?;
        let request = Self::build_claim_request(claim)?;
        let service = self.service_guard()?;
        let decision = service
            .admit_native_worker_claim(self.generation_gateway.ors.as_ref(), &request, now)
            .map_err(|_| NativeWorkerRouteError::Fence {
                field: "service_state",
            })?;
        Self::seal_decision(
            "native_worker_claim",
            &claim_id,
            &binding_digest,
            worker_generation,
            &[],
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
        if native_worker_json_u64(report, "authority_epoch")?
            != native_worker_json_u64(claim, "authority_epoch")?
        {
            return Err(NativeWorkerRouteError::Fence {
                field: "epoch_fence",
            });
        }
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
        if refs.len() > MAX_CREDENTIAL_REFERENCES {
            return Err(NativeWorkerRouteError::Shape {
                field: "credential_refs",
            });
        }
        for reference in refs {
            let object = reference.as_object().ok_or(NativeWorkerRouteError::Shape {
                field: "credential_refs",
            })?;
            if !object.contains_key("provider") || !object.contains_key("key") {
                return Err(NativeWorkerRouteError::Shape {
                    field: "credential_refs",
                });
            }
            require_claim_text(reference, "provider")?;
            require_claim_text(reference, "key")?;
        }
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
        let request = Self::build_claim_request(claim)?;
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
    /// fence (enforced at dispatch) and the epoch it carries.
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
        if binding.fence.authority_epoch.value() != binding.authority_epoch {
            return Err(NativeWorkerRouteError::Fence {
                field: "epoch_fence",
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
