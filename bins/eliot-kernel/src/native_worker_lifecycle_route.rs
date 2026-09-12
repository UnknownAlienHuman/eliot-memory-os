//! Native-worker lifecycle route (Wave C, issue #872).
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
//! - This module holds no durable state itself. It delegates persistence to
//!   the ORS owner and admission to the Kernel service owner through the six
//!   narrow Wave-B shims at the bottom of this file. The shims fail closed
//!   with [`NativeWorkerRouteError::WaveBPending`] until the integrator binds
//!   them to the real Wave-B functions; they never fabricate a receipt.
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
//! - Wave-A wire identity is mirrored from
//!   `eliot_kernel_service::protocol::native_worker_claim`, which is not
//!   re-exported at this base, so this file cannot name those types. The
//!   `NATIVE_WORKER_*` mirror constants below carry the documented Wave-A
//!   values verbatim and are flagged for the integrator to rebind.
//!
//! Transport error mapping is mechanical: shape, digest, fence, service-gate,
//! and storage failures fail closed as `SessionFenced`; a changed binding
//! under a known identity is `IdentityConflict`; an unknown claim identity is
//! `UnknownRequest`; an elapsed absolute deadline is `Timeout`.

use super::{
    KernelComposition, KernelFrameAction, KernelServiceState, ProcessExecutionRequest,
    caller_binding, sha256_json, status_frame, unix_ms,
};
use eliot_contracts::StateFence;
use eliot_ipc::{Session, TransportError};
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

/// Returns true for the seven Wave-C native-worker operations.
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
    )
}

/// Mirror of Wave-A `NATIVE_WORKER_CLAIM_WIRE_ID`.
///
/// INTEGRATOR: rebind to
/// `eliot_kernel_service::protocol::native_worker_claim::NATIVE_WORKER_CLAIM_WIRE_ID`
/// once Wave B re-exports it at the service-crate root.
const NATIVE_WORKER_CLAIM_WIRE_ID: &str = "eliot.kernel.native-worker-claim";
/// Mirror of Wave-A `NATIVE_WORKER_CLAIM_WIRE_VERSION` (see rebind note above).
const NATIVE_WORKER_CLAIM_WIRE_VERSION: u64 = 1;
/// Mirror of Wave-A `NATIVE_WORKER_PROTOCOL_VERSION` (see rebind note above).
const NATIVE_WORKER_PROTOCOL_VERSION: &str = "eliot-native-worker/v2";
/// Mirror of Wave-A `NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION` (see above).
const NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION: u64 = 1;

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
        heartbeat_id: String,
        claim_id: String,
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
/// Constructed by the Wave-B `stage`/`advance` owners when the same identity
/// is presented with changed bound work. Kept here so the conflict shape is
/// fixed before Wave B lands.
#[allow(dead_code, reason = "Wave-B seam: construction moves to the ORS owner")]
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
    #[allow(dead_code, reason = "Wave-B seam: construction moves to the ORS owner")]
    Unknown { identity: String },
    /// The same identity carries changed bound work.
    #[allow(dead_code, reason = "Wave-B seam: construction moves to the ORS owner")]
    Conflict(NativeWorkerRouteConflict),
    /// The absolute claim deadline elapsed before admission.
    ExpiredDeadline,
    /// The Wave-B gate is not bound yet; fail closed, never fabricate.
    WaveBPending { gate: &'static str },
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
            Self::WaveBPending { gate } => {
                write!(f, "native-worker Wave-B gate is not bound: {gate}")
            }
        }
    }
}

impl NativeWorkerRouteError {
    fn into_transport(self) -> TransportError {
        match self {
            Self::Shape { .. } | Self::Fence { .. } | Self::WaveBPending { .. } => {
                TransportError::SessionFenced
            }
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

/// Staged-record lifecycle states this route may observe or advance to.
///
/// The ORS owner (Wave B) is the authority for the transition table; these
/// labels are the Wave-C contract the shims below must honor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeWorkerAdvanceState {
    Checkpointed,
    ResultSubmitted,
    Cancelling,
}

impl NativeWorkerAdvanceState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Checkpointed => "checkpointed",
            Self::ResultSubmitted => "submitted",
            Self::Cancelling => "cancelling",
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
        &self,
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
        if native_worker_json_u64(payload, "execution_unit_schema_version")?
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

    /// Admits one registration: validate, Ready-gate, stage, receipt.
    fn handle_native_worker_registration(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let (registration_id, worker_generation) =
            self.validate_native_worker_registration(payload)?;
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
        let record = serde_json::json!({
            "kind": "registration",
            "registration_id": registration_id,
            "worker_generation": worker_generation,
            "payload": payload,
        });
        let stored = self.stage_native_worker_claim(&record)?;
        seal_route_receipt(serde_json::json!({
            "kind": "native_worker_registration",
            "registration_id": registration_id,
            "worker_generation": worker_generation,
            "stored": stored,
            "decided_at_unix_ms": unix_ms(),
        }))
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })
    }

    /// Validates the closed claim shape: wire, digests, texts, budget, fence.
    fn validate_native_worker_claim(
        &self,
        payload: &serde_json::Value,
    ) -> Result<(String, String, u64), NativeWorkerRouteError> {
        let wire = payload
            .get("wire_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerRouteError::Shape { field: "wire_id" })?;
        if wire != NATIVE_WORKER_CLAIM_WIRE_ID
            || native_worker_json_u64(payload, "wire_version")? != NATIVE_WORKER_CLAIM_WIRE_VERSION
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
        if native_worker_json_u64(payload, "execution_unit_schema_version")?
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

    /// Admits one claim: validate, deadline, service-gate, stage, receipt.
    ///
    /// An exact replay returns the stored receipt unchanged; a changed binding
    /// under the same claim identity conflicts before effect.
    fn handle_native_worker_claim(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let (claim_id, binding_digest, worker_generation) =
            self.validate_native_worker_claim(payload)?;
        Self::require_message_identity(identity, &claim_id)?;
        Self::require_claim_deadline(payload, unix_ms())?;
        let admitted = self.admit_native_worker_claim(payload)?;
        let record = serde_json::json!({
            "kind": "claim",
            "claim_id": claim_id,
            "binding_digest": binding_digest,
            "worker_generation": worker_generation,
            "admission": admitted,
            "payload": payload,
        });
        let stored = self.stage_native_worker_claim(&record)?;
        seal_route_receipt(serde_json::json!({
            "kind": "native_worker_claim",
            "claim_id": claim_id,
            "binding_digest": binding_digest,
            "worker_generation": worker_generation,
            "stored": stored,
            "decided_at_unix_ms": unix_ms(),
        }))
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })
    }

    /// Validates one ready-or-blocked submission against its admitted claim.
    fn validate_native_worker_readiness(
        &self,
        payload: &serde_json::Value,
        now: u64,
    ) -> Result<(String, String, String, u64), NativeWorkerRouteError> {
        let claim = payload
            .get("claim")
            .filter(|claim| claim.is_object())
            .ok_or(NativeWorkerRouteError::Shape { field: "claim" })?;
        let (claim_id, binding_digest, worker_generation) =
            self.validate_native_worker_claim(claim)?;
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
            "READY" => {
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
            }
            "BLOCKED" => {
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
            }
            _ => {
                return Err(NativeWorkerRouteError::Shape {
                    field: "readiness.kind",
                });
            }
        }
        Ok((ready_id, claim_id, binding_digest, worker_generation))
    }

    /// Records one readiness verdict: validate, Ready-gate, receipt.
    ///
    /// Transport health alone satisfies nothing here: the submission must bind
    /// the exact generation, claim digest, registry revision, credential
    /// references, deadline, and fence.
    fn handle_native_worker_ready(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let now = unix_ms();
        let (ready_id, claim_id, binding_digest, worker_generation) =
            self.validate_native_worker_readiness(payload, now)?;
        Self::require_message_identity(identity, &ready_id)?;
        let decided = self.mark_native_worker_ready(payload, now)?;
        seal_route_receipt(serde_json::json!({
            "kind": "native_worker_ready",
            "ready_id": ready_id,
            "claim_id": claim_id,
            "binding_digest": binding_digest,
            "worker_generation": worker_generation,
            "decided": decided,
            "decided_at_unix_ms": now,
        }))
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })
    }

    /// Loads the staged claim record and checks the presenting binding.
    ///
    /// Unknown identities are `Unknown`; stale generations, epochs, and
    /// fences are `Fence` (never authority); changed bound work under a known
    /// identity is `Conflict`.
    fn load_and_bind(
        &self,
        binding: &NativeWorkerBindingView,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let staged = self.load_native_worker_claim(&binding.claim_id)?;
        let staged_generation = native_worker_json_u64(&staged, "worker_generation")?;
        if staged_generation == 0 || staged_generation != binding.worker_generation {
            return Err(NativeWorkerRouteError::Fence {
                field: "worker_generation",
            });
        }
        if native_worker_json_u64(&staged, "authority_epoch")? != binding.authority_epoch {
            return Err(NativeWorkerRouteError::Fence {
                field: "authority_epoch",
            });
        }
        if native_worker_json_u64(&staged, "resource_generation")?
            != binding.fence.resource_generation.value()
        {
            return Err(NativeWorkerRouteError::Fence {
                field: "state_fence",
            });
        }
        let mut changed: Vec<String> = Vec::new();
        for (field, staged_text, presented) in [
            (
                "claim_id",
                native_worker_json_str(&staged, "claim_id", MAX_OPERATION_IDENTITY_LEN).ok(),
                binding.claim_id.clone(),
            ),
            (
                "attempt_id",
                native_worker_json_str(&staged, "attempt_id", MAX_CLAIM_TEXT_LEN).ok(),
                binding.attempt_id.clone(),
            ),
            (
                "operation_id",
                native_worker_json_str(&staged, "operation_id", MAX_CLAIM_TEXT_LEN).ok(),
                binding.operation_id.clone(),
            ),
            (
                "route_class",
                native_worker_json_str(&staged, "route_class", MAX_CLAIM_TEXT_LEN).ok(),
                binding.route_class.clone(),
            ),
            (
                "predecessor_revision",
                native_worker_json_str(&staged, "predecessor_revision", MAX_CLAIM_TEXT_LEN).ok(),
                binding.predecessor_revision.clone(),
            ),
        ] {
            if staged_text.as_deref() != Some(presented.as_str()) {
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
                    expected_digest: native_worker_json_str(
                        &staged,
                        "binding_digest",
                        MAX_CLAIM_TEXT_LEN,
                    )
                    .unwrap_or_default(),
                    observed_digest: String::new(),
                    changed_fields: changed,
                },
            ));
        }
        Ok(staged)
    }

    /// Requires the staged lifecycle state to admit the requested operation.
    fn require_staged_state(
        staged: &serde_json::Value,
        allowed: &[&str],
    ) -> Result<String, NativeWorkerRouteError> {
        let state = staged
            .get("state")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerRouteError::Shape { field: "state" })?;
        if !allowed.contains(&state) {
            return Err(NativeWorkerRouteError::Fence { field: "state" });
        }
        Ok(state.to_owned())
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
        Self::require_staged_state(&staged, &["ready", "active", "checkpointed"])?;
        let receipt = NativeWorkerLivenessReceipt::seal(
            heartbeat_id,
            binding.claim_id,
            binding.worker_generation,
            observed_at,
        )
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })?;
        Ok(receipt)
    }

    /// Stores one checkpoint: validate, bind, advance, receipt.
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
        let request_digest = identity
            .get("request_digest")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&checkpoint_id)
            .to_owned();
        let staged = self.load_and_bind(&binding)?;
        Self::require_staged_state(&staged, &["ready", "active"])?;
        let receipt = seal_route_receipt(serde_json::json!({
            "kind": "native_worker_checkpoint",
            "checkpoint_id": checkpoint_id,
            "claim_id": binding.claim_id,
            "checkpoint_ref": checkpoint_ref,
            "worker_generation": binding.worker_generation,
            "observed_at_unix_ms": observed_at,
        }))
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })?;
        self.advance_native_worker_claim(
            &binding.claim_id,
            &request_digest,
            NativeWorkerAdvanceState::Checkpointed,
            &receipt,
        )?;
        Ok(receipt)
    }

    /// Submits one result digest: validate, bind, schema-match, advance.
    ///
    /// Submission is not acceptance: the result is staged under the original
    /// claim and reconciled by Wave D before any reclaim or retry.
    fn handle_native_worker_result(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        let result_id = require_op_id(payload, "result_id")?;
        Self::require_message_identity(identity, &result_id)?;
        let result_schema = require_claim_text(payload, "result_schema")?;
        let result_schema_version = require_nonzero_u64(payload, "result_schema_version")?;
        let result_digest = require_digest(payload, "result_digest")?;
        let submitted_at = require_nonzero_u64(payload, "submitted_at_unix_ms")?;
        let binding = NativeWorkerBindingView::parse(payload)?;
        let request_digest = identity
            .get("request_digest")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&result_id)
            .to_owned();
        let staged = self.load_and_bind(&binding)?;
        Self::require_staged_state(&staged, &["ready", "active", "checkpointed"])?;
        let staged_schema =
            native_worker_json_str(&staged, "expected_result_schema", MAX_CLAIM_TEXT_LEN).map_err(
                |_| NativeWorkerRouteError::Shape {
                    field: "expected_result_schema",
                },
            )?;
        if staged_schema != result_schema
            || native_worker_json_u64(&staged, "expected_result_schema_version")?
                != result_schema_version
        {
            return Err(NativeWorkerRouteError::Conflict(
                NativeWorkerRouteConflict {
                    identity: binding.claim_id.clone(),
                    expected_digest: native_worker_json_str(
                        &staged,
                        "binding_digest",
                        MAX_CLAIM_TEXT_LEN,
                    )
                    .unwrap_or_default(),
                    observed_digest: result_digest.clone(),
                    changed_fields: vec!["expected_result_schema".to_owned()],
                },
            ));
        }
        let deadline = native_worker_json_u64(&staged, "deadline_unix_ms").map_err(|_| {
            NativeWorkerRouteError::Shape {
                field: "deadline_unix_ms",
            }
        })?;
        if deadline == 0 || deadline <= unix_ms() || submitted_at > deadline {
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
        self.advance_native_worker_claim(
            &binding.claim_id,
            &request_digest,
            NativeWorkerAdvanceState::ResultSubmitted,
            &receipt,
        )?;
        Ok(receipt)
    }

    /// Stages one cancellation observation and returns the exact operation to
    /// fence through the #100 process-execution path.
    ///
    /// New provider effects stop at the staged `cancelling` transition;
    /// possible work/result state is preserved on the staged record for
    /// reconciliation instead of being discarded.
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
        let request_digest = identity
            .get("request_digest")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&cancellation_id)
            .to_owned();
        let staged = self.load_and_bind(&binding)?;
        let state = Self::require_staged_state(
            &staged,
            &["ready", "active", "checkpointed", "submitted", "cancelling"],
        )?;
        if matches!(state.as_str(), "checkpointed" | "submitted") {
            self.reconcile_native_worker_claim_admission(&binding.claim_id, &request_digest)?;
        }
        let receipt = seal_route_receipt(serde_json::json!({
            "kind": "native_worker_cancelled",
            "cancellation_id": cancellation_id,
            "claim_id": binding.claim_id,
            "attempt_id": binding.attempt_id,
            "operation_id": binding.operation_id,
            "worker_generation": binding.worker_generation,
            "state": NativeWorkerAdvanceState::Cancelling.as_str(),
        }))
        .map_err(|_| NativeWorkerRouteError::Shape { field: "receipt" })?;
        self.advance_native_worker_claim(
            &binding.claim_id,
            &request_digest,
            NativeWorkerAdvanceState::Cancelling,
            &receipt,
        )?;
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

// ---------------------------------------------------------------------------
// Wave-B seams (owned here; the integrator rebinds bodies to Wave B).
//
// Each shim keeps the exact signature Wave B implements. Bodies validate
// their inputs and then fail closed: no gate may fabricate persistence,
// admission, readiness, or a receipt before its owner lands.
// ---------------------------------------------------------------------------

impl KernelComposition {
    /// Stages one registration or claim record before acknowledgement.
    ///
    /// Wave-B contract: persist the record, return the stored receipt
    /// unchanged on exact replay, and fail with `Conflict` on changed bound
    /// work under the same identity.
    fn stage_native_worker_claim(
        &self,
        record: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        if !record.is_object() {
            return Err(NativeWorkerRouteError::Shape { field: "record" });
        }
        Err(NativeWorkerRouteError::WaveBPending {
            gate: "stage_native_worker_claim",
        })
    }

    /// Loads the staged record for one claim identity.
    ///
    /// Wave-B contract: return the exact staged record, or `Unknown` when no
    /// record exists under the identity.
    fn load_native_worker_claim(
        &self,
        claim_id: &str,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        if claim_id.trim().is_empty() {
            return Err(NativeWorkerRouteError::Shape { field: "claim_id" });
        }
        Err(NativeWorkerRouteError::WaveBPending {
            gate: "load_native_worker_claim",
        })
    }

    /// Advances one staged claim to a Wave-C lifecycle state with its receipt.
    ///
    /// Wave-B contract: apply the single transition persistently and return
    /// the updated record; exact replay returns the stored receipt unchanged.
    fn advance_native_worker_claim(
        &self,
        claim_id: &str,
        request_digest: &str,
        state: NativeWorkerAdvanceState,
        receipt: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        if claim_id.trim().is_empty() || request_digest.trim().is_empty() || !receipt.is_object() {
            return Err(NativeWorkerRouteError::Shape { field: "advance" });
        }
        let _ = state;
        Err(NativeWorkerRouteError::WaveBPending {
            gate: "advance_native_worker_claim",
        })
    }

    /// Admits one validated claim through the Kernel service gate.
    ///
    /// Wave-B contract: enforce current-registration, epoch, fence, deadline,
    /// and binding checks, then return the admission verdict for staging.
    fn admit_native_worker_claim(
        &self,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        if !payload.is_object() {
            return Err(NativeWorkerRouteError::Shape { field: "claim" });
        }
        Err(NativeWorkerRouteError::WaveBPending {
            gate: "admit_native_worker_claim",
        })
    }

    /// Reconciles one claim after possible work, before reclaim or fencing.
    ///
    /// Wave-B contract: reconcile the same claim/attempt/operation under the
    /// original binding and return the reconciled record.
    fn reconcile_native_worker_claim_admission(
        &self,
        claim_id: &str,
        request_digest: &str,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        if claim_id.trim().is_empty() || request_digest.trim().is_empty() {
            return Err(NativeWorkerRouteError::Shape { field: "reconcile" });
        }
        Err(NativeWorkerRouteError::WaveBPending {
            gate: "reconcile_native_worker_claim_admission",
        })
    }

    /// Marks one admitted claim ready (or blocked) after worker proof.
    ///
    /// Wave-B contract: verify the exact current generation, claim digest,
    /// registry revision, credential references, deadline, and fence, then
    /// return the readiness decision for the receipt.
    fn mark_native_worker_ready(
        &self,
        payload: &serde_json::Value,
        now_unix_ms: u64,
    ) -> Result<serde_json::Value, NativeWorkerRouteError> {
        if !payload.is_object() || now_unix_ms == 0 {
            return Err(NativeWorkerRouteError::Shape { field: "readiness" });
        }
        Err(NativeWorkerRouteError::WaveBPending {
            gate: "mark_native_worker_ready",
        })
    }
}
