//! Native-worker reconcile route (Wave D, issue #872).
//!
//! Lost-acknowledgement reconciliation for one exact claim/attempt/operation:
//! after possible provider work, checkpoint, or result submission whose
//! acknowledgement was lost, the worker re-presents the full claim (plus its
//! retained receipt, when it has one) and Kernel reconciles under the
//! original claim before any reclaim, retry, route change, or replacement
//! generation. Ordering mirrors
//! [`crate::KernelComposition::dispatch_native_worker_frame`] (Ready-gate,
//! peer authentication, session-fence compatibility) and then
//! `validate → load → fence/conflict → advance → sealed receipt`.
//!
//! Authority rules enforced here:
//!
//! - This module holds no durable state itself. Persistence is owned by the
//!   ORS claim table (`load/advance_native_worker_claim`); this route
//!   translates the frame JSON boundary into that typed owner and translates
//!   its verdicts back into sealed receipts. It never fabricates persistence,
//!   admission, readiness, or a receipt.
//! - `Unknown` advances to `Reconciling` where the ORS transition table
//!   allows it, and stays there: an uncertain outcome is reconciled under the
//!   original claim, never blind-retried as new work (I1.4, I14.14). Every
//!   other durable state reconciles in place — `Terminal` is absorbing, so
//!   Kernel/worker restart rehydrates the terminal outcome instead of
//!   downgrading the unit to unclaimed.
//! - Exact-digest match returns the durable receipt identity; a second
//!   identity is never manufactured (I7.2: replay never creates a second
//!   logical event). A changed binding under a known identity is
//!   `IdentityConflict` before any effect.
//! - A stale or fenced worker generation (or epoch) fences the session; it
//!   can never claim, heartbeat, checkpoint, submit, reconnect, or become
//!   current through this path.
//! - Full typed claim validation stays with the admission path: the durable
//!   record is the authority, and reconcile never re-admits. This handler
//!   validates only the identity/binding/fence subset its decision depends
//!   on, plus the retained-receipt echo when one is presented. A retained
//!   receipt echoing a stale generation/epoch fences; one echoing a changed
//!   registration/binding/attempt/operation conflicts. An optional
//!   `claim.registration_id`, when presented, must equal the durable
//!   registration or the reconcile conflicts before any effect.
//!
//! Transport error mapping is mechanical: shape, digest, fence, service-gate,
//! and storage failures fail closed as `SessionFenced`; a changed binding
//! under a known identity is `IdentityConflict`; an unknown claim identity
//! is `UnknownRequest`.
//!
//! Residuals: the `load`/`advance` helpers below duplicate ~20 lines from
//! `native_worker_lifecycle_route` (private to its module) pending a shared
//! narrow owner; the worker-side reconcile span and the 3-line dispatch
//! wiring in `frame_dispatch` belong to the integrator immediately after
//! this commit.

use super::native_worker_lifecycle_route::{native_worker_json_str, native_worker_json_u64};
use super::{
    KernelComposition, KernelFrameAction, KernelServiceState, sha256_json, status_frame, unix_ms,
};
use eliot_contracts::StateFence;
use eliot_ipc::{Session, TransportError};
use eliot_ors::{NativeWorkerClaimRecord, NativeWorkerClaimState, OperationIdentity, OrsError};
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload};

// ---------------------------------------------------------------------------
// Wire operation.
// ---------------------------------------------------------------------------

/// Reconciles one exact claim after a lost acknowledgement.
///
/// Listed in the sibling route's `is_native_worker_operation` and dispatched
/// from its frame gateway, so every item here is live.
pub(crate) const NATIVE_WORKER_RECONCILE_OPERATION: &str = "native_worker.reconcile";

/// Maximum length of one reconcile operation identity, in UTF-8 bytes.
///
/// Mirrors the sibling route's operation-identity bound.
const MAX_RECONCILE_IDENTITY_LEN: usize = 256;
/// Maximum length of one reconcile text/digest field, in UTF-8 bytes.
///
/// Mirrors the sibling route's claim-text bound.
const MAX_RECONCILE_TEXT_LEN: usize = 1_024;

// ---------------------------------------------------------------------------
// Typed route errors (mechanical TransportError mapping at the boundary).
// ---------------------------------------------------------------------------

/// Changed-work conflict under one claim identity.
///
/// Constructed from the durable binding digest when the same identity is
/// presented with a changed binding or a mismatched retained receipt.
#[derive(Clone, Debug)]
pub(crate) struct NativeWorkerReconcileConflict {
    identity: String,
    expected_digest: String,
    observed_digest: String,
    changed_fields: Vec<String>,
}

/// Typed failure for one native-worker reconcile operation.
#[derive(Clone, Debug)]
pub(crate) enum NativeWorkerReconcileError {
    /// A bounded shape check failed for the named field.
    Shape { field: &'static str },
    /// Epoch, fence, or generation binding failed for the named field.
    Fence { field: &'static str },
    /// The claim identity has no staged record.
    Unknown { identity: String },
    /// The same identity carries a changed binding or receipt.
    Conflict(NativeWorkerReconcileConflict),
}

impl std::fmt::Display for NativeWorkerReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shape { field } => write!(f, "native-worker reconcile shape rejected: {field}"),
            Self::Fence { field } => write!(f, "native-worker reconcile fence rejected: {field}"),
            Self::Unknown { identity } => {
                write!(f, "native-worker reconcile claim is unknown: {identity}")
            }
            Self::Conflict(conflict) => write!(
                f,
                "native-worker reconcile conflict under {} (expected {}, observed {}, changed {})",
                conflict.identity,
                conflict.expected_digest,
                conflict.observed_digest,
                conflict.changed_fields.join(","),
            ),
        }
    }
}

impl NativeWorkerReconcileError {
    fn into_transport(self) -> TransportError {
        match self {
            Self::Shape { .. } | Self::Fence { .. } => TransportError::SessionFenced,
            Self::Unknown { .. } => TransportError::UnknownRequest,
            Self::Conflict(_) => TransportError::IdentityConflict,
        }
    }
}

// ---------------------------------------------------------------------------
// Durable backend: the ORS claim table through its owning API.
// ---------------------------------------------------------------------------

/// Presented reconcile material: the reconcile identity plus the exact
/// claim presentation it reconciles.
///
/// `registration_id` is optional for wire compatibility: callers that still
/// present only the claim subset omit it and are checked exactly as before;
/// callers that present it must match the durable registration or conflict
/// before any effect, so a stale or foreign registration cannot reconcile.
struct ReconcilePresentation {
    reconcile_id: String,
    claim_id: String,
    binding_digest: String,
    worker_generation: u64,
    authority_epoch: u64,
    registration_id: Option<String>,
}

impl KernelComposition {
    /// Loads one claim record by exact identity. Unknown identities are
    /// `Unknown` (records are never invented here); storage or corruption
    /// failures fence the session fail-closed.
    ///
    /// Duplicates the sibling route's loader (private to its module) pending
    /// a shared narrow owner; the two must stay identical.
    fn load_reconcile_record(
        &self,
        claim_id: &str,
    ) -> Result<NativeWorkerClaimRecord, NativeWorkerReconcileError> {
        let identity = OperationIdentity::new(claim_id)
            .map_err(|_| NativeWorkerReconcileError::Shape { field: "claim_id" })?;
        self.generation_gateway
            .ors
            .load_native_worker_claim(&identity)
            .map_err(|_| NativeWorkerReconcileError::Fence { field: "ors_load" })?
            .ok_or_else(|| NativeWorkerReconcileError::Unknown {
                identity: claim_id.to_owned(),
            })
    }

    /// Advances one staged claim to its next mechanical state.
    ///
    /// The ORS transition table owns the anti-downgrade fence (`Terminal` is
    /// absorbing, `Unknown` only becomes `Reconciling`, nothing returns to
    /// `Requested`). An illegal step fences; an unknown identity stays
    /// unknown; any other mechanical failure fences.
    ///
    /// Duplicates the sibling route's advancer (private to its module)
    /// pending a shared narrow owner; the two must stay identical.
    fn advance_reconcile_record(
        &self,
        claim_id: &str,
        target: NativeWorkerClaimState,
    ) -> Result<NativeWorkerClaimRecord, NativeWorkerReconcileError> {
        let identity = OperationIdentity::new(claim_id)
            .map_err(|_| NativeWorkerReconcileError::Shape { field: "claim_id" })?;
        self.generation_gateway
            .ors
            .advance_native_worker_claim(&identity, target, None)
            .map_err(|error| match error {
                OrsError::InvalidTransition => NativeWorkerReconcileError::Fence { field: "state" },
                _ => NativeWorkerReconcileError::Fence {
                    field: "ors_advance",
                },
            })?
            .ok_or_else(|| NativeWorkerReconcileError::Unknown {
                identity: claim_id.to_owned(),
            })
    }
}

// ---------------------------------------------------------------------------
// Dispatch entry point.
// ---------------------------------------------------------------------------

impl KernelComposition {
    /// Dispatches one native-worker reconcile frame.
    ///
    /// Mirrors [`crate::KernelComposition::dispatch_native_worker_frame`]:
    /// the Ready-gate and peer authentication are re-checked here so direct
    /// callers cannot bypass them. Unknown or stale generations fence the
    /// session, never authority. The integrator calls this from the closed
    /// frame gateway once `NATIVE_WORKER_RECONCILE_OPERATION` joins the
    /// sibling route's operation list.
    pub(crate) fn dispatch_native_worker_reconcile(
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
        Self::require_session_fence(session, &identity_value)?;
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        let operation = payload
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if operation != NATIVE_WORKER_RECONCILE_OPERATION {
            return Err(TransportError::SessionFenced);
        }
        let receipt = self
            .handle_native_worker_reconcile(&identity_value, &payload)
            .map_err(NativeWorkerReconcileError::into_transport)?;
        let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, receipt)?;
        frame.request_id = Some(request_id);
        frame
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(KernelFrameAction::Reply(frame))
    }

    /// Requires the presenting fence to agree with the session fence.
    ///
    /// A worker generation presenting under a fence incompatible with its
    /// session is stale or foreign: it fences the session and is never
    /// granted authority, admission, or a receipt.
    fn require_session_fence(
        session: &Session,
        identity_value: &serde_json::Value,
    ) -> Result<(), TransportError> {
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
        Ok(())
    }

    /// Parses one reconcile presentation: the distinct reconcile identity
    /// (bound to the frame idempotency key) and the exact claim fields the
    /// durable record is checked against.
    fn parse_reconcile_presentation(
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<ReconcilePresentation, NativeWorkerReconcileError> {
        let reconcile_id =
            native_worker_json_str(payload, "reconcile_id", MAX_RECONCILE_IDENTITY_LEN).map_err(
                |_| NativeWorkerReconcileError::Shape {
                    field: "reconcile_id",
                },
            )?;
        Self::require_reconcile_identity(identity, &reconcile_id)?;
        let claim = payload
            .get("claim")
            .filter(|claim| claim.is_object())
            .ok_or(NativeWorkerReconcileError::Shape { field: "claim" })?;
        let claim_id = native_worker_json_str(claim, "claim_id", MAX_RECONCILE_IDENTITY_LEN)
            .map_err(|_| NativeWorkerReconcileError::Shape { field: "claim_id" })?;
        let binding_digest = Self::require_reconcile_digest(claim, "binding_digest")?;
        let worker_generation =
            native_worker_json_u64(claim, "worker_generation").map_err(|_| {
                NativeWorkerReconcileError::Shape {
                    field: "worker_generation",
                }
            })?;
        if worker_generation == 0 {
            return Err(NativeWorkerReconcileError::Shape {
                field: "worker_generation",
            });
        }
        let authority_epoch = native_worker_json_u64(claim, "authority_epoch").map_err(|_| {
            NativeWorkerReconcileError::Shape {
                field: "authority_epoch",
            }
        })?;
        if authority_epoch == 0 {
            return Err(NativeWorkerReconcileError::Shape {
                field: "authority_epoch",
            });
        }
        let fence_value =
            claim
                .get("state_fence")
                .cloned()
                .ok_or(NativeWorkerReconcileError::Shape {
                    field: "state_fence",
                })?;
        let fence: StateFence =
            serde_json::from_value(fence_value).map_err(|_| NativeWorkerReconcileError::Shape {
                field: "state_fence",
            })?;
        if fence.authority_epoch.sequence.get() != authority_epoch {
            return Err(NativeWorkerReconcileError::Fence {
                field: "epoch_fence",
            });
        }
        let registration_id = match claim.get("registration_id") {
            None | Some(serde_json::Value::Null) => None,
            Some(_) => Some(
                native_worker_json_str(claim, "registration_id", MAX_RECONCILE_IDENTITY_LEN)
                    .map_err(|_| NativeWorkerReconcileError::Shape {
                        field: "registration_id",
                    })?,
            ),
        };
        Ok(ReconcilePresentation {
            reconcile_id,
            claim_id,
            binding_digest,
            worker_generation,
            authority_epoch,
            registration_id,
        })
    }

    /// Requires the frame idempotency key to equal the message's distinct
    /// reconcile identity, binding replay protection to the exact message.
    fn require_reconcile_identity(
        identity: &serde_json::Value,
        reconcile_id: &str,
    ) -> Result<(), NativeWorkerReconcileError> {
        let key = identity
            .get("idempotency_key")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerReconcileError::Shape {
                field: "idempotency_key",
            })?;
        if key != reconcile_id {
            return Err(NativeWorkerReconcileError::Shape {
                field: "idempotency_key",
            });
        }
        Ok(())
    }

    /// Reads one lowercase SHA-256 digest field.
    fn require_reconcile_digest(
        value: &serde_json::Value,
        field: &'static str,
    ) -> Result<String, NativeWorkerReconcileError> {
        let digest = native_worker_json_str(value, field, MAX_RECONCILE_TEXT_LEN)
            .map_err(|_| NativeWorkerReconcileError::Shape { field })?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(NativeWorkerReconcileError::Shape { field });
        }
        Ok(digest)
    }

    /// Checks an optional retained receipt echo against the durable record.
    ///
    /// Absent or explicit-null `receipt` means the worker holds no receipt
    /// (lost acknowledgement without retained identity) and is accepted so
    /// the durable identity can be rehydrated. A present non-object receipt
    /// is malformed and fails closed as `Shape`. A present object must echo
    /// the exact claim identity and the durable receipt digest; any other
    /// echoed field it carries (generation, epoch, registration, binding,
    /// attempt, operation, fence) must also agree with the durable record:
    /// stale generation/epoch/fence fences the session while changed
    /// registration/binding/attempt/operation conflicts before any effect.
    /// The durable record stays the authority; this echo never re-admits.
    fn check_retained_receipt(
        payload: &serde_json::Value,
        claim_id: &str,
        staged: &NativeWorkerClaimRecord,
    ) -> Result<(), NativeWorkerReconcileError> {
        let raw = match payload.get("receipt") {
            None | Some(serde_json::Value::Null) => return Ok(()),
            Some(raw) => raw,
        };
        let retained = match raw {
            serde_json::Value::Object(_) => raw,
            _ => {
                return Err(NativeWorkerReconcileError::Shape { field: "receipt" });
            }
        };
        let retained_claim =
            native_worker_json_str(retained, "claim_id", MAX_RECONCILE_IDENTITY_LEN).map_err(
                |_| NativeWorkerReconcileError::Shape {
                    field: "receipt.claim_id",
                },
            )?;
        if retained_claim != claim_id {
            return Err(NativeWorkerReconcileError::Shape {
                field: "receipt.claim_id",
            });
        }
        let retained_digest = Self::require_reconcile_digest(retained, "receipt_digest")?;
        if staged.receipt_digest.as_deref() != Some(retained_digest.as_str()) {
            return Err(NativeWorkerReconcileError::Conflict(
                NativeWorkerReconcileConflict {
                    identity: claim_id.to_owned(),
                    expected_digest: staged.receipt_digest.clone().unwrap_or_default(),
                    observed_digest: retained_digest,
                    changed_fields: vec!["receipt_digest".to_owned()],
                },
            ));
        }
        Self::check_retained_binding_echo(retained, claim_id, staged)
    }

    /// Checks the optional binding fields a retained receipt may echo.
    ///
    /// Only fields the worker actually presents are compared; absent fields
    /// keep the previous wire shape working. Stale generation/epoch/fence
    /// fences while changed registration/binding/attempt/operation
    /// conflicts, both before any effect.
    fn check_retained_binding_echo(
        retained: &serde_json::Value,
        claim_id: &str,
        staged: &NativeWorkerClaimRecord,
    ) -> Result<(), NativeWorkerReconcileError> {
        if retained
            .get("worker_generation")
            .is_some_and(|v| !v.is_null())
        {
            let generation =
                native_worker_json_u64(retained, "worker_generation").map_err(|_| {
                    NativeWorkerReconcileError::Shape {
                        field: "receipt.worker_generation",
                    }
                })?;
            if generation != staged.worker_generation {
                return Err(NativeWorkerReconcileError::Fence {
                    field: "receipt.worker_generation",
                });
            }
        }
        if retained
            .get("authority_epoch")
            .is_some_and(|v| !v.is_null())
        {
            let epoch = native_worker_json_u64(retained, "authority_epoch").map_err(|_| {
                NativeWorkerReconcileError::Shape {
                    field: "receipt.authority_epoch",
                }
            })?;
            if epoch != staged.authority_epoch {
                return Err(NativeWorkerReconcileError::Fence {
                    field: "receipt.authority_epoch",
                });
            }
        }
        Self::check_retained_changed_fields(retained, claim_id, staged)?;
        if let Some(fence_value) = retained.get("state_fence").filter(|v| !v.is_null()) {
            let fence: StateFence = serde_json::from_value(fence_value.clone()).map_err(|_| {
                NativeWorkerReconcileError::Shape {
                    field: "receipt.state_fence",
                }
            })?;
            if fence.authority_epoch.sequence.get() != staged.authority_epoch {
                return Err(NativeWorkerReconcileError::Fence {
                    field: "receipt.epoch_fence",
                });
            }
        }
        Ok(())
    }

    /// Checks the changed-binding fields a retained receipt may echo.
    ///
    /// A retained registration, binding digest, attempt, or operation that
    /// disagrees with the durable record conflicts before any effect; the
    /// receipt digest check above already covers the common case, and these
    /// per-field checks close the digest-copying smuggle.
    fn check_retained_changed_fields(
        retained: &serde_json::Value,
        claim_id: &str,
        staged: &NativeWorkerClaimRecord,
    ) -> Result<(), NativeWorkerReconcileError> {
        if retained
            .get("registration_id")
            .is_some_and(|v| !v.is_null())
        {
            let registration =
                native_worker_json_str(retained, "registration_id", MAX_RECONCILE_IDENTITY_LEN)
                    .map_err(|_| NativeWorkerReconcileError::Shape {
                        field: "receipt.registration_id",
                    })?;
            if registration != staged.registration_id.as_str() {
                return Err(NativeWorkerReconcileError::Conflict(
                    NativeWorkerReconcileConflict {
                        identity: claim_id.to_owned(),
                        expected_digest: staged.binding_digest.clone(),
                        observed_digest: staged.binding_digest.clone(),
                        changed_fields: vec!["receipt.registration_id".to_owned()],
                    },
                ));
            }
        }
        if retained.get("binding_digest").is_some_and(|v| !v.is_null()) {
            let binding =
                Self::require_reconcile_digest(retained, "binding_digest").map_err(|_| {
                    NativeWorkerReconcileError::Shape {
                        field: "receipt.binding_digest",
                    }
                })?;
            if binding != staged.binding_digest {
                return Err(NativeWorkerReconcileError::Conflict(
                    NativeWorkerReconcileConflict {
                        identity: claim_id.to_owned(),
                        expected_digest: staged.binding_digest.clone(),
                        observed_digest: binding,
                        changed_fields: vec!["receipt.binding_digest".to_owned()],
                    },
                ));
            }
        }
        if retained.get("attempt_id").is_some_and(|v| !v.is_null()) {
            let presented =
                native_worker_json_str(retained, "attempt_id", MAX_RECONCILE_IDENTITY_LEN)
                    .map_err(|_| NativeWorkerReconcileError::Shape {
                        field: "receipt.attempt_id",
                    })?;
            if presented != staged.attempt_id.as_str() {
                return Err(NativeWorkerReconcileError::Conflict(
                    NativeWorkerReconcileConflict {
                        identity: claim_id.to_owned(),
                        expected_digest: staged.binding_digest.clone(),
                        observed_digest: staged.binding_digest.clone(),
                        changed_fields: vec!["receipt.attempt_id".to_owned()],
                    },
                ));
            }
        }
        if retained.get("operation_id").is_some_and(|v| !v.is_null()) {
            let presented =
                native_worker_json_str(retained, "operation_id", MAX_RECONCILE_IDENTITY_LEN)
                    .map_err(|_| NativeWorkerReconcileError::Shape {
                        field: "receipt.operation_id",
                    })?;
            if presented != staged.operation_id.as_str() {
                return Err(NativeWorkerReconcileError::Conflict(
                    NativeWorkerReconcileConflict {
                        identity: claim_id.to_owned(),
                        expected_digest: staged.binding_digest.clone(),
                        observed_digest: staged.binding_digest.clone(),
                        changed_fields: vec!["receipt.operation_id".to_owned()],
                    },
                ));
            }
        }
        Ok(())
    }

    /// Reconciles one exact claim after a lost acknowledgement.
    ///
    /// The payload carries the full presented claim plus the retained receipt
    /// when the worker still holds one. The durable record is loaded by exact
    /// claim identity; generation and epoch currency are fenced against it; a
    /// changed binding or a mismatched retained receipt conflicts before any
    /// effect; `Unknown` advances to `Reconciling` where the ORS table allows
    /// it while every other state reconciles in place. The sealed receipt
    /// echoes the durable receipt identity — never a second identity.
    fn handle_native_worker_reconcile(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerReconcileError> {
        let presentation = Self::parse_reconcile_presentation(identity, payload)?;
        let reconcile_id = presentation.reconcile_id;
        let claim_id = presentation.claim_id;
        let binding_digest = presentation.binding_digest;
        let worker_generation = presentation.worker_generation;
        let authority_epoch = presentation.authority_epoch;
        let staged = self.load_reconcile_record(&claim_id)?;
        if staged.worker_generation == 0 || staged.worker_generation != worker_generation {
            return Err(NativeWorkerReconcileError::Fence {
                field: "worker_generation",
            });
        }
        if staged.authority_epoch != authority_epoch {
            return Err(NativeWorkerReconcileError::Fence {
                field: "authority_epoch",
            });
        }
        if let Some(presented_registration) = presentation.registration_id.as_deref()
            && presented_registration != staged.registration_id.as_str()
        {
            return Err(NativeWorkerReconcileError::Conflict(
                NativeWorkerReconcileConflict {
                    identity: claim_id.clone(),
                    expected_digest: staged.binding_digest.clone(),
                    observed_digest: binding_digest.clone(),
                    changed_fields: vec!["registration_id".to_owned()],
                },
            ));
        }
        if staged.binding_digest != binding_digest {
            return Err(NativeWorkerReconcileError::Conflict(
                NativeWorkerReconcileConflict {
                    identity: claim_id.clone(),
                    expected_digest: staged.binding_digest.clone(),
                    observed_digest: binding_digest,
                    changed_fields: vec!["binding_digest".to_owned()],
                },
            ));
        }
        Self::check_retained_receipt(payload, &claim_id, &staged)?;
        let durable_state = if staged.state == NativeWorkerClaimState::Unknown {
            self.advance_reconcile_record(&claim_id, NativeWorkerClaimState::Reconciling)?
                .state
        } else {
            staged.state
        };
        let durable_state_value = serde_json::to_value(durable_state)
            .map_err(|_| NativeWorkerReconcileError::Shape { field: "state" })?;
        let mut body = serde_json::json!({
            "kind": "native_worker_reconciled",
            "reconcile_id": reconcile_id,
            "claim_id": claim_id,
            "binding_digest": staged.binding_digest,
            "worker_generation": staged.worker_generation,
            "durable_state": durable_state_value,
            "admission_receipt_digest": staged.receipt_digest,
            "reconciled_at_unix_ms": unix_ms(),
        });
        // One canonical seal over the whole body, sibling idiom: the
        // `admission_receipt_digest` echo above is the durable admission
        // identity (null while only requested), while `receipt_digest` seals
        // this reconciliation reply itself.
        let digest = sha256_json(&body)
            .map_err(|_| NativeWorkerReconcileError::Shape { field: "receipt" })?;
        body["receipt_digest"] = serde_json::Value::String(digest);
        Ok(body)
    }
}

// Slice B focused tests live in `tests/native_worker_reconcile_plumbing.rs`
// but are hooked here (not in `tests.rs`) so this slice stays disjoint from
// Slice A and the T2/T6 serializer: no shared wiring file is touched. The
// manager may rewire that file under `tests.rs` on integration and remove
// this one-line hook.
#[cfg(test)]
#[path = "tests/native_worker_reconcile_plumbing.rs"]
mod native_worker_reconcile_plumbing;
