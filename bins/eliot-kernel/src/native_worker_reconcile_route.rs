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
//!   on, plus the retained-receipt echo when one is presented.
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
struct ReconcilePresentation {
    reconcile_id: String,
    claim_id: String,
    binding_digest: String,
    worker_generation: u64,
    authority_epoch: u64,
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
        if fence.authority_epoch.value() != authority_epoch {
            return Err(NativeWorkerReconcileError::Fence {
                field: "epoch_fence",
            });
        }
        Ok(ReconcilePresentation {
            reconcile_id,
            claim_id,
            binding_digest,
            worker_generation,
            authority_epoch,
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
        if let Some(retained) = payload.get("receipt").filter(|receipt| receipt.is_object()) {
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
                        identity: claim_id.clone(),
                        expected_digest: staged.receipt_digest.clone().unwrap_or_default(),
                        observed_digest: retained_digest,
                        changed_fields: vec!["receipt_digest".to_owned()],
                    },
                ));
            }
        }
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
