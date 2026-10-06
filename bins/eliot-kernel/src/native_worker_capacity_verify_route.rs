//! Native-worker capacity-verify route (issue #1679, W11 provider side).
//!
//! Serves the `native_worker.capacity_verify` query the #1701 consumer
//! replays over its authenticated Kernel session before every claimed
//! start and recovery use: the child presents the claim projection plus
//! the exact retained pair from its dispatch-file section, and this route
//! answers against the contour-retained [`ProcessPermit`][eliot_kernel_core::ProcessPermit]
//! holding under the same claim identity, with the verdict vocabulary the
//! consumer maps (`verified`, `not_held`, `foreign_owner`, `stale_epoch`,
//! `stale_owner`, `conflict`).
//!
//! Authority rules enforced here:
//!
//! - This module holds no capacity state itself. The dispatch contour owns
//!   the reserve and the retained holdings; this route translates the frame
//!   JSON boundary into the owner's typed answer through
//!   [`super::dispatch_launch::answer_native_worker_capacity_verify`]. It
//!   never mints, stores, or releases a permit.
//! - Only `verified` admits, and only when the presented pair equals the
//!   retained request and issuance record and the holding still verifies
//!   against the live boundary (current owner generation, Authority Epoch,
//!   compiled profile). Every other outcome is a typed refusal the
//!   consumer fails closed on.
//! - An uncomposed contour, a lock failure, or a malformed presentation
//!   fails the frame closed (`SessionFenced`): the lookup did not
//!   authenticate, so nothing is admitted on it.
//! - The frame idempotency key must equal the queried claim identity,
//!   binding replay protection to the exact message.

use super::{
    KernelComposition, KernelFrameAction, KernelServiceState,
    native_worker_lifecycle_route::{native_worker_json_str, native_worker_request_body},
    status_frame,
};
use eliot_ipc::{Session, TransportError};
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload};

// ---------------------------------------------------------------------------
// Wire operation.
// ---------------------------------------------------------------------------

/// Replays the owner's live issuance/currency check for one carried
/// capacity pair.
///
/// Listed in the sibling lifecycle route's `is_native_worker_operation`
/// and dispatched from its frame gateway, so every item here is live.
/// Paired with the worker-side `NATIVE_WORKER_CAPACITY_VERIFY_OPERATION`
/// in `bins/eliot-native-worker/src/kernel_admission_client.rs`; both
/// lists must stay identical.
pub(crate) const NATIVE_WORKER_CAPACITY_VERIFY_OPERATION: &str = "native_worker.capacity_verify";

/// Expected `kind` of a capacity-verify answer.
///
/// Paired with the worker-side `CAPACITY_VERIFY_ANSWER_KIND`; both lists
/// must stay identical.
pub(crate) const CAPACITY_VERIFY_ANSWER_KIND: &str = "native_worker_capacity_verified";

/// Maximum length of one capacity-verify text field, in UTF-8 bytes.
///
/// Mirrors the sibling route's claim-text bound.
const MAX_CAPACITY_VERIFY_TEXT_LEN: usize = 1_024;

// ---------------------------------------------------------------------------
// Typed route errors (mechanical TransportError mapping at the boundary).
// ---------------------------------------------------------------------------

/// Typed failure for one native-worker capacity-verify operation.
#[derive(Clone, Debug)]
pub(crate) enum NativeWorkerCapacityVerifyError {
    /// A bounded shape check failed for the named field.
    Shape { field: &'static str },
    /// The contour is uncomposed or the owner lookup is unavailable.
    Unavailable,
}

impl std::fmt::Display for NativeWorkerCapacityVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shape { field } => {
                write!(f, "native-worker capacity verify shape rejected: {field}")
            }
            Self::Unavailable => {
                write!(f, "native-worker capacity verify lookup is unavailable")
            }
        }
    }
}

impl NativeWorkerCapacityVerifyError {
    fn into_transport(self) -> TransportError {
        match self {
            Self::Shape { .. } | Self::Unavailable => TransportError::SessionFenced,
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch entry point.
// ---------------------------------------------------------------------------

impl KernelComposition {
    /// Dispatches one native-worker capacity-verify frame.
    ///
    /// Mirrors
    /// [`crate::KernelComposition::dispatch_native_worker_reconcile`]:
    /// the Ready-gate and peer authentication are re-checked here so
    /// direct callers cannot bypass them. Unknown or stale generations
    /// fence the session, never authority.
    pub(crate) fn dispatch_native_worker_capacity_verify(
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
        if operation != NATIVE_WORKER_CAPACITY_VERIFY_OPERATION {
            return Err(TransportError::SessionFenced);
        }
        // The real consumer frame nests the flat claim projection under
        // the closed `transact_json` envelope (issue #1679 W11/W4); the
        // handler reads the inner body, exactly as the currentness proof
        // does through `native_worker_frame_context`.
        let body = native_worker_request_body(&payload).clone();
        let receipt = self
            .handle_native_worker_capacity_verify(&identity_value, &body)
            .map_err(NativeWorkerCapacityVerifyError::into_transport)?;
        let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, receipt)?;
        frame.request_id = Some(request_id);
        frame
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(KernelFrameAction::Reply(frame))
    }

    /// Answers one capacity-verify presentation with the owner's verdict.
    ///
    /// The frame idempotency key must equal the queried claim identity
    /// (the consumer binds exactly that), and the answer kind names this
    /// query so a substituted answer cannot authenticate another pair.
    fn handle_native_worker_capacity_verify(
        &self,
        identity: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerCapacityVerifyError> {
        let claim_id = native_worker_json_str(payload, "claim_id", MAX_CAPACITY_VERIFY_TEXT_LEN)
            .map_err(|_| NativeWorkerCapacityVerifyError::Shape { field: "claim_id" })?;
        let key = identity
            .get("idempotency_key")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeWorkerCapacityVerifyError::Shape {
                field: "idempotency_key",
            })?;
        if key != claim_id {
            return Err(NativeWorkerCapacityVerifyError::Shape {
                field: "idempotency_key",
            });
        }
        let answer = super::dispatch_launch::answer_native_worker_capacity_verify(self, payload)
            .map_err(|error| match error {
                super::dispatch_launch::DispatchLaunchError::InvalidMaterial(_) => {
                    NativeWorkerCapacityVerifyError::Shape {
                        field: "presentation",
                    }
                }
                _ => NativeWorkerCapacityVerifyError::Unavailable,
            })?;
        if answer.get("kind").and_then(serde_json::Value::as_str)
            != Some(CAPACITY_VERIFY_ANSWER_KIND)
        {
            return Err(NativeWorkerCapacityVerifyError::Unavailable);
        }
        let _ = answer
            .get("claim_id")
            .and_then(serde_json::Value::as_str)
            .filter(|echo| *echo == claim_id)
            .ok_or(NativeWorkerCapacityVerifyError::Unavailable)?;
        Ok(answer)
    }
}
