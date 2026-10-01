//! Canonical `ADMITTED` submit leg of the admission-reservation saga (#1678
//! W3, REQ4, A3).
//!
//! # What this module owns
//!
//! [`KernelComposition::ensure_reservation_canonical_admitted`] — the
//! production submit path for the reservation's canonical `ADMITTED`
//! transition. The dispatch arm for
//! [`ADMISSION_RESERVATION_ADMIT_OPERATION`](super::admission_reservation_saga::ADMISSION_RESERVATION_ADMIT_OPERATION)
//! calls it before the admit/activate coordinator, so the coordinator's owner
//! receipt readback observes the commit this leg submitted instead of an
//! eternal absence.
//!
//! The order is fixed, and every step re-derives rather than trusts:
//!
//! 1. **Re-derive, never trust.** The reservation identity and the canonical
//!    operation identity come from the payload's reservation binding, and the
//!    payload's own canonical-operation copy must equal the derived one, or
//!    the payload could redirect the saga to a second admission.
//! 2. **Adopt, never re-submit.** The owner's own `WriteReceipt` for the
//!    ORIGINAL operation is read back first and classified through
//!    [`eliot_ors::reconcile_canonical_admission`]. A committed receipt is
//!    adopted as-is; a terminal receipt is left for the coordinator's typed
//!    refusal. Only an absent receipt or a proven non-commit reaches submit,
//!    and the submit reuses the SAME operation identity.
//! 3. **Submit only current staged evidence.** The staged row is reloaded, and
//!    the submit proceeds only for a `StagedInactive`/`Reconciling` row with
//!    no retained commit, an unexpired boundary, and a staged fence identical
//!    to the live fence. A moved fence fails closed here — before any
//!    canonical effect — rather than committing an admission the saga could
//!    never activate into launch.
//! 4. **Submit the owner-built plan.** The transition is built by
//!    [`eliot_store_api::prepare_reservation_admission_transition`] from the
//!    staged facts, and committed through the retained generation-routed
//!    gateway (`KernelStoreGateway::apply`). The returned receipt is the
//!    canonical owner's own artifact; nothing is fabricated here and nothing
//!    is inferred from a successful transport response.
//!
//! A submit whose outcome is unknown (transport failure after a possible
//! commit) fails closed: the next call re-resolves the SAME operation,
//! adopts the commit if it landed, and resubmits the byte-identical plan if
//! it did not. No path mints a second admission (A3), and an exact replay
//! converges on the one committed receipt (A7).
//!
//! The payload is parsed tolerantly (unknown fields ignored): this leg reads
//! only the reservation binding, the canonical operation copy and the live
//! fence, so a coordinator payload shape that gains or loses an
//! owner-supplied field keeps parsing here while the coordinator validates it
//! strictly at its own boundary.

use super::{KernelComposition, TransportError};

#[cfg(windows)]
use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence, canonical_json_bytes,
};
#[cfg(windows)]
use eliot_ors::{
    AdmissionReservationState, CanonicalAdmissionResolution, OperationIdentity,
    OperationalRecoveryStore, OrsError, StateFenceSnapshot, reconcile_canonical_admission,
    reload_staged_admission_reservation, stage_operation_identity,
};
#[cfg(windows)]
use serde::Deserialize;

/// The reservation binding, canonical operation copy and live fence one
/// submit needs.
///
/// Parsed tolerantly on purpose (see the module documentation): unknown
/// fields are ignored rather than refused, because the strict payload
/// contract belongs to the coordinator that follows this leg.
#[cfg(windows)]
#[derive(Deserialize)]
struct ReservationAdmissionSubmitFacts {
    /// Stable reservation identity the submit re-derives everything from.
    reservation_id: String,
    /// The canonical `ADMITTED` operation identity. Must equal
    /// `stage_operation_identity(reservation_id)`.
    canonical_operation_id: String,
    /// The live fence the daemon presents for this operation.
    state_fence: StateFence,
}

/// F-LOG-KERNEL-5 (#1678): reservation canonical-submit boundary observation.
///
/// Same shape as the saga's own observer: a fixed event name plus a bounded
/// stable outcome, carrying no reservation identity, operation identity,
/// receipt digest, fence or owner error string.
#[cfg(windows)]
fn observe_canonical_submit(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "admission reservation canonical submit observation"
    );
}

#[cfg(windows)]
impl KernelComposition {
    /// Ensures the canonical owner's `ADMITTED` commit exists for one staged
    /// reservation, submitting the owner-built transition when the owner
    /// holds no committed receipt for the ORIGINAL operation identity (#1678
    /// W3, REQ4, A3).
    ///
    /// This is the submit half of the I14.6 saga; the prove/activate half
    /// stays with the coordinator that runs after this returns. On success
    /// the coordinator's readback observes either the adopted or the just
    /// submitted commit. Every canonical outcome the owner already decided
    /// (committed, terminal) is left untouched for the coordinator to
    /// classify; only an absent receipt or a proven non-commit submits, under
    /// the SAME operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IdentityConflict`] when the payload names a
    /// canonical operation that is not this reservation's own, and
    /// [`TransportError::UnknownRequest`] when no reservation is durably
    /// staged. Any other failure — shape, fence, storage, gateway or submit —
    /// is [`TransportError::SessionFenced`], matching the coordinator's own
    /// mapping for the same failure classes. A submit failure never claims a
    /// commit: the retry re-resolves the same identity.
    pub(crate) async fn ensure_reservation_canonical_admitted(
        &self,
        payload: &serde_json::Value,
    ) -> Result<(), TransportError> {
        let facts: ReservationAdmissionSubmitFacts =
            serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
        let reservation_id = OperationIdentity::new(&facts.reservation_id)
            .map_err(|_| TransportError::SessionFenced)?;
        let canonical_operation_id =
            stage_operation_identity(&reservation_id).map_err(|_| TransportError::SessionFenced)?;
        if facts.canonical_operation_id != canonical_operation_id.as_str() {
            observe_canonical_submit(
                "kernel.admission_reservation.submit_rejected:identity",
                "rejected",
            );
            return Err(TransportError::IdentityConflict);
        }
        let store_operation_id = eliot_contracts::OperationId::new(canonical_operation_id.as_str())
            .map_err(|_| TransportError::SessionFenced)?;
        let gateway = self.retained_store_gateway()?;

        // Adopt, never re-submit: the owner's own receipt for the ORIGINAL
        // operation decides. A transport failure reads as absent here; the
        // submit below is idempotent under the same identity, so a commit
        // that already landed is adopted on retry rather than duplicated.
        let readback = gateway
            .receipt(&facts.state_fence, store_operation_id.clone())
            .await
            .ok()
            .flatten();
        let resolution =
            reconcile_canonical_admission(readback.as_ref(), canonical_operation_id.as_str())
                .map_err(|_| TransportError::SessionFenced)?;
        match resolution {
            CanonicalAdmissionResolution::Committed => {
                observe_canonical_submit("kernel.admission_reservation.submit_adopted", "adopted");
                return Ok(());
            }
            CanonicalAdmissionResolution::TerminalFailure { .. } => {
                // The same identity is dead; the coordinator retains the exact
                // terminal evidence and dispositions the reservation without
                // launch. Submitting again would be pointless, not unlawful,
                // but the typed refusal belongs to the coordinator.
                return Ok(());
            }
            CanonicalAdmissionResolution::ProvenNonCommit
            | CanonicalAdmissionResolution::Unknown { .. } => {}
        }

        let now_unix_ms =
            i64::try_from(super::unix_ms()).map_err(|_| TransportError::SessionFenced)?;
        let staged = reload_staged_admission_reservation(
            self.generation_gateway.ors.as_ref(),
            &reservation_id,
            now_unix_ms,
        )
        .map_err(|error| match error {
            OrsError::ReservationNotFound => TransportError::UnknownRequest,
            _ => TransportError::SessionFenced,
        })?;
        let record = staged.record();
        // A row that already retains the committed decision needs no submit;
        // the coordinator re-proves it. Anything that is not durably staged
        // (or reconciling a lost response) cannot be submitted for.
        if record.canonical_admission.is_some() {
            return Ok(());
        }
        if record.state != AdmissionReservationState::StagedInactive
            && record.state != AdmissionReservationState::Reconciling
        {
            observe_canonical_submit(
                "kernel.admission_reservation.submit_rejected:state",
                "rejected",
            );
            return Err(TransportError::SessionFenced);
        }
        if now_unix_ms >= record.expires_at_ms {
            observe_canonical_submit(
                "kernel.admission_reservation.submit_rejected:expired",
                "rejected",
            );
            return Err(TransportError::SessionFenced);
        }
        // The staged fence must be the live fence, compared BY VALUE through
        // the owner's own snapshot capture: a moved fence fails closed here,
        // before any canonical effect, instead of committing an admission the
        // saga could never activate into launch.
        let live_sequence = facts.state_fence.authority_epoch.sequence.get();
        let live_snapshot = StateFenceSnapshot::capture(&facts.state_fence, live_sequence)
            .map_err(|_| TransportError::SessionFenced)?;
        if live_snapshot != record.state_fence {
            observe_canonical_submit(
                "kernel.admission_reservation.submit_rejected:fence",
                "rejected",
            );
            return Err(TransportError::SessionFenced);
        }

        let receipt_json = String::from_utf8(
            canonical_json_bytes(staged.receipt()).map_err(|_| TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let context = RequestMetadata {
            // Stable retry identity: the same reservation always submits
            // under the same request, so a lost response resubmits the
            // byte-identical plan instead of a second admission.
            request_id: RequestId::new(format!("{}-admission", canonical_operation_id.as_str()))
                .map_err(|_| TransportError::SessionFenced)?,
            session_id: None,
            // Not task-relative: the reservation binds a work item, not a
            // task, so no task binding is claimed.
            task_id: None,
            product_id: ProductId::new("eliot-kernel")
                .map_err(|_| TransportError::SessionFenced)?,
            source_id: SourceId::new(super::ACTIVE_DAEMON_CALLER)
                .map_err(|_| TransportError::SessionFenced)?,
            state_fence: facts.state_fence.clone(),
            clock: ClockReading::default(),
        };
        let admission = eliot_store_api::prepare_reservation_admission_transition(
            &eliot_store_api::ReservationAdmissionRequest {
                operation_id: store_operation_id,
                idempotency_key: reservation_id.as_str().to_owned(),
                request: context.clone(),
                reservation_id: reservation_id.as_str().to_owned(),
                work_item_id: record.work_item_id.as_str().to_owned(),
                proposed_attempt_id: record.proposed_attempt_id.as_str().to_owned(),
                claims: eliot_store_api::ReservationAdmissionClaims {
                    resources: eliot_store_api::ReservationAdmissionClaim {
                        reference: record.claims.resources.reference.as_str().to_owned(),
                        digest: record.claims.resources.sha256.clone(),
                    },
                    lane: eliot_store_api::ReservationAdmissionClaim {
                        reference: record.claims.lane.reference.as_str().to_owned(),
                        digest: record.claims.lane.sha256.clone(),
                    },
                    environment: eliot_store_api::ReservationAdmissionClaim {
                        reference: record.claims.environment.reference.as_str().to_owned(),
                        digest: record.claims.environment.sha256.clone(),
                    },
                    effects: eliot_store_api::ReservationAdmissionClaim {
                        reference: record.claims.effects.reference.as_str().to_owned(),
                        digest: record.claims.effects.sha256.clone(),
                    },
                    quota_view: eliot_store_api::ReservationAdmissionClaim {
                        reference: record.claims.quota_view.reference.as_str().to_owned(),
                        digest: record.claims.quota_view.sha256.clone(),
                    },
                },
                expires_at_ms: record.expires_at_ms,
                reservation_receipt_json: receipt_json,
                presenter: super::ACTIVE_DAEMON_CALLER.to_owned(),
                presenter_epoch: record.authority_epoch.current.epoch,
            },
        )
        .map_err(|_| TransportError::SessionFenced)?;

        gateway
            .apply(
                &context,
                admission.transition,
                admission.expected_revision_heads,
                admission.expected_ordering_heads,
            )
            .await
            .map_err(|_| {
                observe_canonical_submit("kernel.admission_reservation.submit_failed", "rejected");
                TransportError::SessionFenced
            })?;
        observe_canonical_submit("kernel.admission_reservation.submit_committed", "success");
        Ok(())
    }
}

#[cfg(not(windows))]
impl KernelComposition {
    /// Non-Windows placeholder: the canonical store route does not exist here,
    /// so the submit leg fails closed rather than pretending to have an owner
    /// receipt.
    pub(crate) async fn ensure_reservation_canonical_admitted(
        &self,
        _payload: &serde_json::Value,
    ) -> Result<(), TransportError> {
        Err(TransportError::SessionFenced)
    }
}
