//! Authenticated use-time readback for Governor source-artifact admission.
//!
//! The transport returns the original ORS row and its store-issued receipt;
//! it never serializes `ActiveAdmissionReservation`. Kernel re-runs the one
//! original ORS launch-prerequisite verifier against the row read in this
//! request and includes that verifier's typed disposition with the readback.

use eliot_kernel_service::AuthenticatedHostSession;
use eliot_ors::{
    AdmissionReservationClaims, AdmissionReservationLaunchPrerequisite,
    EpochLineage, OperationIdentity, OperationalRecoveryStore, StateFenceSnapshot,
    epoch_lineage_for, verify_admission_reservation_launch_prerequisite,
};
use eliot_protocol::{RequestIdentity, SELECTED_SOURCE_CAPTURE_CAPABILITY};
use serde::{Deserialize, Serialize};

use crate::{KernelComposition, TransportError};

pub(crate) const OPERATION: &str = "admission_reservation.current_use";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentUseRequest {
    reservation_id: OperationIdentity,
    work_item_id: OperationIdentity,
    proposed_attempt_id: OperationIdentity,
    work_scope_id: String,
    host_request_operation_id: OperationIdentity,
    host_request_digest: String,
    claims: AdmissionReservationClaims,
}

#[derive(Serialize)]
struct CurrentUseReadback<'a> {
    record: &'a eliot_ors::AdmissionReservationRecord,
    receipt: &'a eliot_ors::OperationalMutationReceipt,
    record_revision: u64,
    state_fence: &'a StateFenceSnapshot,
    reservation_id: &'a OperationIdentity,
    work_item_id: &'a OperationIdentity,
    proposed_attempt_id: &'a OperationIdentity,
    work_scope_id: &'a str,
    owner_verification: &'a AdmissionReservationLaunchPrerequisite,
}

impl KernelComposition {
    pub(crate) async fn current_use_operation(
        &self,
        session: &AuthenticatedHostSession,
        payload: serde_json::Value,
        request_identity: Option<&RequestIdentity>,
    ) -> Result<serde_json::Value, TransportError> {
        let identity = request_identity.ok_or(TransportError::SessionFenced)?;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if identity.request.state_fence != *session.state_fence() {
            return Err(TransportError::SessionFenced);
        }

        let mut payload = payload;
        let object = payload
            .as_object_mut()
            .ok_or(TransportError::SessionFenced)?;
        if object.remove("operation").and_then(|value| value.as_str().map(str::to_owned))
            .as_deref()
            != Some(OPERATION)
        {
            return Err(TransportError::SessionFenced);
        }
        let request: CurrentUseRequest =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        if request.host_request_digest.len() != 64
            || !request
                .host_request_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || request.work_scope_id.trim().is_empty()
            || request.work_scope_id.chars().any(char::is_control)
        {
            return Err(TransportError::SessionFenced);
        }

        // Bind the claimed request to its original durable Host row before the
        // ORS read. The client supplies only the immutable selectors returned
        // with the claim; every binding is compared to the authenticated
        // original RequestIdentity and durable request row here.
        let parent = self
            .generation_gateway
            .ors
            .load_host_request(
                &request.host_request_operation_id,
                &request.host_request_digest,
            )
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if parent.kind != eliot_ors::HostRequestKind::SelectedSourceCapture
            || parent.state != eliot_ors::HostRequestState::Admitted
            || parent.request_digest != request.host_request_digest
            || parent.capability_ref.as_str() != SELECTED_SOURCE_CAPTURE_CAPABILITY
            || parent.request_id.as_str() != identity.request.metadata.request_id.as_str()
            || parent.idempotency_key.as_str() != identity.idempotency_key
            || parent.cancellation_id.as_str() != identity.cancellation_id
            || parent.session_ref.as_ref().map(|value| value.as_str())
                != identity.request.metadata.session_id.as_ref().map(|value| value.as_str())
            || parent.task_ref.as_ref().map(|value| value.as_str())
                != identity.request.metadata.task_id.as_ref().map(|value| value.as_str())
            || parent.scope_ref.as_ref().map(|value| value.as_str())
                != Some(request.work_scope_id.as_str())
            || parent.deadline_unix_ms != identity.deadline_unix_ms
            || parent.authority_epoch != identity.request.state_fence.authority_epoch
            || parent.fence_digest
                != crate::sha256_json(&identity.request.state_fence)
                    .map_err(|_| TransportError::SessionFenced)?
        {
            return Err(TransportError::IdentityConflict);
        }

        let snapshot = self
            .generation_gateway
            .ors
            .load_kernel_admission_reservation(&request.reservation_id)
            .map_err(|_| TransportError::SessionFenced)?;
        let expected_epoch: EpochLineage = epoch_lineage_for(
            &identity.request.state_fence.authority_epoch,
            None,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let expected_fence = StateFenceSnapshot::capture(
            &identity.request.state_fence,
            identity
                .request
                .state_fence
                .authority_epoch
                .sequence
                .get(),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let now = i64::try_from(crate::unix_ms()).map_err(|_| TransportError::SessionFenced)?;
        let owner_verification = verify_admission_reservation_launch_prerequisite(
            snapshot.as_ref(),
            &request.work_item_id,
            &request.proposed_attempt_id,
            &expected_epoch,
            &expected_fence,
            now,
        )
        .map_err(|_| TransportError::SessionFenced)?;

        if let Some(snapshot) = snapshot.as_ref() {
            let record = snapshot.record();
            let receipt = snapshot.receipt();
            if record.reservation_id != request.reservation_id
                || record.work_item_id != request.work_item_id
                || record.proposed_attempt_id != request.proposed_attempt_id
                || record.claims != request.claims
                || record.state_fence != expected_fence
                || receipt.subject_id() != &request.reservation_id
                || receipt.record_id() != &record.operation_id
                || receipt.operation_order() == 0
            {
                return Err(TransportError::IdentityConflict);
            }
            let readback = CurrentUseReadback {
                record,
                receipt,
                record_revision: receipt.operation_order(),
                state_fence: &record.state_fence,
                reservation_id: &record.reservation_id,
                work_item_id: &record.work_item_id,
                proposed_attempt_id: &record.proposed_attempt_id,
                work_scope_id: &request.work_scope_id,
                owner_verification: &owner_verification,
            };
            return Ok(serde_json::json!({
                "status": "known",
                "value": {
                    "kind": "admission_reservation_current_use",
                    "value": { "current": readback },
                },
                "recovery": null,
            }));
        }

        Ok(serde_json::json!({
            "status": "known",
            "value": {
                "kind": "admission_reservation_current_use",
                "value": {
                    "current": {
                        "record": null,
                        "receipt": null,
                        "record_revision": null,
                        "state_fence": expected_fence,
                        "reservation_id": request.reservation_id,
                        "work_item_id": request.work_item_id,
                        "proposed_attempt_id": request.proposed_attempt_id,
                        "work_scope_id": request.work_scope_id,
                        "owner_verification": owner_verification,
                    }
                }
            },
            "recovery": null,
        }))
    }
}
