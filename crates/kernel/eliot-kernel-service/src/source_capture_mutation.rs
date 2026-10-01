//! Canonical owner boundary for selected-source ProposedAttempt mutations.
//!
//! The caller supplies a semantically admitted prepared transition; this
//! module does not mint authority or reconstruct ORS capabilities. It performs
//! the original canonical write through the active Kernel gateway and returns
//! only the exact original receipt and typed record read back from that owner.

use eliot_contracts::RequestMetadata;
use eliot_ors::{
    AdmissionReservationClaims, AdmissionReservationIdentityInput,
    AdmissionReservationStageRequest, AdmissionReservationStagedOutcome, EpochLineage,
    OperationalRecoveryStore, OperationIdentity, StateFenceSnapshot,
    admission_reservation_identity, epoch_lineage_for, proposed_attempt_identity,
    stage_admission_reservation_inactive, stage_operation_identity,
};
use eliot_protocol::{
    HostRequestEnvelope, HostRequestKind, RequestIdentity, SelectedSourceCaptureInvocation,
    host_request_operation_id,
};
use eliot_store_api::{
    CONTRACT_VERSION, NamedMutationOperation, OrderingHeadExpectation, PreparedTransition,
    CausalWriteReceipt, ProposedAttemptRecord, RecoveryRecord, RevisionHeadExpectation,
    StoreRecoveryRequest, WriteReceipt, WriteReceiptStatus,
    proposed_attempt_record_key,
};

use crate::{KernelStoreGateway, StoreApplyRefusal};

/// Governor-owned facts required to stage one selected-source admission.
/// Kernel fills identity and epoch/fence fields from the retained original
/// HostRequest; this DTO contains only current owner-resolved work/profile
/// evidence and the complete typed ORS claim set.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedSourceCaptureStageIntent {
    pub work_item_id: OperationIdentity,
    pub work_lease_id: String,
    pub principal_id: String,
    pub operation: String,
    pub selected_relative_path: String,
    pub selector: Option<String>,
    pub source_digest: String,
    pub configuration_digest: String,
    pub action_contract_digest: String,
    pub semantic_admission_revision: String,
    pub claims: AdmissionReservationClaims,
}

/// Exact inactive ORS stage and the typed canonical record projection that the
/// Governor must place into its normal `CanonicalWriteEnvelope`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedSourceCaptureStageOutcome {
    pub record: eliot_store_api::ProposedAttemptRecord,
    pub staged: AdmissionReservationStagedOutcome,
    pub stage_receipt_id: String,
}

/// Stages the inactive ORS half from the exact retained HostRequest and
/// Governor-resolved WorkItem/profile facts. It writes no canonical admission
/// and grants no execution authority.
pub fn stage_selected_source_capture(
    store: &dyn OperationalRecoveryStore,
    envelope: &HostRequestEnvelope,
    invocation: &SelectedSourceCaptureInvocation,
    request_identity: &RequestIdentity,
    intent: &SelectedSourceCaptureStageIntent,
    now_unix_ms: i64,
) -> Result<SelectedSourceCaptureStageOutcome, String> {
    envelope
        .validate_for_admission()
        .map_err(|error| error.to_string())?;
    invocation
        .validate()
        .map_err(|error| error.to_string())?;
    request_identity
        .validate()
        .map_err(|error| error.to_string())?;
    if envelope.kind != HostRequestKind::SelectedSourceCapture
        || request_identity.request.state_fence != envelope.state_fence
        || request_identity.request.metadata.state_fence != envelope.state_fence
        || request_identity.request.metadata.request_id != envelope.identity.request_id
        || request_identity.idempotency_key != envelope.identity.idempotency_key
        || request_identity.cancellation_id != envelope.identity.cancellation_id
        || request_identity.deadline_unix_ms != envelope.identity.deadline_unix_ms
        || intent.operation != match invocation.operation {
            eliot_protocol::SelectedSourceCaptureOperation::Diagnostics => "Diagnostics",
            eliot_protocol::SelectedSourceCaptureOperation::ProbeVersion => "ProbeVersion",
        }
        || intent.selected_relative_path != invocation.selected_relative_path
        || intent.selector != invocation.selector
        || now_unix_ms <= 0
        || i64::try_from(envelope.identity.deadline_unix_ms)
            .map_err(|_| "source-capture deadline is outside the ORS range".to_owned())?
            <= now_unix_ms
    {
        return Err("source-capture stage does not match the original admitted request".to_owned());
    }
    intent.claims.validate().map_err(|error| error.to_string())?;
    for (value, field) in [
        (intent.work_lease_id.as_str(), "work_lease_id"),
        (intent.principal_id.as_str(), "principal_id"),
        (intent.source_digest.as_str(), "source_digest"),
        (intent.configuration_digest.as_str(), "configuration_digest"),
        (intent.action_contract_digest.as_str(), "action_contract_digest"),
        (
            intent.semantic_admission_revision.as_str(),
            "semantic_admission_revision",
        ),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(format!("source-capture {field} is invalid"));
        }
    }
    let authority_epoch: EpochLineage =
        epoch_lineage_for(&envelope.state_fence.authority_epoch, None)
            .map_err(|error| error.to_string())?;
    let state_fence = StateFenceSnapshot::capture(
        &envelope.state_fence,
        envelope.state_fence.authority_epoch.sequence.get(),
    )
    .and_then(|snapshot| {
        snapshot
            .validate_against_lineage(&authority_epoch)
            .map(|()| snapshot)
    })
    .map_err(|error| error.to_string())?;

    // `proposed_attempt_identity` validates an immutable binding that includes
    // an attempt slot, but its derived preimage intentionally excludes that
    // slot. Seed only that validation call with a deterministic non-persisted
    // marker, then bind the returned distinct identity into the reservation.
    let mut identity_input = AdmissionReservationIdentityInput {
        work_item_id: intent.work_item_id.clone(),
        proposed_attempt_id: OperationIdentity::new(format!(
            "source-capture-seed:{}",
            host_request_operation_id(envelope)
        ))
        .map_err(|error| error.to_string())?,
        causal_operation_id: Some(
            OperationIdentity::new(host_request_operation_id(envelope))
                .map_err(|error| error.to_string())?,
        ),
        semantic_admission_revision: intent.semantic_admission_revision.clone(),
        claims: intent.claims.clone(),
        state_fence: state_fence.clone(),
        authority_epoch: authority_epoch.clone(),
    };
    let proposed_attempt_id = proposed_attempt_identity(&identity_input)
        .map_err(|error| error.to_string())?;
    if proposed_attempt_id == intent.work_item_id {
        return Err("ProposedAttempt identity aliases its original WorkItem".to_owned());
    }
    identity_input.proposed_attempt_id = proposed_attempt_id.clone();
    let reservation_id = admission_reservation_identity(&identity_input)
        .map_err(|error| error.to_string())?;
    let stage_operation_id =
        stage_operation_identity(&reservation_id).map_err(|error| error.to_string())?;
    let staged = stage_admission_reservation_inactive(
        store,
        &AdmissionReservationStageRequest {
            reservation_id: reservation_id.clone(),
            work_item_id: intent.work_item_id.clone(),
            proposed_attempt_id: proposed_attempt_id.clone(),
            operation_id: stage_operation_id,
            claims: intent.claims.clone(),
            authority_epoch: authority_epoch.clone(),
            state_fence: state_fence.clone(),
            expires_at_ms: i64::try_from(envelope.identity.deadline_unix_ms)
                .map_err(|_| "source-capture deadline is outside the ORS range".to_owned())?,
            now_unix_ms,
        },
    )
    .map_err(|error| error.to_string())?;
    let staged_record = staged.snapshot.record();
    let stage_receipt_id = staged.snapshot.receipt().record_id().as_str().to_owned();
    if staged.reservation_id != reservation_id
        || staged_record.work_item_id != intent.work_item_id
        || staged_record.proposed_attempt_id != proposed_attempt_id
        || staged_record.state != eliot_ors::AdmissionReservationState::StagedInactive
        || staged_record.claims != intent.claims
        || staged_record.state_fence != state_fence
        || staged_record.authority_epoch != authority_epoch
        || stage_receipt_id.trim().is_empty()
    {
        return Err("ORS returned a staged row that differs from the selected-source proposal".to_owned());
    }
    let request_identity_value = serde_json::to_value(request_identity)
        .map_err(|error| error.to_string())?;
    let record = eliot_store_api::ProposedAttemptRecord {
        work_item_id: intent.work_item_id.as_str().to_owned(),
        proposed_attempt_id: proposed_attempt_id.as_str().to_owned(),
        reservation_id: reservation_id.as_str().to_owned(),
        reservation_stage_receipt_id: stage_receipt_id.clone(),
        request_identity: request_identity_value,
        parent_operation_id: host_request_operation_id(envelope),
        task_id: envelope.identity.task_id.clone().ok_or_else(|| {
            "selected-source request omitted its original Task binding".to_owned()
        })?,
        session_id: envelope.identity.session_id.clone().ok_or_else(|| {
            "selected-source request omitted its original Session binding".to_owned()
        })?,
        work_scope_id: envelope.identity.work_scope_id.clone().ok_or_else(|| {
            "selected-source request omitted its original WorkScope binding".to_owned()
        })?,
        work_lease_id: intent.work_lease_id.clone(),
        principal_id: intent.principal_id.clone(),
        operation: intent.operation.clone(),
        selected_relative_path: intent.selected_relative_path.clone(),
        selector: intent.selector.clone(),
        source_digest: intent.source_digest.clone(),
        configuration_digest: intent.configuration_digest.clone(),
        action_contract_digest: intent.action_contract_digest.clone(),
        authority_epoch: serde_json::to_value(&authority_epoch).map_err(|error| error.to_string())?,
        reservation_claims: serde_json::to_value(&intent.claims).map_err(|error| error.to_string())?,
        state_fence: envelope.state_fence.clone(),
        disposition: "ADMITTED".to_owned(),
        created_at_ms: now_unix_ms,
    };
    record.validate().map_err(|error| error.to_string())?;
    Ok(SelectedSourceCaptureStageOutcome {
        record,
        stage_receipt_id,
        staged,
    })
}

/// Exact canonical outcome after the owner has written and read back one
/// ProposedAttempt and its terminal receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalProposedAttemptAdmission {
    /// Typed record recovered from the canonical owner row.
    pub record: ProposedAttemptRecord,
    /// Exact original canonical receipt returned by the owner read path.
    pub receipt: WriteReceipt,
    /// Exact owner recovery row used to validate the typed record payload.
    pub record_readback: RecoveryRecord,
    /// Causal owner projection returned with the exact original receipt.
    pub causal_receipt: CausalWriteReceipt,
}

/// Writes one already-admitted ProposedAttempt through the canonical owner,
/// then independently re-reads the original receipt and exact typed row.
///
/// `transition` must contain exactly one `AdmitProposedAttempt` operation;
/// normal Store admission remains responsible for validating its manifest,
/// effect ceiling, caller and current fence. The Store's ordinary prepared
/// write creates its existing Launch outbox reference in the same transaction.
/// This function never treats a native claim receipt as canonical evidence.
pub async fn admit_proposed_attempt(
    gateway: &KernelStoreGateway,
    context: &RequestMetadata,
    transition: PreparedTransition,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<CanonicalProposedAttemptAdmission, String> {
    let matching = transition
        .named_operations
        .iter()
        .filter(|command| command.operation == NamedMutationOperation::AdmitProposedAttempt)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err("prepared source-capture transition must contain exactly one ProposedAttempt".to_owned());
    }
    let record = eliot_store_api::decode_proposed_attempt_record(
        NamedMutationOperation::AdmitProposedAttempt,
        &matching[0].parameters,
    )
    .map_err(|error| error.to_string())?;
    if record.state_fence != transition.state_fence
        || record.task_id != transition.task_id.as_deref().unwrap_or_default()
        || context.state_fence != transition.state_fence
    {
        return Err("ProposedAttempt task or fence differs from the admitted transition".to_owned());
    }
    let expected_identity = transition.identity.clone();
    let causal_receipt = gateway
        .apply_with_causal(
            context,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .await
        .map_err(|error: StoreApplyRefusal| error.to_string())?;
    verify_proposed_attempt_readback(gateway, record, expected_identity, causal_receipt).await
}

/// Re-reads the original terminal receipt and typed ProposedAttempt row after
/// the normal Kernel `apply_prepared` owner has committed the prepared
/// transition. The receipt is never reconstructed from the request.
pub async fn verify_proposed_attempt_readback(
    gateway: &KernelStoreGateway,
    record: ProposedAttemptRecord,
    expected_identity: eliot_store_api::OperationIdentity,
    causal_receipt: CausalWriteReceipt,
) -> Result<CanonicalProposedAttemptAdmission, String> {
    let receipt = causal_receipt.receipt.clone();
    let original_operation_id = receipt.operation_id.clone();
    if receipt.operation_id != expected_identity.operation_id
        || receipt.idempotency_key != expected_identity.idempotency_key
        || receipt.canonical_request_hash != expected_identity.canonical_request_hash
        || receipt.state_fence != record.state_fence
        || receipt.status != WriteReceiptStatus::Committed
        || receipt.outbox_refs.is_empty()
    {
        return Err("canonical receipt does not match the original source-capture mutation".to_owned());
    }
    let exact_receipt = gateway
        .receipt_with_causal(&record.state_fence, original_operation_id.clone())
        .await?
        .ok_or_else(|| "canonical owner omitted the original terminal write receipt".to_owned())?;
    if exact_receipt != causal_receipt {
        return Err("canonical terminal receipt readback differs from the original receipt".to_owned());
    }

    let key = proposed_attempt_record_key(&record.work_item_id, &record.proposed_attempt_id);
    let snapshot = gateway
        .recovery(StoreRecoveryRequest {
            contract_version: CONTRACT_VERSION,
            state_fence: record.state_fence.clone(),
            records: vec![key],
            include_receipts: false,
            include_jobs: false,
        })
        .await?;
    let readback = snapshot
        .owner_records
        .into_iter()
        .next()
        .ok_or_else(|| "canonical owner omitted the ProposedAttempt recovery row".to_owned())?;
    if readback != record.recovery_record().map_err(|error| error.to_string())? {
        return Err("canonical ProposedAttempt row differs from the original typed record".to_owned());
    }
    let payload = std::str::from_utf8(&readback.payload)
        .map_err(|_| "canonical ProposedAttempt payload is not UTF-8".to_owned())?;
    let decoded: ProposedAttemptRecord = serde_json::from_str(payload)
        .map_err(|_| "canonical ProposedAttempt payload is not a typed record".to_owned())?;
    decoded.validate().map_err(|error| error.to_string())?;
    if decoded != record {
        return Err("canonical ProposedAttempt typed readback changed the original identity".to_owned());
    }
    Ok(CanonicalProposedAttemptAdmission {
        record: decoded,
        receipt: exact_receipt.receipt.clone(),
        record_readback: readback,
        causal_receipt: exact_receipt,
    })
}
