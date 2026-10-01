//! Canonical owner boundary for selected-source ProposedAttempt mutations.
//!
//! The caller supplies a semantically admitted prepared transition; this
//! module does not mint authority or reconstruct ORS capabilities. It performs
//! the original canonical write through the active Kernel gateway and returns
//! only the exact original receipt and typed record read back from that owner.

use eliot_contracts::RequestMetadata;
use eliot_store_api::{
    CONTRACT_VERSION, NamedMutationOperation, OrderingHeadExpectation, PreparedTransition,
    ProposedAttemptRecord, RecoveryRecord, RevisionHeadExpectation, StoreRecoveryRequest, WriteReceipt,
    WriteReceiptStatus,
    proposed_attempt_record_key,
};

use crate::{KernelStoreGateway, StoreApplyRefusal};

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
    let original_operation_id = transition.identity.operation_id.clone();
    let expected_identity = transition.identity.clone();
    let receipt = gateway
        .apply(
            context,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .await
        .map_err(|error: StoreApplyRefusal| error.to_string())?;
    if receipt.operation_id != original_operation_id
        || receipt.idempotency_key != expected_identity.idempotency_key
        || receipt.canonical_request_hash != expected_identity.canonical_request_hash
        || receipt.state_fence != record.state_fence
        || receipt.status != WriteReceiptStatus::Committed
        || receipt.outbox_refs.is_empty()
    {
        return Err("canonical receipt does not match the original source-capture mutation".to_owned());
    }
    let exact_receipt = gateway
        .receipt(&record.state_fence, original_operation_id.clone())
        .await?
        .ok_or_else(|| "canonical owner omitted the original terminal write receipt".to_owned())?;
    if exact_receipt != receipt {
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
        receipt: exact_receipt,
        record_readback: readback,
    })
}
