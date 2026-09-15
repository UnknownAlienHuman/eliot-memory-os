//! Shared position transaction cases for the reference Store.
use super::*;
use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::TaskRevision;
use eliot_epistemic_contracts::{ClaimVerdict, PositionRevision, SupportResult};
use eliot_store_api::{ReadConsistency, epistemic_revision::EpistemicPositionReadback};
#[path = "../../eliot-store-api/tests/support/epistemic_envelope.rs"]
mod fixture;
use fixture::envelope;
type ProofResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn apply(store: &MemoryStore, envelope: &CanonicalWriteEnvelope) -> ProofResult<WriteReceipt> {
    Ok(store.apply_transaction(
        &envelope.request,
        envelope.prepare()?,
        &envelope.expected_revision_heads,
        &envelope.expected_ordering_heads,
    )?)
}

#[test]
fn position_cas_replay_and_external_receipt_remain_atomic() -> ProofResult {
    let store = MemoryStore::new();
    let first = envelope("first", "position", None, None)?;
    let receipt = apply(&store, &first)?;
    let snapshot = store.snapshot()?;
    assert_eq!(apply(&store, &first)?, receipt);
    assert_eq!(store.snapshot()?, snapshot);
    let stale = envelope("stale", "position", None, None)?;
    assert!(matches!(
        store.apply_transaction(
            &stale.request,
            stale.prepare()?,
            &stale.expected_revision_heads,
            &stale.expected_ordering_heads
        ),
        Err(StoreError::RevisionConflict)
    ));
    assert_eq!(store.snapshot()?, snapshot);
    let changed = envelope("first", "another-position", None, None)?;
    assert!(matches!(
        store.apply_transaction(
            &changed.request,
            changed.prepare()?,
            &changed.expected_revision_heads,
            &changed.expected_ordering_heads
        ),
        Err(StoreError::IdentityConflict)
    ));
    assert_eq!(store.snapshot()?, snapshot);
    let query = NamedReadRequest {
        operation: NamedReadOperation::GetCurrentEpistemicPosition,
        scope_id: Some(first.scope_id.clone()),
        consistency: ReadConsistency::ExactFence,
        state_fence: first.request.state_fence.clone(),
        parameters: BTreeMap::from([("position".to_owned(), json!("position"))]),
    };
    let readback: EpistemicPositionReadback =
        serde_json::from_value(store.execute_named_sync(&query)?.payload)?;
    assert_eq!(readback.receipt, receipt);
    assert_eq!(readback.positions[0].admission.position_revision.value(), 1);
    assert_eq!(readback.candidate.support[0].result, SupportResult::Unknown);
    assert_eq!(readback.candidate.claims[0].verdict, ClaimVerdict::Withheld);
    let wrong_predecessor = envelope(
        "wrong-prior",
        "position",
        Some(PositionRevision::new(1)?),
        Some("other-candidate"),
    )?;
    assert!(matches!(
        store.apply_transaction(
            &wrong_predecessor.request,
            wrong_predecessor.prepare()?,
            &wrong_predecessor.expected_revision_heads,
            &wrong_predecessor.expected_ordering_heads
        ),
        Err(StoreError::RevisionConflict)
    ));
    assert_eq!(store.snapshot()?, snapshot);
    let next = envelope(
        "next",
        "position",
        Some(PositionRevision::new(1)?),
        Some(&readback.candidate.digest),
    )?;
    let second_receipt = apply(&store, &next)?;
    let readback: EpistemicPositionReadback =
        serde_json::from_value(store.execute_named_sync(&query)?.payload)?;
    assert_eq!(readback.receipt, second_receipt);
    assert_eq!(readback.positions[0].admission.position_revision.value(), 2);
    assert_eq!(readback.candidate.revision, TaskRevision::genesis());
    assert_eq!(store.snapshot()?.receipts.len(), 2);
    Ok(())
}
