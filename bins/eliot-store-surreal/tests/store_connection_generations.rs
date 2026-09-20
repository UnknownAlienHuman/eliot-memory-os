//! Bridge connection-generation acceptance proof (issue #1933).
//!
//! Three cases mirror the acceptance criteria through production boundary
//! code with no provider instance: bounded class-specific sets reuse slots
//! instead of growing per request, an unknown write resolves by its original
//! operation identity before any new attempt is permissible, and health
//! traffic stays on its isolated path without consuming a write slot.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::num::NonZeroUsize;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_store_api::{
    CommitId, OperationId, OperationManifestDigest, Resubmission, StoreError, TransitionClass,
    WriteReceipt, WriteReceiptStatus,
};
use eliot_store_surreal::{
    ClientClass, HealthAdminAdmission, ReplayVerdict, ResolvedWriteOutcome, StoreConnectionManager,
    UnknownWriteGate, classify_receipt_lookup, decide_replay,
};

const LINEAGE_1933: &str = "550e8400-e29b-41d4-a716-446655440000";

fn manager() -> StoreConnectionManager {
    StoreConnectionManager::from_timeouts(
        NonZeroUsize::new(4).expect("read bound"),
        NonZeroUsize::new(2).expect("write limit"),
        1_000,
        1_000,
    )
    .expect("bounded client sets compose")
}

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE_1933).expect("lineage");
    let epoch =
        EpochId::new(lineage, std::num::NonZeroU64::new(1).expect("sequence")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

/// Shape-valid terminal receipt that crossed the provider boundary without
/// proving its envelope: reconciliation state, never success.
fn envelopeless_receipt(operation: &str) -> WriteReceipt {
    WriteReceipt {
        operation_id: OperationId::new(operation).expect("operation id"),
        idempotency_key: "idem-1933".to_owned(),
        canonical_request_hash: "a".repeat(64),
        transition_class: TransitionClass::RecoverySchema,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-1933").expect("commit")),
        state_fence: fence(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["genesis-seed".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: OperationManifestDigest::new("manifest-1933")
            .expect("manifest digest"),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    }
}

// WORK_UNIT_CASE: 1933/1 — bounded class sets reuse without per-request growth.
#[test]
fn bounded_class_sets_reuse_without_per_request_growth() {
    let manager = manager();
    assert_eq!(manager.generation(ClientClass::Read), 1);
    assert_eq!(manager.generation(ClientClass::Write), 1);
    // Repeated concurrent-style named reads and writes reuse the fixed
    // sets: fifty acquire/release cycles never hold more than the bound
    // and always drain back to zero.
    for _ in 0..50 {
        let read = manager.try_acquire(ClientClass::Read).unwrap();
        let write = manager.try_acquire(ClientClass::Write).unwrap();
        assert!(read.is_current(&manager));
        assert!(write.is_current(&manager));
        assert!(manager.in_use(ClientClass::Read) <= 4);
        assert!(manager.in_use(ClientClass::Write) <= 2);
        drop((read, write));
    }
    assert_eq!(manager.in_use(ClientClass::Read), 0);
    assert_eq!(manager.in_use(ClientClass::Write), 0);
    // Exhaustion sheds load instead of growing: the write set holds exactly
    // its limit, the next acquisition refuses, and release reopens the slot.
    let first = manager.try_acquire(ClientClass::Write).unwrap();
    let second = manager.try_acquire(ClientClass::Write).unwrap();
    assert_eq!(manager.in_use(ClientClass::Write), 2);
    assert_eq!(
        manager.try_acquire(ClientClass::Write).unwrap_err(),
        StoreError::Unavailable
    );
    drop(first);
    assert!(manager.try_acquire(ClientClass::Write).is_ok());
    drop(second);
}

// WORK_UNIT_CASE: 1933/2 — unknown write resolves by operation id before replay.
#[test]
fn unknown_write_resolves_by_operation_id_before_any_new_attempt() {
    let operation = OperationId::new("op-1933").expect("operation id");
    let mut gate = UnknownWriteGate::unknown(operation.clone());
    // A fresh transport failure authorizes nothing.
    assert_eq!(gate.verdict(), ReplayVerdict::MustReconcile);
    assert!(!gate.is_resolved());
    // A missing receipt keeps the outcome unknown: no blind replay.
    gate.resolve(classify_receipt_lookup(&operation, None));
    assert_eq!(gate.verdict(), ReplayVerdict::MustReconcile);
    assert!(!gate.is_resolved());
    // An envelope-less observation for the exact identity stays unknown.
    let ambiguous = envelopeless_receipt("op-1933");
    assert!(ambiguous.validate().is_ok());
    gate.resolve(classify_receipt_lookup(&operation, Some(&ambiguous)));
    assert_eq!(
        classify_receipt_lookup(&operation, Some(&ambiguous)),
        ResolvedWriteOutcome::ForeignOrInvalid
    );
    assert_eq!(gate.verdict(), ReplayVerdict::MustReconcile);
    assert!(!gate.is_resolved());
    // A receipt for another identity cannot resolve this gate.
    let foreign = envelopeless_receipt("op-other");
    assert_eq!(
        classify_receipt_lookup(&operation, Some(&foreign)),
        ResolvedWriteOutcome::ForeignOrInvalid
    );
    // The terminal decision matrix never permits a blind same-identity
    // replay: committed reuses its receipt, proven non-application admits
    // only a new identity, and every unknown arm reconciles.
    assert_eq!(
        decide_replay(&ResolvedWriteOutcome::Absent),
        ReplayVerdict::MustReconcile
    );
    assert_eq!(
        decide_replay(&ResolvedWriteOutcome::ForeignOrInvalid),
        ReplayVerdict::MustReconcile
    );
    assert_eq!(
        decide_replay(&ResolvedWriteOutcome::Committed),
        ReplayVerdict::UseExistingReceipt
    );
    assert_eq!(
        decide_replay(&ResolvedWriteOutcome::ProvenNotApplied),
        ReplayVerdict::NewIdentityOnly
    );
    // A proven terminal outcome for the exact identity resolves the gate —
    // still without authorizing a blind replay.
    gate.resolve(ResolvedWriteOutcome::Committed);
    assert!(gate.is_resolved());
    assert_eq!(gate.verdict(), ReplayVerdict::UseExistingReceipt);
}

// WORK_UNIT_CASE: 1933/3 — health stays isolated without consuming a write slot.
#[test]
fn health_continues_on_its_isolated_path_without_a_write_slot() {
    let manager = manager();
    let admission = HealthAdminAdmission::bridge_default();
    // Only the exact health/readiness operations ride the isolated path.
    assert!(admission.is_admitted("store.health"));
    assert!(admission.is_admitted("store.readiness"));
    assert!(!admission.is_admitted("store.apply"));
    // Saturate every write slot: health still acquires its own client.
    let writes: Vec<_> = (0..2)
        .map(|_| manager.try_acquire(ClientClass::Write).unwrap())
        .collect();
    assert_eq!(manager.in_use(ClientClass::Write), 2);
    let health = manager.try_acquire(ClientClass::Health).unwrap();
    assert_eq!(health.class(), ClientClass::Health);
    assert_eq!(manager.in_use(ClientClass::Write), 2);
    drop(health);
    assert_eq!(manager.in_use(ClientClass::Write), 2);
    drop(writes);
    assert_eq!(manager.in_use(ClientClass::Write), 0);
    // A broken write generation refuses new writes while health is
    // unaffected; explicit replacement reopens writes at a new generation
    // and stale leases report themselves.
    let stale = manager.try_acquire(ClientClass::Write).unwrap();
    manager.mark_broken(ClientClass::Write);
    assert!(manager.is_broken(ClientClass::Write));
    assert!(!manager.is_broken(ClientClass::Health));
    assert_eq!(
        manager.try_acquire(ClientClass::Write).unwrap_err(),
        StoreError::Unavailable
    );
    assert!(manager.try_acquire(ClientClass::Health).is_ok());
    assert_eq!(manager.replace_generation(ClientClass::Write).unwrap(), 2);
    assert!(!manager.is_broken(ClientClass::Write));
    assert!(!stale.is_current(&manager));
    assert!(
        manager
            .try_acquire(ClientClass::Write)
            .unwrap()
            .is_current(&manager)
    );
    // Replacement without a marked failure refuses: generations advance
    // only as declared recovery.
    assert!(manager.replace_generation(ClientClass::Write).is_err());
}
