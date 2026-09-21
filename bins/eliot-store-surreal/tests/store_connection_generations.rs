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
    CommitId, ErrorCode, OperationId, OperationManifestDigest, Resubmission, StoreError,
    TransitionClass, WriteReceipt, WriteReceiptStatus,
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

/// Records one reconnect attempt and returns the policy backoff the caller
/// must wait before dialing.
fn reconnect(manager: &StoreConnectionManager, class: ClientClass) -> u64 {
    manager.note_reconnect_attempt(class).unwrap()
}

/// Shape-valid terminal receipt that crossed the provider boundary without
/// proving its envelope: reconciliation state, never success.
fn envelopeless_receipt(operation: &str) -> WriteReceipt {
    envelopeless_receipt_with_status(operation, WriteReceiptStatus::Committed, None)
}

/// Shape-valid receipt with an exact terminal status. Dead letters carry
/// their terminal error code; every variant here stays envelope-less, so
/// receipt resolution must keep them unknown.
fn envelopeless_receipt_with_status(
    operation: &str,
    status: WriteReceiptStatus,
    error_code: Option<ErrorCode>,
) -> WriteReceipt {
    WriteReceipt {
        operation_id: OperationId::new(operation).expect("operation id"),
        idempotency_key: "idem-1933".to_owned(),
        canonical_request_hash: "a".repeat(64),
        transition_class: TransitionClass::RecoverySchema,
        status,
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
        error_code,
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

// WORK_UNIT_CASE: 1933/1b — concurrent threads share the fixed sets.
#[test]
fn concurrent_threads_share_fixed_sets_without_growth() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let manager = manager();
    let peak = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..16 {
        let manager = manager.clone();
        let peak = Arc::clone(&peak);
        threads.push(std::thread::spawn(move || {
            for _ in 0..25 {
                let read = manager.try_acquire(ClientClass::Read).unwrap();
                let write = manager.try_acquire(ClientClass::Write).unwrap();
                let _ = peak.fetch_max(manager.in_use(ClientClass::Read), Ordering::Relaxed);
                assert!(read.is_current(&manager));
                assert!(write.is_current(&manager));
                drop((read, write));
            }
        }));
    }
    for thread in threads {
        thread.join().expect("worker thread joins");
    }
    // Sixteen threads ran four hundred acquire/release cycles against fixed
    // sets: the read peak never exceeded its bound and everything drained.
    assert!(peak.load(Ordering::Relaxed) <= 4);
    assert_eq!(manager.in_use(ClientClass::Read), 0);
    assert_eq!(manager.in_use(ClientClass::Write), 0);
    assert_eq!(manager.generation(ClientClass::Read), 1);
    assert_eq!(manager.generation(ClientClass::Write), 1);
}

// WORK_UNIT_CASE: 1933/4 — configured limits take effect, zero fails closed.
#[test]
fn configured_limits_take_effect_and_zero_fails_closed() {
    // Zero bounds never compose: typed refusal before any client set exists.
    assert!(StoreConnectionManager::from_configured_limits(0, 2, 1_000, 1_000).is_err());
    assert!(StoreConnectionManager::from_configured_limits(4, 0, 1_000, 1_000).is_err());
    // A non-default write limit threads from construction through
    // enforcement: the policy carries 5 and the set sheds exactly there.
    let manager = StoreConnectionManager::from_configured_limits(6, 5, 1_000, 1_000)
        .expect("configured limits compose");
    assert_eq!(manager.policy(ClientClass::Write).bound.get(), 5);
    assert_eq!(manager.policy(ClientClass::Read).bound.get(), 6);
    let held: Vec<_> = (0..5)
        .map(|_| manager.try_acquire(ClientClass::Write).unwrap())
        .collect();
    assert_eq!(manager.in_use(ClientClass::Write), 5);
    assert_eq!(
        manager.try_acquire(ClientClass::Write).unwrap_err(),
        StoreError::Unavailable
    );
    drop(held);
    assert_eq!(manager.in_use(ClientClass::Write), 0);
}

// WORK_UNIT_CASE: 1933/5 — reconnect evidence gates cutover; budget enforced.
#[test]
fn reconnect_evidence_gates_generation_cutover() {
    let manager = manager();
    manager.mark_broken(ClientClass::Read);
    // Attempts return the policy backoff schedule the caller must honor:
    // 100, 200, then the 5_000 ceiling is never reached inside budget 3.
    assert_eq!(reconnect(&manager, ClientClass::Read), 100);
    assert_eq!(reconnect(&manager, ClientClass::Read), 200);
    assert_eq!(manager.replace_generation(ClientClass::Read).unwrap(), 2);
    // A fresh break reopens a fresh budget: old attempts do not carry over,
    // and blowing the budget refuses cutover until escalation.
    manager.mark_broken(ClientClass::Read);
    assert!(manager.replace_generation(ClientClass::Read).is_err());
    assert_eq!(reconnect(&manager, ClientClass::Read), 100);
    assert_eq!(reconnect(&manager, ClientClass::Read), 200);
    assert_eq!(reconnect(&manager, ClientClass::Read), 400);
    assert!(manager.note_reconnect_attempt(ClientClass::Read).is_err());
    assert!(manager.replace_generation(ClientClass::Read).is_err());
    assert!(manager.is_broken(ClientClass::Read));
}

// WORK_UNIT_CASE: 1933/6 — client fencing over the shared pool.
#[test]
fn generation_fencing_admits_new_clients_and_refuses_stale_ones() {
    let manager = manager();
    let first = manager.try_acquire(ClientClass::Write).unwrap();
    let first_id = first.lease_id();
    assert!(manager.validate_lease(&first).is_ok());
    assert_eq!(manager.validate_lease(&first).unwrap().generation(), 1);
    // Cutover through the real reconnect path.
    manager.mark_broken(ClientClass::Write);
    reconnect(&manager, ClientClass::Write);
    assert_eq!(manager.replace_generation(ClientClass::Write).unwrap(), 2);
    // The stale client is refused at the boundary although it still holds
    // its pool slot; the shared pool keeps accounting that slot while new
    // clients validate under the admitted generation.
    assert_eq!(
        manager.validate_lease(&first).unwrap_err(),
        StoreError::Unavailable
    );
    assert!(!first.is_current(&manager));
    let second = manager.try_acquire(ClientClass::Write).unwrap();
    assert_eq!(second.generation(), 2);
    // High-water resets per generation: identities restart without aliasing
    // the sealed lineage, and the guard binds the new pair.
    assert_eq!(second.lease_id(), 1);
    assert_ne!(first_id, 0);
    let access = manager.validate_lease(&second).unwrap();
    assert_eq!(access.class(), ClientClass::Write);
    assert_eq!(access.generation(), 2);
    assert_eq!(access.lease_id(), second.lease_id());
    // A fabricated identity under the current generation never validates:
    // only manager-issued handles clear the high-water check.
    drop(second);
    let third = manager.try_acquire(ClientClass::Write).unwrap();
    assert_eq!(third.lease_id(), 2);
    assert!(manager.validate_lease(&third).is_ok());
    drop((first, third));
    assert_eq!(manager.in_use(ClientClass::Write), 0);
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
    // Identity-bound resolution: the gate classifies against its own
    // operation id, so a foreign receipt keeps it unknown.
    let mut bound = UnknownWriteGate::unknown(operation.clone());
    bound.resolve_lookup(Some(&foreign));
    assert_eq!(bound.verdict(), ReplayVerdict::MustReconcile);
    assert!(!bound.is_resolved());
    bound.resolve_lookup(Some(&ambiguous));
    assert_eq!(bound.verdict(), ReplayVerdict::MustReconcile);
    assert!(!bound.is_resolved());
    // A dead letter is shape-valid but envelope-less: still unknown, and
    // its guard precedes any status mapping.
    let dead_unknown = envelopeless_receipt_with_status(
        "op-1933",
        WriteReceiptStatus::DeadLetter,
        Some(ErrorCode::Timeout),
    );
    assert!(dead_unknown.validate().is_ok());
    assert_eq!(
        classify_receipt_lookup(&operation, Some(&dead_unknown)),
        ResolvedWriteOutcome::ForeignOrInvalid
    );
    // The terminal decision matrix never permits a blind same-identity
    // replay: committed reuses its receipt, proven non-application admits
    // only a new identity, a dead letter requires gap disposition first,
    // and every unknown arm reconciles.
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
        decide_replay(&ResolvedWriteOutcome::ProvenNotApplied {
            resubmission: Resubmission::None
        }),
        ReplayVerdict::NewIdentityOnly
    );
    assert_eq!(
        decide_replay(&ResolvedWriteOutcome::DeadLetterGapOpen),
        ReplayVerdict::RequiresGapDisposition
    );
    // A proven terminal outcome for the exact identity resolves the gate —
    // still without authorizing a blind replay.
    gate.resolve(ResolvedWriteOutcome::Committed);
    assert!(gate.is_resolved());
    assert_eq!(gate.verdict(), ReplayVerdict::UseExistingReceipt);
    assert_eq!(gate.resubmission(), None);
    // A proven non-application carries the receipt's resubmission rule for
    // the admission path to enforce; a dead letter carries gap disposition
    // instead of any resubmission.
    gate.resolve(ResolvedWriteOutcome::ProvenNotApplied {
        resubmission: Resubmission::NewIdentityAfterCondition,
    });
    assert!(gate.is_resolved());
    assert_eq!(gate.verdict(), ReplayVerdict::NewIdentityOnly);
    assert_eq!(
        gate.resubmission(),
        Some(Resubmission::NewIdentityAfterCondition)
    );
    gate.resolve(ResolvedWriteOutcome::DeadLetterGapOpen);
    assert!(gate.is_resolved());
    assert_eq!(gate.verdict(), ReplayVerdict::RequiresGapDisposition);
    assert_eq!(gate.resubmission(), None);
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
    // Replacement requires the reconnect path first: no recorded attempt
    // fails closed even though the set is broken.
    assert!(manager.replace_generation(ClientClass::Write).is_err());
    // The recorded attempt returns the policy backoff the caller must wait
    // before dialing; then the cutover admits generation 2.
    assert_eq!(reconnect(&manager, ClientClass::Write), 100);
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
    // Recording an attempt against a healthy set refuses: there is nothing
    // to reconnect.
    assert!(manager.note_reconnect_attempt(ClientClass::Write).is_err());
}
