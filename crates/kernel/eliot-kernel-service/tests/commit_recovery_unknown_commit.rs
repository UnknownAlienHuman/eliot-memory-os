//! Unknown-commit recovery behaviour (I14.21, issue #1690).
//!
//! These tests drive the production [`recover_commit`] procedure with
//! scripted commit/query closures and a real temporary ORS database: every
//! stage, pause, disposition, resolve, and retry line below is the executed
//! production logic, not a copy. The scripted `send` outcome stands in for
//! what the transport client returns after its own exact receipt lookup
//! (covered separately in `store_client` tests): the procedure under test
//! never sends blindly and never synthesizes acceptance.
//!
//! Three scenarios mirror the issue acceptance plus the mandated
//! known-rollback retry:
//! 1. a committed receipt returns after one send, with no second mutation
//!    and nothing staged;
//! 2. a response loss with no evidence opens Problem State, pauses the
//!    scope, refuses dependents, then disposes without a new send once
//!    receipt evidence arrives;
//! 3. a known rollback retries exactly once under the identical identity.

use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use eliot_kernel_service::{
    CommitRecoveryError, classify_commit_receipt, paused_ordering_scope_view,
    paused_scopes_snapshot, recover_commit,
};
use eliot_ors::RedbRecoveryStore;
use eliot_store_api::{
    OperationId, OperationIdentity, Resubmission, StateFence, StoreError, TransitionClass,
    WriteReceipt, WriteReceiptStatus,
};

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

type SendOutcome = Result<WriteReceipt, StoreError>;

fn test_fence() -> StateFence {
    let lineage = eliot_contracts::EpochLineageId::new(TEST_LINEAGE).expect("lineage");
    let epoch = eliot_contracts::EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero"))
        .expect("epoch");
    StateFence::new(
        epoch,
        eliot_contracts::ResourceGeneration::new(1).expect("generation"),
    )
}

fn test_identity(tag: &str) -> OperationIdentity {
    OperationIdentity {
        operation_id: OperationId::new(format!("op-1690-{tag}")).expect("operation"),
        idempotency_key: format!("key-1690-{tag}"),
        canonical_request_hash: "a".repeat(64),
    }
}

fn test_receipt(
    identity: &OperationIdentity,
    status: WriteReceiptStatus,
    resubmission: Resubmission,
) -> WriteReceipt {
    WriteReceipt {
        operation_id: identity.operation_id.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        canonical_request_hash: identity.canonical_request_hash.clone(),
        transition_class: TransitionClass::CaptureCandidate,
        status,
        commit_id: None,
        state_fence: test_fence(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: Vec::new(),
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: eliot_store_api::OperationManifestDigest::new("manifest-1690")
            .expect("manifest"),
        error_code: None,
        resubmission,
        committed_at: None,
        envelope: None,
    }
}

fn temp_ors(tag: &str) -> (RedbRecoveryStore, std::path::PathBuf) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "eliot-1690-recovery-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("recovery temp root");
    let ors = RedbRecoveryStore::open(dir.join("recovery.redb")).expect("recovery ors opens");
    (ors, dir)
}

fn remove_temp(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

type BoxSend = Pin<Box<dyn Future<Output = SendOutcome> + Send>>;

/// Scripts `send` outcomes in call order and counts the sends.
fn scripted_send(script: Vec<SendOutcome>, counter: &Arc<Mutex<usize>>) -> impl FnMut() -> BoxSend {
    let script = Arc::new(Mutex::new(VecDeque::from(script)));
    let counter = Arc::clone(counter);
    move || {
        let script = Arc::clone(&script);
        let counter = Arc::clone(&counter);
        Box::pin(async move {
            *counter.lock().expect("send counter") += 1;
            script
                .lock()
                .expect("send script")
                .pop_front()
                .expect("send script has an outcome per call")
        }) as BoxSend
    }
}

/// Scripts `query` outcomes in call order.
fn scripted_query(script: Vec<SendOutcome>) -> impl Fn() -> BoxSend {
    let script = Arc::new(Mutex::new(VecDeque::from(script)));
    move || {
        let script = Arc::clone(&script);
        Box::pin(async move {
            script
                .lock()
                .expect("query script")
                .pop_front()
                .expect("query script has an outcome per call")
        }) as BoxSend
    }
}

async fn unreachable_outcome(path: &'static str) -> SendOutcome {
    panic!("recovery must not {path} on this path")
}

fn never_query() -> impl Fn() -> BoxSend {
    || Box::pin(unreachable_outcome("query the receipt"))
}

fn never_send() -> impl FnMut() -> BoxSend {
    || Box::pin(unreachable_outcome("send"))
}

// Acceptance 1: a committed receipt after response loss returns after
// exactly one send, with no second mutation and nothing staged.
#[tokio::test]
async fn committed_receipt_returns_after_exactly_one_send() {
    let (ors, dir) = temp_ors("committed");
    let paused = Mutex::new(BTreeSet::new());
    let identity = test_identity("committed");
    let committed = test_receipt(&identity, WriteReceiptStatus::Committed, Resubmission::None);
    let sends = Arc::new(Mutex::new(0_usize));
    // The scripted send stands in for the transport client's return after
    // its own exact receipt lookup reconciled the lost response.
    let send = scripted_send(vec![Ok(committed.clone())], &sends);
    let receipt = recover_commit(
        Some(&ors),
        &paused,
        &identity,
        &["scope-1690-a".to_owned()],
        send,
        never_query(),
    )
    .await
    .expect("committed receipt returns");
    assert_eq!(receipt, committed);
    assert_eq!(*sends.lock().expect("sends"), 1, "no second mutation");
    assert!(
        ors.load_unknown_commit(&identity.idempotency_key)
            .expect("load")
            .is_none(),
        "healthy commit stages nothing"
    );
    remove_temp(&dir);
}

// Acceptance 2: response loss with no evidence preserves the operation,
// pauses the scope, refuses dependents, then disposes with no new send
// once receipt evidence arrives.
#[tokio::test]
async fn unknown_commit_pauses_scope_and_disposes_on_evidence() {
    let (ors, dir) = temp_ors("unknown");
    let paused = Mutex::new(BTreeSet::new());
    let identity = test_identity("unknown");
    let scopes = vec!["scope-1690-b".to_owned()];
    let sends = Arc::new(Mutex::new(0_usize));

    // Phase 1: the send outcome is unknown and no receipt evidence exists.
    let send = scripted_send(vec![Err(StoreError::MissingReceiptEnvelope)], &sends);
    let query = scripted_query(vec![Err(StoreError::MissingReceiptEnvelope)]);
    match recover_commit(Some(&ors), &paused, &identity, &scopes, send, query).await {
        Err(CommitRecoveryError::UnknownCommitOpen {
            idempotency_key,
            preserved,
            ..
        }) => {
            assert_eq!(idempotency_key, identity.idempotency_key);
            assert!(preserved, "the operation is preserved");
        }
        other => panic!("unknown outcome must open problem state, got {other:?}"),
    }
    assert_eq!(*sends.lock().expect("sends"), 1);
    let open = ors
        .load_unknown_commit(&identity.idempotency_key)
        .expect("load")
        .expect("unknown commit staged");
    assert!(open.is_open());
    assert_eq!(open.ordering_scopes, scopes);
    assert_eq!(paused_scopes_snapshot(&paused), scopes);
    assert_eq!(
        paused_ordering_scope_view(&paused, Some(&ors)),
        vec![(scopes[0].clone(), identity.idempotency_key.clone())],
        "the visible problem state names the pausing key"
    );

    // Phase 2: a dependent mutation in the paused scope is refused without
    // any send.
    let dependent = test_identity("unknown-dependent");
    match recover_commit(
        Some(&ors),
        &paused,
        &dependent,
        &scopes,
        never_send(),
        never_query(),
    )
    .await
    {
        Err(CommitRecoveryError::ScopePaused {
            scope,
            paused_by_key,
        }) => {
            assert_eq!(scope, scopes[0]);
            assert_eq!(paused_by_key, identity.idempotency_key);
        }
        other => panic!("dependent in a paused scope must be refused, got {other:?}"),
    }

    // Phase 3: receipt evidence arrives. The same key dispositions with no
    // new send, and the record resolves with the receipt digest.
    let committed = test_receipt(&identity, WriteReceiptStatus::Committed, Resubmission::None);
    let send = scripted_send(vec![], &sends);
    let query = scripted_query(vec![Ok(committed.clone())]);
    let receipt = recover_commit(Some(&ors), &paused, &identity, &scopes, send, query)
        .await
        .expect("evidence-backed disposition returns the receipt");
    assert_eq!(receipt, committed);
    assert_eq!(
        *sends.lock().expect("sends"),
        1,
        "disposition sends nothing"
    );
    let resolved = ors
        .load_unknown_commit(&identity.idempotency_key)
        .expect("load")
        .expect("record kept as terminal evidence");
    assert!(!resolved.is_open());

    // Phase 4: the scope is unpaused; the dependent now proceeds.
    let dependent_receipt = test_receipt(
        &dependent,
        WriteReceiptStatus::Committed,
        Resubmission::None,
    );
    let send = scripted_send(vec![Ok(dependent_receipt.clone())], &sends);
    let receipt = recover_commit(
        Some(&ors),
        &paused,
        &dependent,
        &scopes,
        send,
        never_query(),
    )
    .await
    .expect("dependent proceeds after disposition");
    assert_eq!(receipt, dependent_receipt);
    remove_temp(&dir);
}

// A known rollback on disposition proceeds to its single send without
// pausing itself: a key never blocks its own retry.
#[tokio::test]
async fn rollback_disposition_proceeds_without_self_pause() {
    let (ors, dir) = temp_ors("rollback-dispose");
    let paused = Mutex::new(BTreeSet::new());
    let identity = test_identity("rollback-dispose");
    let scopes = vec!["scope-1690-d".to_owned()];
    let sends = Arc::new(Mutex::new(0_usize));

    // Phase 1: first attempt ends unknown; the record opens and pauses.
    let send = scripted_send(vec![Err(StoreError::MissingReceiptEnvelope)], &sends);
    let query = scripted_query(vec![Err(StoreError::MissingReceiptEnvelope)]);
    match recover_commit(Some(&ors), &paused, &identity, &scopes, send, query).await {
        Err(CommitRecoveryError::UnknownCommitOpen { preserved, .. }) => {
            assert!(preserved);
        }
        other => panic!("first attempt must open problem state, got {other:?}"),
    }
    assert_eq!(*sends.lock().expect("sends"), 1);

    // Phase 2: resubmission finds a known rollback, proceeds to its single
    // send (no self-pause), commits, and resolves the open record.
    let rolled_back = test_receipt(&identity, WriteReceiptStatus::Cancelled, Resubmission::None);
    let committed = test_receipt(&identity, WriteReceiptStatus::Committed, Resubmission::None);
    let send = scripted_send(vec![Ok(committed.clone())], &sends);
    let query = scripted_query(vec![Ok(rolled_back)]);
    let receipt = recover_commit(Some(&ors), &paused, &identity, &scopes, send, query)
        .await
        .expect("rollback disposition proceeds to send");
    assert_eq!(receipt, committed);
    assert_eq!(*sends.lock().expect("sends"), 2, "one retry, no more");
    let resolved = ors
        .load_unknown_commit(&identity.idempotency_key)
        .expect("load")
        .expect("record kept as terminal evidence");
    assert!(!resolved.is_open());
    assert!(paused_scopes_snapshot(&paused).is_empty(), "scopes released");
    remove_temp(&dir);
}

// Work mandate: a known rollback retries exactly once under the identical
// identity, then resolves and returns.
#[tokio::test]
async fn known_rollback_retries_once_under_the_same_identity() {
    let (ors, dir) = temp_ors("rollback");
    let paused = Mutex::new(BTreeSet::new());
    let identity = test_identity("rollback");
    let scopes = vec!["scope-1690-c".to_owned()];
    let rejected = test_receipt(&identity, WriteReceiptStatus::Rejected, Resubmission::None);
    let committed = test_receipt(&identity, WriteReceiptStatus::Committed, Resubmission::None);
    let sends = Arc::new(Mutex::new(0_usize));
    let send = scripted_send(vec![Ok(rejected), Ok(committed.clone())], &sends);
    let receipt = recover_commit(Some(&ors), &paused, &identity, &scopes, send, never_query())
        .await
        .expect("rollback retries and commits");
    assert_eq!(receipt, committed);
    assert_eq!(
        *sends.lock().expect("sends"),
        2,
        "exactly one same-identity retry"
    );
    assert!(
        ors.load_unknown_commit(&identity.idempotency_key)
            .expect("load")
            .is_none(),
        "no unknown outcome means nothing staged"
    );
    remove_temp(&dir);
}

// A receipt that forbids same-identity resubmission is never retried.
#[test]
fn receipt_classification_never_retries_new_identity() {
    let identity = test_identity("classify");
    let committed = test_receipt(&identity, WriteReceiptStatus::Committed, Resubmission::None);
    assert_eq!(
        classify_commit_receipt(&committed),
        eliot_kernel_service::CommitRecoveryClass::Committed
    );
    for status in [WriteReceiptStatus::Rejected, WriteReceiptStatus::Cancelled] {
        let rollback = test_receipt(&identity, status, Resubmission::None);
        assert_eq!(
            classify_commit_receipt(&rollback),
            eliot_kernel_service::CommitRecoveryClass::KnownRollback,
            "{status:?} with no resubmission retries same identity"
        );
        let fresh = test_receipt(&identity, status, Resubmission::NewIdentityAfterCondition);
        assert!(
            matches!(
                classify_commit_receipt(&fresh),
                eliot_kernel_service::CommitRecoveryClass::NeedsNewIdentity(_)
            ),
            "{status:?} with new-identity resubmission never retries"
        );
    }
    let dead = test_receipt(
        &identity,
        WriteReceiptStatus::DeadLetter,
        Resubmission::None,
    );
    assert!(
        matches!(
            classify_commit_receipt(&dead),
            eliot_kernel_service::CommitRecoveryClass::NeedsNewIdentity(_)
        ),
        "dead letter never retries"
    );
}
