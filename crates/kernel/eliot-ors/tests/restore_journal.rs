//! Durable restore-journal backend proof (issue #957, prerequisite for #960).
//!
//! Exercises the real `RedbRecoveryStore` restore-journal tables only: exact
//! predecessor compare-and-append, identical-operation replay, unknown-commit
//! readback reconciliation, bounded readback, explicit schema ensure, prune
//! retention of unresolved intents, and reopen durability over temporary redb
//! files. No second database is created, `eliot-backup` is never imported, and
//! no phase semantics, authority, or effect mutation lives here.

use std::path::PathBuf;
use std::sync::Arc;

use eliot_ors::{
    CONTRACT_VERSION, JournalPredecessor, MAX_JOURNAL_PAGE_ENTRIES, MAX_JOURNAL_PAYLOAD_BYTES,
    MIN_RETAINED_RESOLVED_MEMBERS, RESTORE_JOURNAL_RECORD_SCHEMA, RESTORE_JOURNAL_SCHEMA_VERSION,
    RETENTION_RECLAIM_FROM_MEMBERS, RecoveryPayloadEnvelope, RedbRecoveryStore,
    RestoreJournalAppendReceipt, RestoreJournalArchiveClass, RestoreJournalCompleteness,
    RestoreJournalMemberDenominator, RestoreJournalOperation, RestoreJournalReadback,
    RestoreJournalReadbackRequest, RestoreJournalResult, RestoreJournalRetentionDisposition,
    RestoreJournalStreamBinding, StateFenceSnapshot,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
/// Same failure type as [`TestResult`] for a proof helper that returns a value.
type TestValue<T> = Result<T, Box<dyn std::error::Error>>;

const PAYLOAD_GENESIS: &str = "{\"note\":\"genesis-957\",\"phase\":\"verify\"}";
const PAYLOAD_GENESIS_SHA: &str =
    "043064b10d65863e06089279c619786b38aea72b3f87681886043ed7d6e226c5";
const PAYLOAD_SECOND: &str = "{\"note\":\"second-957\",\"phase\":\"materialize\"}";
const PAYLOAD_SECOND_SHA: &str = "71c7b8e8ce7aa9ae4be0df23b7df84cdf7a3892b6263c78f892961bc4a6ac598";
const PAYLOAD_ALT: &str = "{\"note\":\"alt-957\",\"phase\":\"verify\"}";
const PAYLOAD_ALT_SHA: &str = "fa48b699035e2f74e6b7b34299d7b5930795d0e8921a9778c1f0ab8f696afdf6";
const RECEIPT_VERIFY: &str = "{\"outcome\":\"applied\",\"phase\":\"verify\"}";
const RECEIPT_VERIFY_SHA: &str = "47fdfa3c389aa6174fb0bff29d75193864a04c669c5d784674d8e5e862f2a95a";
const RECEIPT_MATERIALIZE: &str = "{\"outcome\":\"applied\",\"phase\":\"materialize\"}";
const RECEIPT_MATERIALIZE_SHA: &str =
    "c228d2326e2c714dee3501f372811d0d6717e79bc3873a77859d9e56b21eacbd";

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/restore-journal")
}

fn read_fixture(name: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(fixture_dir().join(name))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn temp_db(case: &str) -> PathBuf {
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    std::env::temp_dir().join(format!(
        "eliot-957-{case}-{}-{nanos}.redb",
        std::process::id()
    ))
}

fn open_db(case: &str) -> Result<(RedbRecoveryStore, PathBuf), Box<dyn std::error::Error>> {
    let path = temp_db(case);
    let _ = std::fs::remove_file(&path);
    let store = RedbRecoveryStore::open(&path)?;
    store.ensure_restore_journal_schema()?;
    Ok((store, path))
}

fn binding(transaction: &str, writer: &str) -> RestoreJournalStreamBinding {
    RestoreJournalStreamBinding {
        transaction_id: transaction.to_owned(),
        source_archive_id: "archive-957-a".to_owned(),
        archive_class: RestoreJournalArchiveClass::FullRecovery,
        destination_ref: "dest-957-a".to_owned(),
        writer_id: writer.to_owned(),
        writer_fence_digest: digest('e'),
    }
}

fn operation(
    transaction: &str,
    phase: &str,
    request: char,
    body: char,
    predecessor: Option<JournalPredecessor>,
) -> RestoreJournalOperation {
    RestoreJournalOperation {
        transaction_id: transaction.to_owned(),
        source_archive_id: "archive-957-a".to_owned(),
        archive_class: RestoreJournalArchiveClass::FullRecovery,
        destination_ref: "dest-957-a".to_owned(),
        writer_id: "writer-957-a".to_owned(),
        writer_fence_digest: digest('e'),
        record_schema: RESTORE_JOURNAL_RECORD_SCHEMA.to_owned(),
        phase_operation: phase.to_owned(),
        request_digest: digest(request),
        body_digest: digest(body),
        expected_predecessor: predecessor,
        payload_handle: format!("payload-957-{transaction}-{phase}"),
    }
}

fn result_for(
    transaction: &str,
    phase: &str,
    intent_sequence: u64,
    receipt: &str,
    receipt_sha: &str,
) -> RestoreJournalResult {
    RestoreJournalResult {
        transaction_id: transaction.to_owned(),
        phase_operation: phase.to_owned(),
        intent_sequence,
        receipt_sha256: receipt_sha.to_owned(),
        receipt: receipt.to_owned(),
    }
}

fn predecessor_of(sequence: u64, digest_value: &str) -> JournalPredecessor {
    JournalPredecessor {
        sequence,
        digest: digest_value.to_owned(),
    }
}

// WORK_UNIT_CASE: 957/1
#[test]
fn exact_owner_neutral_transaction_identity() -> TestResult {
    let (store, path) = open_db("01")?;
    let stream = "stream-957-01";
    let fixture: RestoreJournalStreamBinding =
        serde_json::from_value(read_fixture("stream-binding.json")?)?;
    store.bind_restore_journal_stream(stream, &fixture)?;
    assert_eq!(store.load_restore_journal_binding(stream)?, Some(fixture));
    let genesis: RestoreJournalOperation =
        serde_json::from_value(read_fixture("genesis-operation.json")?)?;
    let receipt = store.append_restore_journal_intent(
        stream,
        &genesis,
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    assert_eq!(receipt.transaction_id, "tx-957-fixture");
    assert_eq!(receipt.phase_operation, "verify");
    assert_eq!(receipt.sequence, 0);
    assert_eq!(receipt.record_digest.len(), 64);
    assert!(!receipt.replayed);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/2
#[test]
fn wrong_writer_fence_source_destination_archive_rejected() -> TestResult {
    let (store, path) = open_db("02")?;
    let stream = "stream-957-02";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    for mutated in [
        binding("tx-957-a", "writer-957-other"),
        RestoreJournalStreamBinding {
            writer_fence_digest: digest('f'),
            ..binding("tx-957-a", "writer-957-a")
        },
        RestoreJournalStreamBinding {
            source_archive_id: "archive-957-other".to_owned(),
            ..binding("tx-957-a", "writer-957-a")
        },
        RestoreJournalStreamBinding {
            destination_ref: "dest-957-other".to_owned(),
            ..binding("tx-957-a", "writer-957-a")
        },
        RestoreJournalStreamBinding {
            archive_class: RestoreJournalArchiveClass::ScopeExport,
            ..binding("tx-957-a", "writer-957-a")
        },
    ] {
        let conflict = store.bind_restore_journal_stream(stream, &mutated);
        assert!(
            matches!(conflict, Err(eliot_ors::OrsError::IntegrityProblem { .. })),
            "conflicting rebind must fail closed"
        );
    }
    let mut bad_schema = operation("tx-957-a", "verify", 'a', 'b', None);
    bad_schema.record_schema = "restore-journal-v9".to_owned();
    assert!(matches!(
        store.append_restore_journal_intent(
            stream,
            &bad_schema,
            PAYLOAD_GENESIS_SHA,
            PAYLOAD_GENESIS
        ),
        Err(eliot_ors::OrsError::InvalidField { .. })
    ));
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/3
#[test]
fn durable_intent_append_and_reopen() -> TestResult {
    let (store, path) = open_db("03")?;
    let stream = "stream-957-03";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let first = store.append_restore_journal_intent(
        stream,
        &operation("tx-957-a", "verify", 'a', 'b', None),
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    let second = store.append_restore_journal_intent(
        stream,
        &operation(
            "tx-957-a",
            "materialize",
            'c',
            'd',
            Some(predecessor_of(first.sequence, &first.record_digest)),
        ),
        PAYLOAD_SECOND_SHA,
        PAYLOAD_SECOND,
    )?;
    assert_eq!((first.sequence, second.sequence), (0, 1));
    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    let entries = reopened.load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].sequence, 0);
    assert_eq!(entries[1].sequence, 1);
    assert_eq!(
        entries[1].operation.expected_predecessor,
        Some(predecessor_of(first.sequence, &first.record_digest))
    );
    drop(reopened);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/4
#[test]
fn durable_result_index_sequence_atomicity() -> TestResult {
    let (store, path) = open_db("04")?;
    let stream = "stream-957-04";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let intent = store.append_restore_journal_intent(
        stream,
        &operation("tx-957-a", "verify", 'a', 'b', None),
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    let answered = result_for(
        "tx-957-a",
        "verify",
        intent.sequence,
        RECEIPT_VERIFY,
        RECEIPT_VERIFY_SHA,
    );
    let receipt = store.append_restore_journal_result(stream, &answered)?;
    assert_eq!(receipt.sequence, intent.sequence);
    assert!(!receipt.replayed);
    assert_eq!(
        store.load_restore_journal_result(stream, "verify")?,
        Some(answered)
    );
    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    assert_eq!(
        reopened
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .len(),
        1
    );
    assert!(
        reopened
            .load_restore_journal_result(stream, "verify")?
            .is_some()
    );
    drop(reopened);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/5
#[test]
fn two_writers_same_predecessor_one_advance() -> TestResult {
    let (store, path) = open_db("05")?;
    let stream = "stream-957-05";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let head = store.append_restore_journal_intent(
        stream,
        &operation("tx-957-a", "verify", 'a', 'b', None),
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    let shared = Some(predecessor_of(head.sequence, &head.record_digest));
    let winner = store.append_restore_journal_intent(
        stream,
        &operation("tx-957-a", "materialize", 'c', 'd', shared.clone()),
        PAYLOAD_SECOND_SHA,
        PAYLOAD_SECOND,
    )?;
    assert_eq!(winner.sequence, 1);
    let loser = store.append_restore_journal_intent(
        stream,
        &operation("tx-957-a", "reconcile", 'e', 'f', shared),
        PAYLOAD_SECOND_SHA,
        PAYLOAD_SECOND,
    );
    assert!(
        matches!(loser, Err(eliot_ors::OrsError::IntegrityProblem { .. })),
        "second writer on the same predecessor must fail"
    );
    assert_eq!(
        store
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .len(),
        2
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/6
#[test]
fn exact_replay_returns_identical_receipt() -> TestResult {
    let (store, path) = open_db("06")?;
    let stream = "stream-957-06";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let genesis = operation("tx-957-a", "verify", 'a', 'b', None);
    let first = store.append_restore_journal_intent(
        stream,
        &genesis,
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    let replayed = store.append_restore_journal_intent(
        stream,
        &genesis,
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    assert!(!first.replayed);
    assert!(replayed.replayed);
    assert_eq!(
        (replayed.sequence, replayed.record_digest.as_str()),
        (first.sequence, first.record_digest.as_str())
    );
    assert_eq!(
        store
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .len(),
        1,
        "replay appends nothing"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/7
#[test]
fn changed_same_operation_payload_conflicts() -> TestResult {
    let (store, path) = open_db("07")?;
    let stream = "stream-957-07";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let genesis = operation("tx-957-a", "verify", 'a', 'b', None);
    store.append_restore_journal_intent(stream, &genesis, PAYLOAD_GENESIS_SHA, PAYLOAD_GENESIS)?;
    let changed =
        store.append_restore_journal_intent(stream, &genesis, PAYLOAD_ALT_SHA, PAYLOAD_ALT);
    assert!(
        matches!(changed, Err(eliot_ors::OrsError::IntegrityProblem { .. })),
        "changed payload under the same operation identity must conflict"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/8
#[test]
fn lost_acknowledgement_reconciles_by_readback() -> TestResult {
    let (store, path) = open_db("08")?;
    let stream = "stream-957-08";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let genesis = operation("tx-957-a", "verify", 'a', 'b', None);
    let _lost_receipt = store.append_restore_journal_intent(
        stream,
        &genesis,
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    let entries = store.load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].operation, genesis);
    assert_eq!(entries[0].payload_sha256, PAYLOAD_GENESIS_SHA);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/9
#[test]
fn acknowledged_record_survives_reopen_nothing_phantom() -> TestResult {
    let (store, path) = open_db("09")?;
    let stream = "stream-957-09";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    assert!(
        store
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .is_empty(),
        "no commit means no record"
    );
    let receipt = store.append_restore_journal_intent(
        stream,
        &operation("tx-957-a", "verify", 'a', 'b', None),
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    let entries = reopened.load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].sequence, receipt.sequence);
    assert_eq!(entries[0].payload, PAYLOAD_GENESIS);
    drop(reopened);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/10
#[test]
fn stale_missing_and_unbounded_history_fail_closed() -> TestResult {
    let (store, path) = open_db("10")?;
    let stream = "stream-957-10";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let stale = store.append_restore_journal_intent(
        stream,
        &operation(
            "tx-957-a",
            "verify",
            'a',
            'b',
            Some(predecessor_of(9, &digest('9'))),
        ),
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    );
    assert!(
        matches!(stale, Err(eliot_ors::OrsError::IntegrityProblem { .. })),
        "stale predecessor must fail"
    );
    let orphan = result_for("tx-957-a", "verify", 0, RECEIPT_VERIFY, RECEIPT_VERIFY_SHA);
    assert!(
        matches!(
            store.append_restore_journal_result(stream, &orphan),
            Err(eliot_ors::OrsError::IntegrityProblem { .. })
        ),
        "result answering no intent must fail"
    );
    assert!(matches!(
        store.load_restore_journal_stream(stream, 0),
        Err(eliot_ors::OrsError::InvalidField { .. })
    ));
    assert!(matches!(
        store.load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES + 1),
        Err(eliot_ors::OrsError::InvalidField { .. })
    ));
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/11
#[test]
fn known_empty_distinct_from_unavailable() -> TestResult {
    let (store, path) = open_db("11")?;
    let stream = "stream-957-11";
    assert!(
        store
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .is_empty(),
        "validated new journal reads known-empty"
    );
    assert_eq!(store.load_restore_journal_binding(stream)?, None);
    assert_eq!(store.load_restore_journal_result(stream, "verify")?, None);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/12
#[test]
fn bounds_hold_and_prune_retains_unresolved() -> TestResult {
    let (store, path) = open_db("12")?;
    let stream = "stream-957-12";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let intent_a = store.append_restore_journal_intent(
        stream,
        &operation("tx-957-a", "verify", 'a', 'b', None),
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    store.append_restore_journal_result(
        stream,
        &result_for(
            "tx-957-a",
            "verify",
            intent_a.sequence,
            RECEIPT_VERIFY,
            RECEIPT_VERIFY_SHA,
        ),
    )?;
    let intent_b = store.append_restore_journal_intent(
        stream,
        &operation(
            "tx-957-a",
            "materialize",
            'c',
            'd',
            Some(predecessor_of(intent_a.sequence, &intent_a.record_digest)),
        ),
        PAYLOAD_SECOND_SHA,
        PAYLOAD_SECOND,
    )?;
    let intent_c = store.append_restore_journal_intent(
        stream,
        &operation(
            "tx-957-a",
            "reconcile",
            'e',
            'f',
            Some(predecessor_of(intent_b.sequence, &intent_b.record_digest)),
        ),
        PAYLOAD_ALT_SHA,
        PAYLOAD_ALT,
    )?;
    store.append_restore_journal_result(
        stream,
        &result_for(
            "tx-957-a",
            "reconcile",
            intent_c.sequence,
            RECEIPT_MATERIALIZE,
            RECEIPT_MATERIALIZE_SHA,
        ),
    )?;
    assert_eq!(store.prune_restore_journal(stream, 1)?, 1);
    let entries = store.load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?;
    assert_eq!(
        entries.len(),
        2,
        "unresolved intent is never evicted to fit"
    );
    assert_eq!(entries[0].operation.phase_operation, "materialize");
    assert_eq!(entries[1].operation.phase_operation, "reconcile");
    assert_eq!(store.load_restore_journal_result(stream, "verify")?, None);
    assert!(
        store
            .load_restore_journal_result(stream, "reconcile")?
            .is_some()
    );
    let oversize = "x".repeat(MAX_JOURNAL_PAYLOAD_BYTES + 1);
    assert!(matches!(
        store.append_restore_journal_intent(
            stream,
            &operation(
                "tx-957-a",
                "verify",
                '1',
                '2',
                Some(predecessor_of(intent_c.sequence, &intent_c.record_digest)),
            ),
            &digest('7'),
            oversize.as_str(),
        ),
        Err(eliot_ors::OrsError::PayloadTooLarge)
    ));
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/13
#[test]
fn additive_schema_migration_replays_compatibly() -> TestResult {
    let (store, path) = open_db("13")?;
    assert_eq!(
        store.ensure_restore_journal_schema()?,
        RESTORE_JOURNAL_SCHEMA_VERSION
    );
    assert_eq!(
        store.ensure_restore_journal_schema()?,
        RESTORE_JOURNAL_SCHEMA_VERSION,
        "ensure is idempotent"
    );
    let stream = "stream-957-13";
    assert!(
        store
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .is_empty(),
        "an ensured-but-empty journal is known-empty, never complete"
    );
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    store.append_restore_journal_intent(
        stream,
        &operation("tx-957-a", "verify", 'a', 'b', None),
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    assert_eq!(
        store.ensure_restore_journal_schema()?,
        RESTORE_JOURNAL_SCHEMA_VERSION
    );
    assert_eq!(
        store
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .len(),
        1,
        "re-ensure preserves history"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/14
#[test]
fn payload_integrity_and_diagnostic_redaction() -> TestResult {
    let (store, path) = open_db("14")?;
    let stream = "stream-957-14";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let genesis = operation("tx-957-a", "verify", 'a', 'b', None);
    let tampered =
        store.append_restore_journal_intent(stream, &genesis, &digest('7'), PAYLOAD_GENESIS);
    assert!(matches!(
        tampered,
        Err(eliot_ors::OrsError::PayloadIntegrityMismatch)
    ));
    if let Err(error) = tampered {
        let rendered = format!("{error}");
        assert!(
            !rendered.contains(PAYLOAD_GENESIS),
            "diagnostics stay redacted"
        );
    }
    let intent = store.append_restore_journal_intent(
        stream,
        &genesis,
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    let mut bad_receipt = result_for(
        "tx-957-a",
        "verify",
        intent.sequence,
        RECEIPT_VERIFY,
        RECEIPT_VERIFY_SHA,
    );
    bad_receipt.receipt = "tampered-receipt-bytes".to_owned();
    let rejected = store.append_restore_journal_result(stream, &bad_receipt);
    assert!(matches!(
        rejected,
        Err(eliot_ors::OrsError::PayloadIntegrityMismatch)
    ));
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/15
#[test]
fn temp_redb_concurrent_cas_and_reopen() -> TestResult {
    let (store, path) = open_db("15")?;
    let stream = "stream-957-15".to_owned();
    store.bind_restore_journal_stream(&stream, &binding("tx-957-a", "writer-957-a"))?;
    let head = store.append_restore_journal_intent(
        &stream,
        &operation("tx-957-a", "verify", 'a', 'b', None),
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    let shared = Arc::new(store);
    let predecessor = predecessor_of(head.sequence, &head.record_digest);
    let racer = |phase: &'static str, request: char, body: char| {
        let store = Arc::clone(&shared);
        let stream = stream.clone();
        let predecessor = predecessor.clone();
        std::thread::spawn(move || {
            store.append_restore_journal_intent(
                stream.as_str(),
                &operation("tx-957-a", phase, request, body, Some(predecessor)),
                PAYLOAD_SECOND_SHA,
                PAYLOAD_SECOND,
            )
        })
    };
    let first = racer("materialize", 'c', 'd')
        .join()
        .map_err(|_| std::io::Error::other("materialize racer join failed"))?;
    let second = racer("reconcile", 'e', 'f')
        .join()
        .map_err(|_| std::io::Error::other("reconcile racer join failed"))?;
    let outcomes = [&first, &second];
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "exactly one racer advances the same predecessor"
    );
    assert_eq!(
        shared
            .load_restore_journal_stream(&stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .len(),
        2
    );
    drop(shared);
    let reopened = RedbRecoveryStore::open(&path)?;
    assert_eq!(
        reopened
            .load_restore_journal_stream(&stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .len(),
        2,
        "contended append persists across reopen"
    );
    drop(reopened);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/16
#[test]
fn guard_excludes_second_db_backup_dep_and_authority() -> TestResult {
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    let dir = std::env::temp_dir().join(format!("eliot-957-16-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("journal.redb");
    let store = RedbRecoveryStore::open(&path)?;
    store.ensure_restore_journal_schema()?;
    let stream = "stream-957-16";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    store.append_restore_journal_intent(
        stream,
        &operation("tx-957-a", "verify", 'a', 'b', None),
        PAYLOAD_GENESIS_SHA,
        PAYLOAD_GENESIS,
    )?;
    drop(store);
    let mut databases = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        databases.push(entry?.path());
    }
    assert_eq!(databases, vec![path.clone()], "exactly one database file");
    let reopened = RedbRecoveryStore::open(&path)?;
    assert!(matches!(
        reopened.load_restore_journal_stream("has\0separator", MAX_JOURNAL_PAGE_ENTRIES),
        Err(eliot_ors::OrsError::InvalidField { .. })
    ));
    let mut foreign = operation("tx-957-a", "verify", 'a', 'b', None);
    foreign.record_schema = "backup-journal-v9".to_owned();
    assert!(matches!(
        reopened.append_restore_journal_intent(
            stream,
            &foreign,
            PAYLOAD_GENESIS_SHA,
            PAYLOAD_GENESIS
        ),
        Err(eliot_ors::OrsError::InvalidField { .. })
    ));
    drop(reopened);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
    Ok(())
}

// Retention-pressure proofs for issue #2653.
//
// Every append-triggered retention pass runs only after the addressed stream
// binding, the exact replay/conflict classification and the current predecessor
// have all been decided inside the one write transaction that commits the
// append. The only state in which that pass is reachable is a stream already at
// the accepted reclaim point (`RETENTION_RECLAIM_FROM_MEMBERS` retained
// members) with an eligible contiguous resolved prefix, so each fixture below
// fills a bound stream to exactly that point. The oldest retained operation is
// deliberately inside that eligible prefix: a pass that ran before replay
// classification, or before a refusal was decided, would reclaim exactly the
// row these proofs assert is still there.

const PRESSURE_EPOCH: u64 = 1;
const PRESSURE_LINEAGE: &str = "lineage-2653";
const PRESSURE_VISIBILITY: &str = "restore-journal-2653";
const PRESSURE_TRANSACTION: &str = "tx-2653-a";

/// Exact canonical fence every pressure-proof envelope carries.
///
/// The journal compares an envelope's `state_fence.sha256` against the
/// operation's own `writer_fence_digest`, and ORS requires that digest to be
/// the SHA-256 of the fence's canonical bytes. The fence is therefore captured
/// once through the public capture path and its derived digest is what the
/// stream binding and every operation carry, instead of a hand-written digest
/// no envelope could satisfy.
fn pressure_fence() -> TestValue<StateFenceSnapshot> {
    Ok(StateFenceSnapshot::capture(
        &serde_json::json!({
            "epoch": PRESSURE_EPOCH,
            "lineage": PRESSURE_LINEAGE,
        }),
        PRESSURE_EPOCH,
    )?)
}

/// The one stream binding all pressure-proof operations match.
fn pressure_binding(fence: &StateFenceSnapshot) -> RestoreJournalStreamBinding {
    RestoreJournalStreamBinding {
        transaction_id: PRESSURE_TRANSACTION.to_owned(),
        source_archive_id: "archive-2653-a".to_owned(),
        archive_class: RestoreJournalArchiveClass::FullRecovery,
        destination_ref: "dest-2653-a".to_owned(),
        writer_id: "writer-2653-a".to_owned(),
        writer_fence_digest: fence.sha256.clone(),
    }
}

/// One operation on the pressure stream. `phase` names the phase slot, so two
/// operations differ only when their slots differ.
fn pressure_operation(
    fence: &StateFenceSnapshot,
    phase: &str,
    predecessor: Option<JournalPredecessor>,
) -> RestoreJournalOperation {
    RestoreJournalOperation {
        transaction_id: PRESSURE_TRANSACTION.to_owned(),
        source_archive_id: "archive-2653-a".to_owned(),
        archive_class: RestoreJournalArchiveClass::FullRecovery,
        destination_ref: "dest-2653-a".to_owned(),
        writer_id: "writer-2653-a".to_owned(),
        writer_fence_digest: fence.sha256.clone(),
        record_schema: RESTORE_JOURNAL_RECORD_SCHEMA.to_owned(),
        phase_operation: phase.to_owned(),
        request_digest: digest('a'),
        body_digest: digest('b'),
        expected_predecessor: predecessor,
        payload_handle: format!("payload-2653-{phase}"),
    }
}

/// Builds the exact opaque envelope an operation (or the result answering it)
/// must carry, with the digest the call must present beside it.
///
/// The envelope is derived from the operation rather than being a fixed
/// fixture: the journal binds it back to the operation identity and the writer
/// fence, so an envelope that is not bound that way is refused before any table
/// is opened. `created_at_ms` varies the exact bytes without touching the
/// operation identity, which is how one proof presents a different payload under
/// an unchanged operation.
fn pressure_payload(
    stream: &str,
    operation: &RestoreJournalOperation,
    fence: &StateFenceSnapshot,
    created_at_ms: i64,
) -> TestValue<(String, String)> {
    let body = format!("body-2653-{}", operation.payload_handle);
    let envelope: RecoveryPayloadEnvelope = serde_json::from_value(serde_json::json!({
        "contract_version": CONTRACT_VERSION,
        "operation_or_checkpoint_id": operation.identity(stream)?,
        "privacy_and_visibility_class": {
            "privacy": "PRIVATE",
            "visibility": PRESSURE_VISIBILITY,
            "instruction_taint": "CLEARED",
        },
        "payload": {
            "kind": "IMMUTABLE_LOCATOR",
            "locator": operation.payload_handle,
        },
        "payload_sha256": eliot_contracts::sha256_hex(body.as_bytes()),
        "payload_length": body.len(),
        "authority_epoch": {
            "current": {
                "lineage_id": PRESSURE_LINEAGE,
                "epoch": PRESSURE_EPOCH,
            },
            "predecessor": null,
        },
        "state_fence": {
            "canonical_json": fence.canonical_json,
            "sha256": fence.sha256,
            "observed_authority_epoch": PRESSURE_EPOCH,
        },
        "created_at_ms": created_at_ms,
        "known_at_ms": created_at_ms,
        // An unresolved restore-journal row must never expire.
        "expires_at_ms": null,
    }))?;
    envelope.validate()?;
    let payload = serde_json::to_string(&envelope)?;
    let payload_sha256 = eliot_contracts::sha256_hex(payload.as_bytes());
    Ok((payload_sha256, payload))
}

/// Appends one intent on `stream` and returns it with the head the next append
/// must chain to.
fn append_intent(
    store: &RedbRecoveryStore,
    stream: &str,
    fence: &StateFenceSnapshot,
    phase: &str,
    predecessor: Option<JournalPredecessor>,
) -> TestValue<(
    RestoreJournalOperation,
    RestoreJournalAppendReceipt,
    JournalPredecessor,
)> {
    let operation = pressure_operation(fence, phase, predecessor);
    let (payload_sha256, payload) = pressure_payload(stream, &operation, fence, 0)?;
    let intent =
        store.append_restore_journal_intent(stream, &operation, &payload_sha256, &payload)?;
    Ok((
        operation,
        intent.clone(),
        predecessor_of(intent.sequence, &intent.record_digest),
    ))
}

/// Appends one intent and the durable result that resolves it, returning the
/// operation, its intent receipt and the head the next append must chain to.
fn append_resolved(
    store: &RedbRecoveryStore,
    stream: &str,
    fence: &StateFenceSnapshot,
    phase: &str,
    predecessor: Option<JournalPredecessor>,
) -> TestValue<(
    RestoreJournalOperation,
    RestoreJournalAppendReceipt,
    JournalPredecessor,
)> {
    let (operation, intent, head) = append_intent(store, stream, fence, phase, predecessor)?;
    let (receipt_sha256, receipt) = pressure_payload(stream, &operation, fence, 0)?;
    store.append_restore_journal_result(
        stream,
        &RestoreJournalResult {
            transaction_id: PRESSURE_TRANSACTION.to_owned(),
            phase_operation: phase.to_owned(),
            intent_sequence: intent.sequence,
            receipt_sha256,
            receipt,
        },
    )?;
    Ok((operation, intent, head))
}

/// A bound stream sitting exactly on the accepted reclaim point.
struct PressureStream {
    /// Oldest retained operation. It is inside the eligible resolved prefix, so
    /// an append-triggered pass would reclaim it unless exact replay is
    /// classified first.
    oldest: RestoreJournalOperation,
    oldest_receipt: RestoreJournalAppendReceipt,
    /// Durable head before the next append.
    head: JournalPredecessor,
}

/// Members the accepted window permits one pass to reclaim from a stream at the
/// reclaim point: everything resolved except the newest retained resolved
/// member.
fn permitted_reclaim() -> u64 {
    u64::try_from(RETENTION_RECLAIM_FROM_MEMBERS - MIN_RETAINED_RESOLVED_MEMBERS)
        .unwrap_or(u64::MAX)
}

/// Fills `stream` with `RETENTION_RECLAIM_FROM_MEMBERS` intents, which is the
/// only shape in which the append path reaches the append-triggered retention
/// branch.
///
/// Every member is resolved except, when `unresolved_oldest` is set, the oldest
/// one. That variant puts a recovery-needed member at the head of the eligible
/// prefix, so the pass has a boundary it must stop at instead of a prefix it may
/// reclaim.
fn fill_pressure(
    store: &RedbRecoveryStore,
    stream: &str,
    fence: &StateFenceSnapshot,
    unresolved_oldest: bool,
) -> TestValue<PressureStream> {
    let mut head = None;
    let mut oldest = None;
    for member in 0..RETENTION_RECLAIM_FROM_MEMBERS {
        let phase = format!("phase-{member:04}");
        let append = if member == 0 && unresolved_oldest {
            append_intent(store, stream, fence, &phase, head.clone())
        } else {
            append_resolved(store, stream, fence, &phase, head.clone())
        };
        let (operation, receipt, next) = append?;
        if member == 0 {
            oldest = Some((operation, receipt));
        }
        head = Some(next);
    }
    let (oldest, oldest_receipt) =
        oldest.ok_or_else(|| std::io::Error::other("the pressure fixture is empty"))?;
    let head = head.ok_or_else(|| std::io::Error::other("the pressure fixture has no head"))?;
    Ok(PressureStream {
        oldest,
        oldest_receipt,
        head,
    })
}

/// Whole-member readback against the denominator the durable head itself
/// accounts for, so completeness is proved by the owner and never asserted by
/// the caller.
fn readback_against_head(
    store: &RedbRecoveryStore,
    stream: &str,
) -> TestValue<RestoreJournalReadback> {
    let head = store.restore_journal_durable_head(stream)?;
    Ok(
        store.load_restore_journal_readback_against(&RestoreJournalReadbackRequest {
            stream: stream.to_owned(),
            limit: MAX_JOURNAL_PAGE_ENTRIES,
            denominator: RestoreJournalMemberDenominator::for_head(head.as_ref())?,
        })?,
    )
}

/// Proves a refused append left no append-triggered journal mutation: the whole
/// observed state is unchanged, the eligible prefix is intact and no durable
/// retention decision was written.
fn assert_no_pressure_mutation(
    store: &RedbRecoveryStore,
    stream: &str,
    before: &RestoreJournalReadback,
    oldest: &RestoreJournalOperation,
) -> TestResult {
    let after = readback_against_head(store, stream)?;
    assert_eq!(
        &after, before,
        "a refused append mutates no journal row, fence, head or slot"
    );
    assert!(
        after.retention.is_none(),
        "a refused append commits no retention decision"
    );
    let entries = store.load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?;
    assert_eq!(entries.len(), RETENTION_RECLAIM_FROM_MEMBERS);
    assert_eq!(&entries[0].operation, oldest);
    Ok(())
}

// WORK_UNIT_CASE: 2653/1
#[test]
fn exact_replay_under_pressure_returns_the_original_receipt() -> TestResult {
    let (store, path) = open_db("2653-01")?;
    let fence = pressure_fence()?;
    let stream = "stream-2653-01";
    store.bind_restore_journal_stream(stream, &pressure_binding(&fence))?;
    let pressure = fill_pressure(&store, stream, &fence, false)?;
    let before = readback_against_head(&store, stream)?;
    assert_eq!(
        before.total_members,
        u64::try_from(RETENTION_RECLAIM_FROM_MEMBERS).unwrap_or(u64::MAX)
    );

    // The replayed operation is the oldest retained one, i.e. exactly the row an
    // append-triggered pass would reclaim at this point.
    let (payload_sha256, payload) = pressure_payload(stream, &pressure.oldest, &fence, 0)?;
    let replayed =
        store.append_restore_journal_intent(stream, &pressure.oldest, &payload_sha256, &payload)?;

    assert!(replayed.replayed, "an exact replay appends nothing");
    assert!(!pressure.oldest_receipt.replayed);
    assert_eq!(
        (
            replayed.sequence,
            replayed.record_digest.as_str(),
            replayed.phase_operation.as_str()
        ),
        (
            pressure.oldest_receipt.sequence,
            pressure.oldest_receipt.record_digest.as_str(),
            pressure.oldest.phase_operation.as_str()
        ),
        "the replay returns the exact persisted receipt"
    );
    store.verify_restore_journal_receipt(stream, &replayed)?;

    // The replay pruned nothing: its own row and result are still readable, the
    // whole eligible prefix is retained, and the head never moved.
    assert_no_pressure_mutation(&store, stream, &before, &pressure.oldest)?;
    assert!(
        store
            .load_restore_journal_result(stream, &pressure.oldest.phase_operation)?
            .is_some()
    );
    assert_eq!(
        store.restore_journal_durable_head(stream)?,
        Some(pressure.head.clone())
    );

    // The same state is a reclaiming one: the next admitted append runs the pass
    // and reclaims exactly the prefix the replay left intact, which is what
    // makes the replay above returning the original receipt (rather than a
    // pruned-slot refusal) the load-bearing observation.
    let admitted = pressure_operation(&fence, "phase-admitted", Some(pressure.head.clone()));
    let (admitted_sha256, admitted_payload) = pressure_payload(stream, &admitted, &fence, 0)?;
    store.append_restore_journal_intent(stream, &admitted, &admitted_sha256, &admitted_payload)?;
    let reclaimed = readback_against_head(&store, stream)?;
    assert_eq!(
        reclaimed
            .retention
            .as_ref()
            .map(|record| record.removed_members),
        Some(permitted_reclaim()),
        "this fixture really does reach the append-triggered retention pass"
    );
    assert!(matches!(
        store.load_restore_journal_result(stream, &pressure.oldest.phase_operation),
        Err(eliot_ors::OrsError::IntegrityProblem { record_type, .. })
            if record_type == "restore_journal_operation"
    ));
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 2653/2
#[test]
fn pressure_refusals_never_run_a_retention_pass() -> TestResult {
    let (store, path) = open_db("2653-02")?;
    let fence = pressure_fence()?;
    let stream = "stream-2653-02";
    store.bind_restore_journal_stream(stream, &pressure_binding(&fence))?;
    let pressure = fill_pressure(&store, stream, &fence, false)?;
    let before = readback_against_head(&store, stream)?;

    // 1. A shape-valid operation whose identity does not match the persisted
    //    stream binding: the fence it carries is a real one, so only the binding
    //    check can refuse it.
    let mut foreign = pressure.oldest.clone();
    foreign.writer_fence_digest = digest('f');
    let (foreign_sha256, foreign_payload) = pressure_payload(stream, &foreign, &fence, 0)?;
    let wrong_binding =
        store.append_restore_journal_intent(stream, &foreign, &foreign_sha256, &foreign_payload);
    assert!(
        matches!(
            wrong_binding,
            Err(eliot_ors::OrsError::IntegrityProblem { record_type, .. })
                if record_type == "restore_journal_binding"
        ),
        "a wrong binding refuses without an append-triggered retention effect"
    );
    assert_no_pressure_mutation(&store, stream, &before, &pressure.oldest)?;

    // 2. A different payload under the unchanged operation identity: the
    //    envelope is still valid and still bound to this operation, so the
    //    conflict is classified rather than malformed.
    let (changed_sha256, changed_payload) = pressure_payload(stream, &pressure.oldest, &fence, 1)?;
    let changed_payload_result = store.append_restore_journal_intent(
        stream,
        &pressure.oldest,
        &changed_sha256,
        &changed_payload,
    );
    assert!(
        matches!(
            changed_payload_result,
            Err(eliot_ors::OrsError::IntegrityProblem { record_type, .. })
                if record_type == "restore_journal_operation"
        ),
        "a changed same-operation payload conflicts without a retention effect"
    );
    assert_no_pressure_mutation(&store, stream, &before, &pressure.oldest)?;

    // 3. A genuinely new operation chained to a predecessor this stream never
    //    had.
    let stale = pressure_operation(&fence, "phase-stale", Some(predecessor_of(9, &digest('9'))));
    let (stale_sha256, stale_payload) = pressure_payload(stream, &stale, &fence, 0)?;
    let stale_predecessor =
        store.append_restore_journal_intent(stream, &stale, &stale_sha256, &stale_payload);
    assert!(
        matches!(
            stale_predecessor,
            Err(eliot_ors::OrsError::IntegrityProblem { record_type, .. })
                if record_type == "restore_journal_entry"
        ),
        "a stale predecessor refuses without a retention effect"
    );
    assert_no_pressure_mutation(&store, stream, &before, &pressure.oldest)?;

    // The stream is still at the reclaim point with its whole resolved prefix, so
    // every refusal above refused before the pass rather than after it.
    assert!(
        store
            .load_restore_journal_result(stream, &pressure.oldest.phase_operation)?
            .is_some()
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 2653/3
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one reclaiming schedule and one blocked-frontier schedule, both with their reopen"
)]
fn admitted_append_reclaims_only_the_prefix_and_reopens_coherent() -> TestResult {
    let (store, path) = open_db("2653-03")?;
    let fence = pressure_fence()?;
    let stream = "stream-2653-03";
    store.bind_restore_journal_stream(stream, &pressure_binding(&fence))?;
    let pressure = fill_pressure(&store, stream, &fence, false)?;

    let admitted = pressure_operation(&fence, "phase-admitted", Some(pressure.head.clone()));
    let (payload_sha256, payload) = pressure_payload(stream, &admitted, &fence, 0)?;
    let receipt =
        store.append_restore_journal_intent(stream, &admitted, &payload_sha256, &payload)?;
    assert!(!receipt.replayed);
    assert_eq!(
        receipt.sequence,
        u64::try_from(RETENTION_RECLAIM_FROM_MEMBERS).unwrap_or(u64::MAX)
    );

    // Reclamation and append committed as one durable unit: the retained members
    // are exactly the newest resolved member the accepted window keeps plus the
    // new append, and the retired phase slots account for the rest of the head the
    // append actually committed.
    let reclaimed = permitted_reclaim();
    let readback = readback_against_head(&store, stream)?;
    assert_eq!(readback.completeness, RestoreJournalCompleteness::Complete);
    assert_eq!(readback.retired_members, reclaimed);
    assert_eq!(readback.retained_members, 2);
    assert_eq!(readback.total_members, reclaimed.saturating_add(2));
    assert_eq!(readback.entries[0].sequence, reclaimed);
    assert_eq!(readback.entries[1].operation, admitted);
    let record = readback
        .retention
        .clone()
        .ok_or_else(|| std::io::Error::other("the append committed no retention decision"))?;
    assert_eq!(
        record.disposition,
        RestoreJournalRetentionDisposition::ReclaimedResolvedPrefix
    );
    assert_eq!(record.removed_members, reclaimed);
    assert_eq!(record.retired_members, reclaimed);
    assert_eq!(
        record.keep_resolved,
        u64::try_from(MIN_RETAINED_RESOLVED_MEMBERS).unwrap_or(u64::MAX)
    );
    assert_eq!(record.frontier.unresolved_members, 0);

    // A reclaimed identity stays outside the retained history and its phase slot
    // is never reusable, while a retained result stays readable.
    assert!(matches!(
        store.load_restore_journal_result(stream, &pressure.oldest.phase_operation),
        Err(eliot_ors::OrsError::IntegrityProblem { record_type, .. })
            if record_type == "restore_journal_operation"
    ));
    let (oldest_sha256, oldest_payload) = pressure_payload(stream, &pressure.oldest, &fence, 0)?;
    assert!(matches!(
        store.append_restore_journal_intent(
            stream,
            &pressure.oldest,
            &oldest_sha256,
            &oldest_payload
        ),
        Err(eliot_ors::OrsError::IntegrityProblem { record_type, .. })
            if record_type == "restore_journal_operation"
    ));
    assert!(
        store
            .load_restore_journal_result(
                stream,
                &format!("phase-{:04}", RETENTION_RECLAIM_FROM_MEMBERS - 1)
            )?
            .is_some()
    );

    // The same stream shape with the oldest member left recovery-needed: the pass
    // refuses to evict it to make room, reclaims nothing, and the admitted append
    // still commits against the unchanged head.
    let blocked_stream = "stream-2653-03-blocked";
    store.bind_restore_journal_stream(blocked_stream, &pressure_binding(&fence))?;
    let blocked = fill_pressure(&store, blocked_stream, &fence, true)?;
    let blocked_admitted = pressure_operation(&fence, "phase-admitted", Some(blocked.head.clone()));
    let (blocked_sha256, blocked_payload) =
        pressure_payload(blocked_stream, &blocked_admitted, &fence, 0)?;
    let blocked_receipt = store.append_restore_journal_intent(
        blocked_stream,
        &blocked_admitted,
        &blocked_sha256,
        &blocked_payload,
    )?;
    assert!(!blocked_receipt.replayed);
    let blocked_readback = readback_against_head(&store, blocked_stream)?;
    assert_eq!(
        blocked_readback.completeness,
        RestoreJournalCompleteness::Complete
    );
    assert_eq!(blocked_readback.retired_members, 0);
    assert_eq!(
        blocked_readback.retained_members,
        u64::try_from(RETENTION_RECLAIM_FROM_MEMBERS + 1).unwrap_or(u64::MAX)
    );
    assert_eq!(
        blocked_readback.entries.len(),
        RETENTION_RECLAIM_FROM_MEMBERS + 1,
        "nothing was reclaimed and the admitted append joined the retained run"
    );
    assert_eq!(blocked_readback.entries[0].operation, blocked.oldest);
    assert_eq!(
        blocked_readback
            .entries
            .last()
            .ok_or_else(|| std::io::Error::other("the blocked readback is empty"))?
            .operation,
        blocked_admitted
    );
    let blocked_record = blocked_readback
        .retention
        .clone()
        .ok_or_else(|| std::io::Error::other("the blocked append committed no decision"))?;
    assert_eq!(
        blocked_record.disposition,
        RestoreJournalRetentionDisposition::NoResolvedPrefixToReclaim
    );
    assert_eq!(blocked_record.removed_members, 0);
    assert_eq!(blocked_record.frontier.unresolved_members, 1);
    assert_eq!(blocked_record.frontier.oldest_unresolved_sequence, Some(0));
    assert!(
        store
            .load_restore_journal_result(blocked_stream, &blocked.oldest.phase_operation)?
            .is_none(),
        "the pass made no result for the member it refused to evict"
    );

    // Reopen proves the reclaim, the tombstones, the fence, the refused evict and
    // both new appends are committed states, never partial ones.
    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    assert_eq!(
        readback_against_head(&reopened, stream)?,
        readback,
        "the committed reclaim survives reopen unchanged"
    );
    reopened.verify_restore_journal_receipt(stream, &receipt)?;
    assert!(matches!(
        reopened.load_restore_journal_result(stream, &pressure.oldest.phase_operation),
        Err(eliot_ors::OrsError::IntegrityProblem { .. })
    ));
    assert_eq!(
        readback_against_head(&reopened, blocked_stream)?,
        blocked_readback,
        "the blocked frontier survives reopen unchanged"
    );
    reopened.verify_restore_journal_receipt(blocked_stream, &blocked_receipt)?;
    assert!(
        reopened
            .load_restore_journal_result(blocked_stream, &blocked.oldest.phase_operation)?
            .is_none()
    );
    drop(reopened);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 2653/4
#[test]
fn refused_append_under_pressure_reopens_at_the_old_state() -> TestResult {
    let (store, path) = open_db("2653-04")?;
    let fence = pressure_fence()?;
    let stream = "stream-2653-04";
    store.bind_restore_journal_stream(stream, &pressure_binding(&fence))?;
    let pressure = fill_pressure(&store, stream, &fence, false)?;
    let before = readback_against_head(&store, stream)?;

    let mut foreign = pressure.oldest.clone();
    foreign.source_archive_id = "archive-2653-other".to_owned();
    let (foreign_sha256, foreign_payload) = pressure_payload(stream, &foreign, &fence, 0)?;
    let refused =
        store.append_restore_journal_intent(stream, &foreign, &foreign_sha256, &foreign_payload);
    assert!(
        matches!(
            refused,
            Err(eliot_ors::OrsError::IntegrityProblem { record_type, .. })
                if record_type == "restore_journal_binding"
        ),
        "the refused append under pressure must refuse"
    );
    drop(store);

    // Whatever the refusal did, it committed nothing: the reopened store is the old
    // state, whole.
    let reopened = RedbRecoveryStore::open(&path)?;
    assert_eq!(
        readback_against_head(&reopened, stream)?,
        before,
        "interruption yields the old state, never pruning beside a rejected append"
    );
    assert_eq!(
        reopened
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .len(),
        RETENTION_RECLAIM_FROM_MEMBERS
    );
    assert_eq!(
        reopened.restore_journal_durable_head(stream)?,
        Some(pressure.head.clone())
    );

    // The eligible prefix is still replayable after the refusal, so nothing was
    // reclaimed and no slot was retired on the way out.
    let (payload_sha256, payload) = pressure_payload(stream, &pressure.oldest, &fence, 0)?;
    let replayed = reopened.append_restore_journal_intent(
        stream,
        &pressure.oldest,
        &payload_sha256,
        &payload,
    )?;
    assert!(replayed.replayed);
    assert_eq!(replayed.sequence, pressure.oldest_receipt.sequence);
    assert_eq!(
        replayed.record_digest, pressure.oldest_receipt.record_digest,
        "the reopened store still holds the original receipt"
    );
    reopened.verify_restore_journal_receipt(stream, &replayed)?;
    assert!(
        readback_against_head(&reopened, stream)?
            .retention
            .is_none(),
        "a refusal and a later replay commit no retention decision"
    );
    drop(reopened);
    let _ = std::fs::remove_file(&path);
    Ok(())
}
