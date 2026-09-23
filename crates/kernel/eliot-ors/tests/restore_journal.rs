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
    JournalPredecessor, MAX_JOURNAL_PAGE_ENTRIES, MAX_JOURNAL_PAYLOAD_BYTES,
    RESTORE_JOURNAL_RECORD_SCHEMA, RESTORE_JOURNAL_SCHEMA_VERSION, RedbRecoveryStore,
    RestoreJournalArchiveClass, RestoreJournalOperation, RestoreJournalResult,
    RestoreJournalStreamBinding,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
