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

use eliot_contracts::sha256_hex;
use eliot_ors::{
    EpochIdentity, EpochLineage, JournalPredecessor, MAX_JOURNAL_PAGE_ENTRIES,
    MAX_JOURNAL_PAYLOAD_BYTES, OpaqueLabel, RESTORE_JOURNAL_RECORD_SCHEMA,
    RESTORE_JOURNAL_SCHEMA_VERSION, RecoveryAccessClass, RecoveryEnvelopeContext,
    RecoveryPayloadEnvelope, RedbRecoveryStore, RestoreJournalArchiveClass,
    RestoreJournalOperation, RestoreJournalResult, RestoreJournalStreamBinding, StateFenceSnapshot,
};
use eliot_platform::SecretReference;
use eliot_security_contracts::{InstructionTaint, PrivacyClass};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PAYLOAD_GENESIS: &str = "{\"note\":\"genesis-957\",\"phase\":\"verify\"}";
const PAYLOAD_SECOND: &str = "{\"note\":\"second-957\",\"phase\":\"materialize\"}";
const PAYLOAD_ALT: &str = "{\"note\":\"alt-957\",\"phase\":\"verify\"}";
const RECEIPT_VERIFY: &str = "{\"outcome\":\"applied\",\"phase\":\"verify\"}";
const RECEIPT_MATERIALIZE: &str = "{\"outcome\":\"applied\",\"phase\":\"materialize\"}";

fn fixture_fence() -> StateFenceSnapshot {
    StateFenceSnapshot::capture(&serde_json::json!({"authority_epoch": 1}), 1)
        .expect("fixture fence is valid")
}

fn recovery_payload_envelope(
    operation: &RestoreJournalOperation,
    stream: &str,
    body: &str,
) -> Result<(String, String), eliot_ors::OrsError> {
    let authority_epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new("restore-journal-fixture-lineage")
                .map_err(|error| eliot_ors::OrsError::Contract(error.to_string()))?,
            epoch: 1,
        },
        predecessor: None,
    };
    let state_fence = fixture_fence();
    if state_fence.sha256 != operation.writer_fence_digest {
        return Err(eliot_ors::OrsError::FenceMismatch);
    }
    let access_class = RecoveryAccessClass {
        privacy: PrivacyClass::Private,
        visibility: OpaqueLabel::new("owner-only")
            .map_err(|error| eliot_ors::OrsError::Contract(error.to_string()))?,
        instruction_taint: InstructionTaint::DataOnly,
    };
    let envelope = RecoveryPayloadEnvelope::encrypted(
        RecoveryEnvelopeContext {
            operation_or_checkpoint_id: OpaqueLabel::new(operation.identity(stream)?)
                .map_err(|error| eliot_ors::OrsError::Contract(error.to_string()))?,
            privacy_and_visibility_class: access_class,
            authority_epoch,
            state_fence,
            created_at_ms: 1,
            known_at_ms: 1,
            expires_at_ms: None,
        },
        SecretReference::new("restore-journal-fixture", "test-key")
            .map_err(|error| eliot_ors::OrsError::Contract(error.to_string()))?,
        body.as_bytes().to_vec(),
    )?;
    let bytes = serde_json::to_string(&envelope)
        .map_err(|error| eliot_ors::OrsError::Encoding(error.to_string()))?;
    let digest = sha256_hex(bytes.as_bytes());
    Ok((bytes, digest))
}

fn append_intent(
    store: &RedbRecoveryStore,
    stream: &str,
    operation: &RestoreJournalOperation,
    body: &str,
) -> Result<eliot_ors::RestoreJournalAppendReceipt, eliot_ors::OrsError> {
    let (payload, digest) = recovery_payload_envelope(operation, stream, body)?;
    store.append_restore_journal_intent(stream, operation, &digest, &payload)
}

fn result_for(
    stream: &str,
    operation: &RestoreJournalOperation,
    intent_sequence: u64,
    receipt_body: &str,
) -> Result<RestoreJournalResult, eliot_ors::OrsError> {
    let (receipt, receipt_sha256) = recovery_payload_envelope(operation, stream, receipt_body)?;
    Ok(RestoreJournalResult {
        transaction_id: operation.transaction_id.clone(),
        phase_operation: operation.phase_operation.clone(),
        intent_sequence,
        receipt_sha256,
        receipt,
    })
}

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
        writer_fence_digest: fixture_fence().sha256,
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
        writer_fence_digest: fixture_fence().sha256,
        record_schema: RESTORE_JOURNAL_RECORD_SCHEMA.to_owned(),
        phase_operation: phase.to_owned(),
        request_digest: digest(request),
        body_digest: digest(body),
        expected_predecessor: predecessor,
        payload_handle: format!("payload-957-{transaction}-{phase}"),
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
    let receipt = append_intent(&store, stream, &genesis, PAYLOAD_GENESIS)?;
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
    let (payload, payload_sha) = recovery_payload_envelope(&bad_schema, stream, PAYLOAD_GENESIS)?;
    bad_schema.record_schema = "restore-journal-v9".to_owned();
    assert!(matches!(
        store.append_restore_journal_intent(stream, &bad_schema, &payload_sha, &payload),
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
    let first_operation = operation("tx-957-a", "verify", 'a', 'b', None);
    let first = append_intent(&store, stream, &first_operation, PAYLOAD_GENESIS)?;
    let second_operation = operation(
        "tx-957-a",
        "materialize",
        'c',
        'd',
        Some(predecessor_of(first.sequence, &first.record_digest)),
    );
    let second = append_intent(&store, stream, &second_operation, PAYLOAD_SECOND)?;
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
    let verify_operation = operation("tx-957-a", "verify", 'a', 'b', None);
    let intent = append_intent(&store, stream, &verify_operation, PAYLOAD_GENESIS)?;
    let answered = result_for(stream, &verify_operation, intent.sequence, RECEIPT_VERIFY)?;
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
    let head_operation = operation("tx-957-a", "verify", 'a', 'b', None);
    let head = append_intent(&store, stream, &head_operation, PAYLOAD_GENESIS)?;
    let shared = Some(predecessor_of(head.sequence, &head.record_digest));
    let winner_operation = operation("tx-957-a", "materialize", 'c', 'd', shared.clone());
    let winner = append_intent(&store, stream, &winner_operation, PAYLOAD_SECOND)?;
    assert_eq!(winner.sequence, 1);
    let loser_operation = operation("tx-957-a", "reconcile", 'e', 'f', shared);
    let loser = append_intent(&store, stream, &loser_operation, PAYLOAD_SECOND);
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
    let first = append_intent(&store, stream, &genesis, PAYLOAD_GENESIS)?;
    let replayed = append_intent(&store, stream, &genesis, PAYLOAD_GENESIS)?;
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
    append_intent(&store, stream, &genesis, PAYLOAD_GENESIS)?;
    let changed = append_intent(&store, stream, &genesis, PAYLOAD_ALT);
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
    let _lost_receipt = append_intent(&store, stream, &genesis, PAYLOAD_GENESIS)?;
    let (_, expected_payload_sha256) =
        recovery_payload_envelope(&genesis, stream, PAYLOAD_GENESIS)?;
    let entries = store.load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].operation, genesis);
    assert_eq!(entries[0].payload_sha256, expected_payload_sha256);
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
    let verify_operation = operation("tx-957-a", "verify", 'a', 'b', None);
    let (expected_payload, _) =
        recovery_payload_envelope(&verify_operation, stream, PAYLOAD_GENESIS)?;
    let receipt = append_intent(&store, stream, &verify_operation, PAYLOAD_GENESIS)?;
    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    let entries = reopened.load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].sequence, receipt.sequence);
    assert_eq!(entries[0].payload, expected_payload);
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
    let stale_operation = operation(
        "tx-957-a",
        "verify",
        'a',
        'b',
        Some(predecessor_of(9, &digest('9'))),
    );
    let stale = append_intent(&store, stream, &stale_operation, PAYLOAD_GENESIS);
    assert!(
        matches!(stale, Err(eliot_ors::OrsError::IntegrityProblem { .. })),
        "stale predecessor must fail"
    );
    let orphan = result_for(stream, &stale_operation, 0, RECEIPT_VERIFY)?;
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
    let expected_binding = binding("tx-957-a", "writer-957-a");
    store.bind_restore_journal_stream(stream, &expected_binding)?;
    assert!(
        store
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .is_empty(),
        "validated new journal reads known-empty"
    );
    assert_eq!(
        store.load_restore_journal_binding(stream)?,
        Some(expected_binding)
    );
    assert_eq!(store.load_restore_journal_result(stream, "verify")?, None);
    assert!(matches!(
        store.load_restore_journal_stream("unavailable-stream-957-11", MAX_JOURNAL_PAGE_ENTRIES),
        Err(eliot_ors::OrsError::IntegrityProblem { .. })
    ));
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// WORK_UNIT_CASE: 957/12
#[test]
fn bounds_hold_and_prune_retains_unresolved() -> TestResult {
    let (store, path) = open_db("12")?;
    let stream = "stream-957-12";
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    let verify_operation = operation("tx-957-a", "verify", 'a', 'b', None);
    let intent_a = append_intent(&store, stream, &verify_operation, PAYLOAD_GENESIS)?;
    store.append_restore_journal_result(
        stream,
        &result_for(stream, &verify_operation, intent_a.sequence, RECEIPT_VERIFY)?,
    )?;
    let materialize_operation = operation(
        "tx-957-a",
        "materialize",
        'c',
        'd',
        Some(predecessor_of(intent_a.sequence, &intent_a.record_digest)),
    );
    let intent_b = append_intent(&store, stream, &materialize_operation, PAYLOAD_SECOND)?;
    let reconcile_operation = operation(
        "tx-957-a",
        "reconcile",
        'e',
        'f',
        Some(predecessor_of(intent_b.sequence, &intent_b.record_digest)),
    );
    let intent_c = append_intent(&store, stream, &reconcile_operation, PAYLOAD_ALT)?;
    store.append_restore_journal_result(
        stream,
        &result_for(
            stream,
            &reconcile_operation,
            intent_c.sequence,
            RECEIPT_MATERIALIZE,
        )?,
    )?;
    assert_eq!(store.prune_restore_journal(stream, 1)?, 1);
    // I14.14: retained history requires the original durable-head denominator.
    assert!(matches!(
        store.load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES),
        Err(eliot_ors::OrsError::ProjectionLimitExceeded)
    ));
    let head = store.restore_journal_durable_head(stream)?;
    let readback =
        store.load_restore_journal_readback_against(&eliot_ors::RestoreJournalReadbackRequest {
            stream: stream.to_owned(),
            limit: MAX_JOURNAL_PAGE_ENTRIES,
            denominator: eliot_ors::RestoreJournalMemberDenominator::for_head(head.as_ref())?,
        })?;
    assert_eq!(
        readback.completeness,
        eliot_ors::RestoreJournalCompleteness::Complete
    );
    assert_eq!(readback.total_members, 3);
    assert_eq!(readback.retired_members, 1);
    assert_eq!(
        readback.history_fence,
        Some(predecessor_of(intent_a.sequence, &intent_a.record_digest))
    );
    let entries = readback.entries;
    assert_eq!(
        entries.len(),
        2,
        "unresolved intent is never evicted to fit"
    );
    assert_eq!(entries[0].operation.phase_operation, "materialize");
    assert_eq!(entries[1].operation.phase_operation, "reconcile");
    assert!(
        matches!(
            store.load_restore_journal_result(stream, "verify"),
            Err(eliot_ors::OrsError::IntegrityProblem {
                record_type: "restore_journal_operation",
                ..
            })
        ),
        "a retired result cannot be proved absent from a retained suffix"
    );
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
    store.bind_restore_journal_stream(stream, &binding("tx-957-a", "writer-957-a"))?;
    assert!(
        store
            .load_restore_journal_stream(stream, MAX_JOURNAL_PAGE_ENTRIES)?
            .is_empty(),
        "an ensured-but-empty journal is known-empty, never complete"
    );
    let verify_operation = operation("tx-957-a", "verify", 'a', 'b', None);
    append_intent(&store, stream, &verify_operation, PAYLOAD_GENESIS)?;
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
    let (payload, _) = recovery_payload_envelope(&genesis, stream, PAYLOAD_GENESIS)?;
    let tampered = store.append_restore_journal_intent(stream, &genesis, &digest('7'), &payload);
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
    let intent = append_intent(&store, stream, &genesis, PAYLOAD_GENESIS)?;
    let mut bad_receipt = result_for(stream, &genesis, intent.sequence, RECEIPT_VERIFY)?;
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
    let head_operation = operation("tx-957-a", "verify", 'a', 'b', None);
    let head = append_intent(&store, &stream, &head_operation, PAYLOAD_GENESIS)?;
    let shared = Arc::new(store);
    let predecessor = predecessor_of(head.sequence, &head.record_digest);
    let racer = |phase: &'static str, request: char, body: char| {
        let store = Arc::clone(&shared);
        let stream = stream.clone();
        let predecessor = predecessor.clone();
        std::thread::spawn(move || {
            let operation = operation("tx-957-a", phase, request, body, Some(predecessor));
            append_intent(store.as_ref(), stream.as_str(), &operation, PAYLOAD_SECOND)
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
    let verify_operation = operation("tx-957-a", "verify", 'a', 'b', None);
    append_intent(&store, stream, &verify_operation, PAYLOAD_GENESIS)?;
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
    let (foreign_payload, foreign_payload_sha) =
        recovery_payload_envelope(&verify_operation, stream, PAYLOAD_GENESIS)?;
    let mut foreign = operation("tx-957-a", "verify", 'a', 'b', None);
    foreign.record_schema = "backup-journal-v9".to_owned();
    assert!(matches!(
        reopened.append_restore_journal_intent(
            stream,
            &foreign,
            &foreign_payload_sha,
            &foreign_payload
        ),
        Err(eliot_ors::OrsError::InvalidField { .. })
    ));
    drop(reopened);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
    Ok(())
}
