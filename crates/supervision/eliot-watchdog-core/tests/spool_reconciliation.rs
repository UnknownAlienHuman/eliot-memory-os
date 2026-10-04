//! Issue #458 Wave A contract proof for `eliot-watchdog-core`.
//!
//! Wave A of issue #458 defines the owner-neutral Watchdog spool reconciliation
//! contract in `src/reconciliation.rs`: seven exported validators over the
//! Watchdog-owned cursor, the immutable export batch, and the sink-owned
//! acknowledgement. Before this file that module carried no `mod tests`, the
//! package had no `tests/` directory at all, and every one of those validators
//! was reachable only indirectly from `bins/eliot-watchdog`. Nothing pinned the
//! fail-closed contract where it is defined, so a validator could be relaxed and
//! stay green as long as the binary happened not to hit the changed branch.
//!
//! These cases bind each validator to the behaviour its own doc comment
//! promises: the exact terminal table (both directions), the distinction
//! between a non-consecutive batch and a mutated restatement, the exact
//! empty-batch shape including its `u64::MAX` fail-closed leg, contiguous
//! cursor advance, gap ordering, retry byte-stability, and duplicate-ack
//! classification. Ownership is unchanged by this file: the Watchdog still owns
//! records and cursor, the sink still owns only its dispositions, and no
//! canonical path is touched.

use std::error::Error;

use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolCursor, WatchdogSpoolEntryDisposition,
    WatchdogSpoolExportBatch, WatchdogSpoolExportEntry, WatchdogSpoolPayloadKind,
    WatchdogSpoolReconciliationError as Error_, WatchdogSpoolSinkDisposition,
    acknowledgement_advances_cursor, export_retry_identity_equal, is_duplicate_ack,
    validate_acknowledgement, validate_batch, validate_batch_freshness, validate_cursor,
};

type TestResult = Result<(), Box<dyn Error>>;

const SCHEMA: u16 = 1;
const GENERATION: u64 = 7;
const EPOCH: u64 = 3;
const INSTALLATION: &str = "install-a";
const SINK: &str = "sink-a";

/// Ownership: fixture only. Opaque caller-supplied digests with exact SHA-256
/// hex shape; this core never computes them, so a repeated character stands in
/// for a real digest without pretending to be one.
fn digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn cursor(acknowledged: u64) -> WatchdogSpoolCursor {
    WatchdogSpoolCursor {
        schema_version: SCHEMA,
        acknowledged_sequence: acknowledged,
        watchdog_generation: GENERATION,
        watchdog_epoch: EPOCH,
        installation_id: INSTALLATION.to_owned(),
        sink_id: SINK.to_owned(),
    }
}

fn entry(sequence: u64, kind: WatchdogSpoolPayloadKind, seed: char) -> WatchdogSpoolExportEntry {
    WatchdogSpoolExportEntry {
        sequence,
        schema_version: SCHEMA,
        observed_at_ms: 1_000 + sequence,
        payload_kind: kind,
        payload_digest: digest(seed),
        record_digest: digest(seed),
    }
}

/// Ownership: fixture only. A well-formed non-empty batch covering
/// `acknowledged + 1 ..= acknowledged + entries.len()` with a live high-water of
/// `last_sequence`.
fn batch(entries: Vec<WatchdogSpoolExportEntry>) -> WatchdogSpoolExportBatch {
    let predecessor = cursor(entries.first().map_or(0, |entry| entry.sequence - 1));
    let first_sequence = entries.first().map_or(0, |entry| entry.sequence);
    let last_sequence = entries.last().map_or(0, |entry| entry.sequence);
    WatchdogSpoolExportBatch {
        schema_version: SCHEMA,
        batch_id: "batch-a".to_owned(),
        installation_id: INSTALLATION.to_owned(),
        watchdog_generation: GENERATION,
        watchdog_epoch: EPOCH,
        high_water_sequence: last_sequence,
        predecessor_cursor: predecessor,
        first_sequence,
        last_sequence,
        item_count: entries.len(),
        byte_size: 128,
        entries,
        batch_digest: digest('d'),
        is_empty_batch: false,
        created_at_ms: 1_000,
        expires_at_ms: 2_000,
    }
}

/// Ownership: fixture only. A well-formed acknowledgement echoing the batch
/// with `dispositions` applied to each entry in order.
fn ack(
    batch: &WatchdogSpoolExportBatch,
    dispositions: Vec<WatchdogSpoolSinkDisposition>,
) -> WatchdogSpoolAcknowledgement {
    WatchdogSpoolAcknowledgement {
        schema_version: batch.schema_version,
        batch_id: batch.batch_id.clone(),
        batch_digest: batch.batch_digest.clone(),
        predecessor_sequence: batch.predecessor_cursor.acknowledged_sequence,
        first_sequence: batch.first_sequence,
        last_sequence: batch.last_sequence,
        sink_id: batch.predecessor_cursor.sink_id.clone(),
        watchdog_generation: batch.watchdog_generation,
        watchdog_epoch: batch.watchdog_epoch,
        installation_id: batch.installation_id.clone(),
        dispositions: batch
            .entries
            .iter()
            .zip(dispositions)
            .map(|(entry, disposition)| WatchdogSpoolEntryDisposition {
                sequence: entry.sequence,
                disposition,
                record_digest: entry.record_digest.clone(),
            })
            .collect(),
    }
}

fn two_heartbeats() -> WatchdogSpoolExportBatch {
    batch(vec![
        entry(1, WatchdogSpoolPayloadKind::Heartbeat, 'a'),
        entry(2, WatchdogSpoolPayloadKind::Heartbeat, 'b'),
    ])
}

#[test]
fn cursor_refuses_every_invalid_field_and_an_acknowledged_above_the_high_water() -> TestResult {
    validate_cursor(&cursor(2), 2)?;

    let mut zero_schema = cursor(0);
    zero_schema.schema_version = 0;
    assert_eq!(
        validate_cursor(&zero_schema, 0),
        Err(Error_::InvalidField("schema_version"))
    );

    let mut zero_generation = cursor(0);
    zero_generation.watchdog_generation = 0;
    assert_eq!(
        validate_cursor(&zero_generation, 0),
        Err(Error_::InvalidField("watchdog_generation"))
    );

    let mut blank_installation = cursor(0);
    blank_installation.installation_id = String::new();
    assert_eq!(
        validate_cursor(&blank_installation, 0),
        Err(Error_::InvalidField("installation_id"))
    );

    let mut blank_sink = cursor(0);
    blank_sink.sink_id = String::new();
    assert_eq!(
        validate_cursor(&blank_sink, 0),
        Err(Error_::InvalidField("sink_id"))
    );

    // The explicit initial epoch is legal, so epoch 0 must NOT be refused here;
    // only the acknowledged-above-high-water combination is.
    let mut initial_epoch = cursor(0);
    initial_epoch.watchdog_epoch = 0;
    validate_cursor(&initial_epoch, 0)?;
    assert_eq!(validate_cursor(&cursor(3), 2), Err(Error_::InvalidCursor));
    Ok(())
}

#[test]
fn batch_refuses_each_predecessor_owner_identity_divergence_with_its_own_variant() -> TestResult {
    let base = two_heartbeats();

    let mut drifted_installation = base.clone();
    drifted_installation.installation_id = "install-b".to_owned();
    assert_eq!(
        validate_batch(&drifted_installation, 2),
        Err(Error_::InstallationMismatch)
    );

    let mut drifted_generation = base.clone();
    drifted_generation.watchdog_generation = 8;
    assert_eq!(
        validate_batch(&drifted_generation, 2),
        Err(Error_::GenerationMismatch)
    );

    let mut drifted_epoch = base.clone();
    drifted_epoch.watchdog_epoch = 4;
    assert_eq!(
        validate_batch(&drifted_epoch, 2),
        Err(Error_::EpochMismatch)
    );

    let mut drifted_schema = base.clone();
    drifted_schema.schema_version = 2;
    assert_eq!(
        validate_batch(&drifted_schema, 2),
        Err(Error_::PredecessorMismatch)
    );

    // A caller high-water older than the embedded high-water is refused rather
    // than trusted, so a stale export cannot validate against a newer spool.
    assert_eq!(validate_batch(&base, 1), Err(Error_::InvalidCursor));
    validate_batch(&base, 2)?;
    Ok(())
}

#[test]
fn empty_batch_shape_is_exact_and_fails_closed_at_sequence_exhaustion() -> TestResult {
    let mut empty = WatchdogSpoolExportBatch {
        schema_version: SCHEMA,
        batch_id: "batch-empty".to_owned(),
        installation_id: INSTALLATION.to_owned(),
        watchdog_generation: GENERATION,
        watchdog_epoch: EPOCH,
        predecessor_cursor: cursor(5),
        first_sequence: 6,
        last_sequence: 5,
        high_water_sequence: 5,
        item_count: 0,
        byte_size: 0,
        entries: Vec::new(),
        batch_digest: digest('d'),
        is_empty_batch: true,
        created_at_ms: 1_000,
        expires_at_ms: 2_000,
    };
    validate_batch(&empty, 5)?;

    let mut with_entry = empty.clone();
    with_entry.entries = vec![entry(6, WatchdogSpoolPayloadKind::Heartbeat, 'a')];
    assert_eq!(validate_batch(&with_entry, 5), Err(Error_::EmptyBatch));

    let mut counted = empty.clone();
    counted.item_count = 1;
    assert_eq!(
        validate_batch(&counted, 5),
        Err(Error_::InvalidField("item_count"))
    );

    let mut sized = empty.clone();
    sized.byte_size = 1;
    assert_eq!(
        validate_batch(&sized, 5),
        Err(Error_::InvalidField("byte_size"))
    );

    let mut cursor_behind = empty.clone();
    cursor_behind.predecessor_cursor = cursor(4);
    assert_eq!(
        validate_batch(&cursor_behind, 5),
        Err(Error_::PredecessorMismatch)
    );

    // `first_sequence == high_water + 1` is inexpressible at u64::MAX, so the
    // empty batch fails closed there instead of wrapping to sequence 0.
    empty.predecessor_cursor = cursor(u64::MAX);
    empty.high_water_sequence = u64::MAX;
    empty.first_sequence = u64::MAX;
    empty.last_sequence = u64::MAX;
    assert_eq!(
        validate_batch(&empty, u64::MAX),
        Err(Error_::PredecessorMismatch)
    );
    Ok(())
}

#[test]
fn batch_entries_must_be_strictly_consecutive_and_counted_exactly() -> TestResult {
    let base = two_heartbeats();
    validate_batch(&base, 2)?;

    let mut skipped = base.clone();
    skipped.entries[1].sequence = 3;
    skipped.last_sequence = 3;
    skipped.high_water_sequence = 3;
    assert_eq!(
        validate_batch(&skipped, 3),
        Err(Error_::NonConsecutiveSequences)
    );

    let mut repeated = base.clone();
    // An IDENTICAL restatement of the same sequence is still a coverage break:
    // only a differing digest makes it a mutation.
    repeated.entries[1] = entry(1, WatchdogSpoolPayloadKind::Heartbeat, 'a');
    repeated.item_count = 2;
    repeated.last_sequence = 1;
    repeated.high_water_sequence = 1;
    assert_eq!(
        validate_batch(&repeated, 1),
        Err(Error_::NonConsecutiveSequences)
    );

    let mut miscounted = base.clone();
    miscounted.item_count = 3;
    assert_eq!(
        validate_batch(&miscounted, 2),
        Err(Error_::InvalidField("item_count"))
    );

    let mut zero_sized = base.clone();
    zero_sized.byte_size = 0;
    assert_eq!(
        validate_batch(&zero_sized, 2),
        Err(Error_::InvalidField("byte_size"))
    );

    let mut off_chain = base.clone();
    off_chain.first_sequence = 2;
    assert_eq!(
        validate_batch(&off_chain, 2),
        Err(Error_::PredecessorMismatch)
    );

    let mut beyond_high_water = base.clone();
    beyond_high_water.last_sequence = 3;
    beyond_high_water.high_water_sequence = 2;
    assert_eq!(
        validate_batch(&beyond_high_water, 2),
        Err(Error_::InvalidField("last_sequence"))
    );

    let mut bad_entry_digest = base.clone();
    bad_entry_digest.entries[0].record_digest = "short".to_owned();
    assert_eq!(
        validate_batch(&bad_entry_digest, 2),
        Err(Error_::InvalidField("record_digest"))
    );

    let mut drifted_entry_schema = base.clone();
    drifted_entry_schema.entries[1].schema_version = 2;
    assert_eq!(
        validate_batch(&drifted_entry_schema, 2),
        Err(Error_::InvalidField("schema_version"))
    );
    Ok(())
}

#[test]
fn a_sequence_restated_under_a_different_digest_is_mutation_not_a_gap() {
    // The two failure modes are distinguishable and must stay so: a forward
    // gap is a coverage break, while an immediately repeated sequence carrying
    // different bytes is a mutated record.
    let mutated = batch(vec![
        entry(1, WatchdogSpoolPayloadKind::Heartbeat, 'a'),
        entry(1, WatchdogSpoolPayloadKind::Heartbeat, 'c'),
    ]);
    assert_eq!(validate_batch(&mutated, 1), Err(Error_::PayloadMutated));

    // A non-hex digest is a shape violation and is refused before the sequence
    // comparison can classify it.
    let unshaped = batch(vec![
        entry(1, WatchdogSpoolPayloadKind::Heartbeat, 'a'),
        entry(1, WatchdogSpoolPayloadKind::Heartbeat, 'z'),
    ]);
    assert_eq!(
        validate_batch(&unshaped, 1),
        Err(Error_::InvalidField("payload_digest"))
    );
}

#[test]
fn batch_window_shape_and_freshness_are_both_enforced() -> TestResult {
    let base = two_heartbeats();

    let mut inverted_window = base.clone();
    inverted_window.created_at_ms = 2_000;
    assert_eq!(
        validate_batch(&inverted_window, 2),
        Err(Error_::InvalidField("expires_at_ms"))
    );

    validate_batch_freshness(&base, 1_999)?;
    assert_eq!(
        validate_batch_freshness(&base, 2_000),
        Err(Error_::ExpiredBatch)
    );
    assert_eq!(
        validate_batch_freshness(&base, 2_001),
        Err(Error_::ExpiredBatch)
    );
    Ok(())
}

#[test]
fn acknowledgement_identity_echo_divergences_each_yield_their_own_variant() -> TestResult {
    let base = two_heartbeats();
    let good = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );
    validate_acknowledgement(&base, &good)?;

    let mut wrong_batch_id = good.clone();
    wrong_batch_id.batch_id = "batch-b".to_owned();
    assert_eq!(
        validate_acknowledgement(&base, &wrong_batch_id),
        Err(Error_::BatchDigestMismatch)
    );

    let mut wrong_batch_digest = good.clone();
    wrong_batch_digest.batch_digest = digest('e');
    assert_eq!(
        validate_acknowledgement(&base, &wrong_batch_digest),
        Err(Error_::BatchDigestMismatch)
    );

    let mut wrong_predecessor = good.clone();
    wrong_predecessor.predecessor_sequence = 1;
    assert_eq!(
        validate_acknowledgement(&base, &wrong_predecessor),
        Err(Error_::PredecessorMismatch)
    );

    let mut wrong_first = good.clone();
    wrong_first.first_sequence = 2;
    assert_eq!(
        validate_acknowledgement(&base, &wrong_first),
        Err(Error_::AcknowledgementRangeMismatch)
    );

    let mut wrong_sink = good.clone();
    wrong_sink.sink_id = "sink-b".to_owned();
    assert_eq!(
        validate_acknowledgement(&base, &wrong_sink),
        Err(Error_::SinkMismatch)
    );

    let mut wrong_generation = good.clone();
    wrong_generation.watchdog_generation = 8;
    assert_eq!(
        validate_acknowledgement(&base, &wrong_generation),
        Err(Error_::GenerationMismatch)
    );

    let mut wrong_epoch = good.clone();
    wrong_epoch.watchdog_epoch = 4;
    assert_eq!(
        validate_acknowledgement(&base, &wrong_epoch),
        Err(Error_::EpochMismatch)
    );

    let mut wrong_installation = good.clone();
    wrong_installation.installation_id = "install-b".to_owned();
    assert_eq!(
        validate_acknowledgement(&base, &wrong_installation),
        Err(Error_::InstallationMismatch)
    );

    let mut wrong_schema = good.clone();
    wrong_schema.schema_version = 2;
    assert_eq!(
        validate_acknowledgement(&base, &wrong_schema),
        Err(Error_::InvalidField("schema_version"))
    );
    Ok(())
}

#[test]
fn acknowledgement_coverage_is_one_line_per_entry_in_order() {
    let base = two_heartbeats();

    let short = ack(&base, vec![WatchdogSpoolSinkDisposition::Applied]);
    assert_eq!(
        validate_acknowledgement(&base, &short),
        Err(Error_::AcknowledgementRangeMismatch)
    );

    let mut reordered = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );
    reordered.dispositions.swap(0, 1);
    assert_eq!(
        validate_acknowledgement(&base, &reordered),
        Err(Error_::AcknowledgementRangeMismatch)
    );

    let mut tampered_entry = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );
    tampered_entry.dispositions[0].record_digest = digest('e');
    assert_eq!(
        validate_acknowledgement(&base, &tampered_entry),
        Err(Error_::EntryDigestMismatch)
    );

    let unknown = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::Unknown,
        ],
    );
    assert_eq!(
        validate_acknowledgement(&base, &unknown),
        Err(Error_::UnknownOutcome)
    );

    let reasonless = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::Rejected {
                reason: String::new(),
            },
        ],
    );
    assert_eq!(
        validate_acknowledgement(&base, &reasonless),
        Err(Error_::InvalidField("reason"))
    );
}

#[test]
fn the_disposition_terminal_table_matches_every_documented_row() {
    use WatchdogSpoolPayloadKind::{Gap, Heartbeat, Recovery};
    use WatchdogSpoolSinkDisposition as Disposition;

    // Exactly the table in the module doc comment, asserted in both directions
    // for every payload kind so that widening any single row turns this red.
    let table = [
        (Disposition::Received, false, false, false),
        (Disposition::Durable, false, false, false),
        (Disposition::AdmittedCandidate, false, false, false),
        (Disposition::Applied, true, true, true),
        (
            Disposition::Rejected {
                reason: "policy".to_owned(),
            },
            true,
            true,
            true,
        ),
        (Disposition::Unknown, false, false, false),
        (Disposition::GapRequiresRecovery, false, true, true),
    ];

    for (disposition, heartbeat, gap, recovery) in table {
        assert_eq!(
            disposition.advances_cursor(Heartbeat),
            heartbeat,
            "heartbeat row for {disposition:?}"
        );
        assert_eq!(
            disposition.advances_cursor(Gap),
            gap,
            "gap row for {disposition:?}"
        );
        assert_eq!(
            disposition.advances_cursor(Recovery),
            recovery,
            "recovery row for {disposition:?}"
        );
    }

    // Rejected is terminal-as-decided, not terminal-for-application: it must
    // advance the cursor without ever claiming the entry was applied.
    let rejected = Disposition::Rejected {
        reason: "policy".to_owned(),
    };
    assert!(rejected.advances_cursor(Heartbeat));
    assert!(!rejected.terminal_for_application());
    assert!(Disposition::Applied.terminal_for_application());
    assert!(Disposition::GapRequiresRecovery.terminal_for_application());
    assert!(!Disposition::Received.terminal_for_application());
    assert!(!Disposition::Durable.terminal_for_application());
    assert!(!Disposition::AdmittedCandidate.terminal_for_application());
    assert!(!Disposition::Unknown.terminal_for_application());
}

#[test]
fn acknowledgement_advances_the_cursor_exactly_once_to_the_last_sequence() -> TestResult {
    let base = two_heartbeats();
    let applied = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );
    assert_eq!(acknowledgement_advances_cursor(&base, &applied)?, 2);

    // Rejected advances exactly like Applied: the entry is decided, not applied.
    let rejected = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Rejected {
                reason: "not admitted".to_owned(),
            },
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );
    assert_eq!(acknowledgement_advances_cursor(&base, &rejected)?, 2);

    // Nothing durable, nothing admitted, nothing known: the cursor stays put.
    for stalled in [
        WatchdogSpoolSinkDisposition::Received,
        WatchdogSpoolSinkDisposition::Durable,
        WatchdogSpoolSinkDisposition::AdmittedCandidate,
    ] {
        let stalled = ack(&base, vec![stalled.clone(), stalled.clone()]);
        assert_eq!(
            acknowledgement_advances_cursor(&base, &stalled),
            Err(Error_::NonTerminalDisposition),
            "{stalled:?} must not advance"
        );
    }

    // An empty batch has nothing to advance past.
    let mut empty = base.clone();
    empty.is_empty_batch = true;
    let empty_ack = ack(&empty, Vec::new());
    assert_eq!(
        acknowledgement_advances_cursor(&empty, &empty_ack),
        Err(Error_::EmptyBatch)
    );
    Ok(())
}

#[test]
fn a_gap_like_entry_left_non_terminal_blocks_every_later_terminal_entry() -> TestResult {
    let base = batch(vec![
        entry(1, WatchdogSpoolPayloadKind::Heartbeat, 'a'),
        entry(2, WatchdogSpoolPayloadKind::Gap, 'b'),
        entry(3, WatchdogSpoolPayloadKind::Heartbeat, 'c'),
    ]);

    // The later heartbeat claims terminal while the gap is still unresolved:
    // that is specifically a gap skip, not merely a stalled entry.
    let skipped_gap = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::Durable,
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );
    assert_eq!(
        acknowledgement_advances_cursor(&base, &skipped_gap),
        Err(Error_::GapSkipped)
    );

    // The gap resolves in order and the whole batch advances.
    let resolved = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::GapRequiresRecovery,
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );
    assert_eq!(acknowledgement_advances_cursor(&base, &resolved)?, 3);

    // GapRequiresRecovery on a heartbeat is the wrong phase: it stalls that
    // entry but does NOT arm the gap blocker, so a later Applied entry is not a
    // gap skip — the batch is simply stalled.
    let wrong_phase = batch(vec![
        entry(1, WatchdogSpoolPayloadKind::Heartbeat, 'a'),
        entry(2, WatchdogSpoolPayloadKind::Heartbeat, 'b'),
    ]);
    let wrong_phase_ack = ack(
        &wrong_phase,
        vec![
            WatchdogSpoolSinkDisposition::GapRequiresRecovery,
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );
    assert_eq!(
        acknowledgement_advances_cursor(&wrong_phase, &wrong_phase_ack),
        Err(Error_::NonTerminalDisposition)
    );
    Ok(())
}

#[test]
fn retry_identity_compares_bytes_not_structural_equality() -> TestResult {
    let first = two_heartbeats();
    validate_batch(&first, 2)?;

    let mut identical = first.clone();
    identical.created_at_ms = 1_500;
    identical.is_empty_batch = false;
    assert!(
        export_retry_identity_equal(&first, &identical),
        "a resend with a different export timestamp carries the same batch bytes"
    );

    let mut different_digest = first.clone();
    different_digest.batch_digest = digest('e');
    assert!(!export_retry_identity_equal(&first, &different_digest));

    let mut different_entry_digest = first.clone();
    different_entry_digest.entries[1].record_digest = digest('e');
    assert!(!export_retry_identity_equal(
        &first,
        &different_entry_digest
    ));

    let mut different_length = first.clone();
    different_length.entries.pop();
    assert!(!export_retry_identity_equal(&first, &different_length));
    Ok(())
}

#[test]
fn duplicate_acknowledgement_is_decided_against_the_stored_cursor() {
    let base = two_heartbeats();
    let applied = ack(
        &base,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );

    // The stored cursor has already advanced past this acknowledgement's
    // predecessor: a duplicate to ignore, not an error.
    assert!(is_duplicate_ack(2, &applied));

    // Equal means this is the next acknowledgement to apply.
    assert!(!is_duplicate_ack(0, &applied));

    // Ahead of the stored cursor: a future acknowledgement the owner must hold
    // until the missing range arrives. Building it from a later batch keeps the
    // classification distinct from the duplicate leg above.
    let mut later = base.clone();
    later.predecessor_cursor = cursor(5);
    let later = ack(
        &later,
        vec![
            WatchdogSpoolSinkDisposition::Applied,
            WatchdogSpoolSinkDisposition::Applied,
        ],
    );
    assert_eq!(later.predecessor_sequence, 5);
    assert!(!is_duplicate_ack(2, &later));
}
