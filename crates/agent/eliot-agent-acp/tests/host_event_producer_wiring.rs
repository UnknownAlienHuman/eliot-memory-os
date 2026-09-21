//! Bridge producer wiring proof for issue #1934 (I7.23).
//!
//! One stream proves the actual producer path end to end: ACP transport
//! bytes (content-length framed JSON-RPC) flow through decode, typed
//! normalization, `stage_allowed`/`stage_redacted`, and `commit` on the
//! merged [`DurableHostEventJournal`]. Persist happens before cursor advance:
//! the cursor is unadvanced before each produce call and advanced only by the
//! commit inside it. A denied-content frame fails closed on the allowed path
//! with the cursor unadvanced, then commits explicitly through the redacted
//! path with a receipt and no source bytes.

use eliot_agent_acp::{
    AcpFrameCodec, DurableHostEventJournal, IngestError, ProduceOutcome, ProducerError,
    ProducerFrame, RedactionReason, produce_allowed, produce_redacted,
};
use eliot_agent_api::{
    ClockReading, EventCursor, EventId, RestrictedRawSourceHandle, SessionLifecycleTransition,
};
use eliot_contracts::sha256_hex;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const STREAM: &str = "host-events:producer-1934";

fn observed_at() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1_750_000_000_000),
        known_time_ms: Some(1_750_000_000_001),
        transaction_sequence: None,
        monotonic_ns: Some(1934),
    }
}

fn frame(body: &[u8]) -> TestResult<Vec<u8>> {
    Ok(AcpFrameCodec::encode(body)?)
}

fn producer_frame<'a>(
    sequence: u64,
    event: &str,
    cursor: &str,
    handle: &str,
    frame_bytes: &'a [u8],
    transition: SessionLifecycleTransition,
) -> Result<ProducerFrame<'a>, Box<dyn std::error::Error>> {
    Ok(ProducerFrame {
        stream_id: STREAM,
        stream_sequence: sequence,
        event_id: EventId::new(event)?,
        cursor: EventCursor::new(cursor)?,
        native_session: "thread-producer-1934",
        raw_source_handle: RestrictedRawSourceHandle::new(handle)?,
        frame_bytes,
        transition,
        observed_at: observed_at(),
    })
}

#[test]
fn producer_persists_before_cursor_advance_end_to_end() -> TestResult {
    let mut journal = DurableHostEventJournal::new();
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 0);

    let benign = frame(
        br#"{"jsonrpc":"2.0","method":"session/update","params":{"update":"agent_message_chunk"}}"#,
    )?;
    let produced: ProduceOutcome = produce_allowed(
        &mut journal,
        &producer_frame(
            1,
            "evt-producer-1",
            "cursor-producer-1",
            "restricted-source:producer-1",
            &benign,
            SessionLifecycleTransition::Started,
        )?,
    )?;
    assert!(produced.fresh);
    assert!(!produced.redacted);
    assert_eq!(produced.cursor.last_durable_sequence, 1);
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 1);
    let record = journal
        .get(&produced.key)
        .ok_or("produced record must be stored")?;
    assert_eq!(record.transport_hash.as_str(), sha256_hex(&benign));
    assert_eq!(record.stored.bytes(), benign.as_slice());
    assert!(record.stored.redaction_receipt().is_none());
    assert_eq!(record.envelope_digest, record.envelope.compute_digest()?);
    assert!(record.disposition.committed);
    assert_eq!(record.envelope.sequence, 1);

    let denied = frame(
        br#"{"jsonrpc":"2.0","method":"session/update","params":{"note":"secret-value-hidden_reasoning"}}"#,
    )?;
    check_denied_fails_closed_then_redacts(&mut journal, &denied)?;
    check_idempotent_replay(&mut journal, &benign, &produced)?;
    Ok(())
}

fn check_denied_fails_closed_then_redacts(
    journal: &mut DurableHostEventJournal,
    denied: &[u8],
) -> TestResult {
    let Err(denied_err) = produce_allowed(
        journal,
        &producer_frame(
            2,
            "evt-producer-2",
            "cursor-producer-2",
            "restricted-source:producer-2",
            denied,
            SessionLifecycleTransition::Resumed,
        )?,
    ) else {
        return Err("denied content must fail closed on the allowed path".into());
    };
    assert!(
        matches!(
            denied_err,
            ProducerError::Ingest(IngestError::PrivacyViolation)
        ),
        "unexpected producer error: {denied_err:?}"
    );
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 1);

    let redacted = produce_redacted(
        journal,
        &producer_frame(
            2,
            "evt-producer-2",
            "cursor-producer-2",
            "restricted-source:producer-redacted-2",
            denied,
            SessionLifecycleTransition::Resumed,
        )?,
        vec!["secret".to_owned(), "scope".to_owned()],
    )?;
    assert!(redacted.fresh);
    assert!(redacted.redacted);
    assert_eq!(redacted.cursor.last_durable_sequence, 2);
    let stored = journal
        .get(&redacted.key)
        .ok_or("redacted record must be stored")?;
    assert_eq!(stored.transport_hash.as_str(), sha256_hex(denied));
    assert!(
        !stored
            .stored
            .bytes()
            .windows(12)
            .any(|window| window == b"secret-value")
    );
    let receipt = stored
        .stored
        .redaction_receipt()
        .ok_or("redacted record must expose a receipt")?;
    assert_eq!(receipt.reason, RedactionReason::ForbiddenContentDetected);
    assert_eq!(receipt.transport_hash.as_str(), sha256_hex(denied));
    Ok(())
}

fn check_idempotent_replay(
    journal: &mut DurableHostEventJournal,
    benign: &[u8],
    produced: &ProduceOutcome,
) -> TestResult {
    let replay = produce_allowed(
        journal,
        &producer_frame(
            1,
            "evt-producer-1",
            "cursor-producer-1",
            "restricted-source:producer-1",
            benign,
            SessionLifecycleTransition::Started,
        )?,
    )?;
    assert!(!replay.fresh);
    assert_eq!(replay.key, produced.key);
    assert_eq!(journal.record_count(), 2);
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 2);
    Ok(())
}
