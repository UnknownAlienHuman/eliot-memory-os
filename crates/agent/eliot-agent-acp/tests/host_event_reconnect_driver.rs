//! Reconnect driver proof for issue #1934 (I7.23).
//!
//! One stream proves the reconnect path through the persistence-owner seam:
//! a committed-but-unacknowledged event plus a staged-but-uncommitted event
//! (simulated pre-commit interruption, cursor unadvanced) flow through
//! [`drive_reconnect`](eliot_agent_acp::drive_reconnect) into commit,
//! delivery, and acknowledgement. A refused delivery stops the drive with the
//! remainder still pending; duplicates never create a second application.

use eliot_agent_acp::{
    AcpFrameCodec, AcpHostEventInput, DurableHostEventJournal, EventKey, ProducerFrame,
    StageAllowed, drive_reconnect, normalize_acp_event, produce_allowed,
};
use eliot_agent_api::{
    ClockReading, EventCursor, EventId, HostEventDeliveryDisposition, HostEventPrivacyClass,
    NativeSession, NativeSessionLocator, NormalizationCoverage, NormalizedHostEventEnvelope,
    NormalizedHostEventPayload, ProviderObservationLineage, RestrictedRawSourceHandle,
    SessionLifecycleObservation, SessionLifecycleTransition, SessionObservation,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const STREAM: &str = "host-events:reconnect-1934";

fn observed_at() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1_750_000_000_000),
        known_time_ms: Some(1_750_000_000_001),
        transaction_sequence: None,
        monotonic_ns: Some(1934),
    }
}

fn lineage() -> Result<ProviderObservationLineage, Box<dyn std::error::Error>> {
    Ok(ProviderObservationLineage::SessionObservation(
        SessionObservation {
            session_id: None,
            native: NativeSession::Native(NativeSessionLocator::new("thread-reconnect-1934")?),
        },
    ))
}

fn normalize(
    event: &str,
    cursor: &str,
    sequence: u64,
    source_bytes: &[u8],
    handle: &str,
) -> Result<NormalizedHostEventEnvelope, Box<dyn std::error::Error>> {
    let (envelope, receipt) = normalize_acp_event(AcpHostEventInput {
        event_id: EventId::new(event)?,
        cursor: EventCursor::new(cursor)?,
        sequence,
        predecessors: Vec::new(),
        lineage: lineage()?,
        raw_source_bytes: source_bytes,
        raw_source_handle: RestrictedRawSourceHandle::new(handle)?,
        payload: NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
            transition: SessionLifecycleTransition::Suspended,
            detail_ref: None,
        }),
        omitted_source_fields: Vec::new(),
        warnings: Vec::new(),
        privacy_class: HostEventPrivacyClass::PublicSummary,
        coverage: NormalizationCoverage::Complete,
        observed_at: observed_at(),
        delivery: HostEventDeliveryDisposition::DurableOrdered,
        admission: None,
    })?;
    assert_eq!(envelope.normalization, receipt);
    Ok(envelope)
}

fn produce_one(
    journal: &mut DurableHostEventJournal,
    sequence: u64,
    event: &str,
    cursor: &str,
    handle: &str,
    frame: &[u8],
) -> TestResult {
    produce_allowed(
        journal,
        &ProducerFrame {
            stream_id: STREAM,
            stream_sequence: sequence,
            event_id: EventId::new(event)?,
            cursor: EventCursor::new(cursor)?,
            native_session: "thread-reconnect-1934",
            raw_source_handle: RestrictedRawSourceHandle::new(handle)?,
            frame_bytes: frame,
            transition: SessionLifecycleTransition::Suspended,
            observed_at: observed_at(),
        },
    )?;
    Ok(())
}

#[test]
fn reconnect_commits_delivers_and_acknowledges_pending() -> TestResult {
    let mut journal = DurableHostEventJournal::new();
    let frame_one = AcpFrameCodec::encode(
        br#"{"jsonrpc":"2.0","method":"session/update","params":{"update":"agent_message_chunk"}}"#,
    )?;
    produce_one(
        &mut journal,
        1,
        "evt-reconnect-1",
        "cursor-reconnect-1",
        "restricted-source:reconnect-1",
        &frame_one,
    )?;
    journal.acknowledge(STREAM, 1)?;

    let pending_bytes = b"acp-frame-reconnect-1934-benign-suspended".to_vec();
    let envelope = normalize(
        "evt-reconnect-2",
        "cursor-reconnect-2",
        2,
        &pending_bytes,
        "restricted-source:reconnect-2",
    )?;
    let staged = journal.stage_allowed(StageAllowed {
        stream_id: STREAM,
        stream_sequence: 2,
        transport_bytes: &pending_bytes,
        envelope,
        binding: None,
        admission: None,
        physical_observation: None,
        requested_route_digest: None,
        actual_route_digest: None,
        predecessors: Vec::new(),
        warnings: Vec::new(),
        transformation_version: eliot_agent_acp::DURABLE_INGEST_TRANSFORMATION_VERSION,
    })?;
    assert!(staged.fresh);
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 1);

    let pending = journal.pending_for_reconnect(STREAM);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].sequence, 2);
    assert!(!pending[0].committed);

    let outcome = drive_reconnect(&mut journal, STREAM, |_| true)?;
    assert_eq!(outcome.committed, vec![2]);
    assert_eq!(outcome.delivered, vec![2]);
    assert_eq!(outcome.acked_through, 2);
    assert!(!outcome.stopped_early);
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 2);
    assert!(journal.pending_for_reconnect(STREAM).is_empty());
    let key = EventKey {
        stream_id: STREAM.to_owned(),
        sequence: 2,
    };
    assert!(journal.record_application(&key)?);
    assert!(!journal.record_application(&key)?);
    Ok(())
}

#[test]
fn reconnect_stops_on_refused_delivery_without_acknowledging() -> TestResult {
    let mut journal = DurableHostEventJournal::new();
    let pending_bytes = b"acp-frame-reconnect-1934-held".to_vec();
    let envelope = normalize(
        "evt-reconnect-held",
        "cursor-reconnect-held",
        1,
        &pending_bytes,
        "restricted-source:reconnect-held",
    )?;
    journal.stage_allowed(StageAllowed {
        stream_id: STREAM,
        stream_sequence: 1,
        transport_bytes: &pending_bytes,
        envelope,
        binding: None,
        admission: None,
        physical_observation: None,
        requested_route_digest: None,
        actual_route_digest: None,
        predecessors: Vec::new(),
        warnings: Vec::new(),
        transformation_version: eliot_agent_acp::DURABLE_INGEST_TRANSFORMATION_VERSION,
    })?;

    let outcome = drive_reconnect(&mut journal, STREAM, |_| false)?;
    assert_eq!(outcome.committed, vec![1]);
    assert!(outcome.delivered.is_empty());
    assert!(outcome.stopped_early);
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 1);
    assert_eq!(journal.cursor(STREAM).last_acked_sequence, 0);
    assert_eq!(journal.pending_for_reconnect(STREAM).len(), 1);
    Ok(())
}
