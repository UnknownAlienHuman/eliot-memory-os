//! Durable host-event ingest proof for issue #1934 (I7.23).
//!
//! One stream exercises the full acceptance shape: an allowed payload, a
//! redacted payload, an interrupted ingest, and a duplicate replay. Every
//! accepted event links its immutable transport hash to its raw-or-redacted
//! record, normalized envelope, and disposition before the cursor advances.

use eliot_agent_acp::{
    AcpHostEventInput, DurableHostEventJournal, EventKey, IngestError, RedactionReason,
    StageAllowed, StageRedacted, contains_forbidden_content, deterministic_redacted_bytes,
    normalize_acp_event,
};
use eliot_agent_api::{
    ClockReading, EventCursor, EventId, HostEventDeliveryDisposition, HostEventPrivacyClass,
    NativeSession, NativeSessionLocator, NormalizationCoverage, NormalizedHostEventEnvelope,
    NormalizedHostEventPayload, ProviderObservationLineage, RestrictedRawSourceHandle,
    SessionLifecycleObservation, SessionLifecycleTransition, SessionObservation,
};
use eliot_contracts::sha256_hex;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const STREAM: &str = "host-events:editor-1934";

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
            native: NativeSession::Native(NativeSessionLocator::new("thread-1934")?),
        },
    ))
}

fn normalize(
    event: &str,
    cursor: &str,
    sequence: u64,
    source_bytes: &[u8],
    handle: &str,
    transition: SessionLifecycleTransition,
    privacy: HostEventPrivacyClass,
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
            transition,
            detail_ref: None,
        }),
        omitted_source_fields: Vec::new(),
        warnings: Vec::new(),
        privacy_class: privacy,
        coverage: NormalizationCoverage::Complete,
        observed_at: observed_at(),
        delivery: HostEventDeliveryDisposition::DurableOrdered,
        admission: None,
    })?;
    assert_eq!(envelope.normalization, receipt);
    Ok(envelope)
}

#[test]
fn durable_ingest_orders_raw_hash_envelope_disposition_before_cursor() -> TestResult {
    let mut journal = DurableHostEventJournal::new();

    // Allowed payload: benign transport bytes persist verbatim.
    let raw_allowed = b"acp-frame-1934-benign-session-start".to_vec();
    assert!(!contains_forbidden_content(&raw_allowed));
    let envelope_allowed = normalize(
        "evt-1934-1",
        "cursor-1934-1",
        1,
        &raw_allowed,
        "restricted-source:1934-1",
        SessionLifecycleTransition::Started,
        HostEventPrivacyClass::PublicSummary,
    )?;
    let outcome = journal.stage_allowed(StageAllowed {
        stream_id: STREAM,
        stream_sequence: 1,
        transport_bytes: &raw_allowed,
        envelope: envelope_allowed,
        requested_route_digest: None,
        actual_route_digest: None,
        predecessors: Vec::new(),
        warnings: Vec::new(),
        transformation_version: eliot_agent_acp::DURABLE_INGEST_TRANSFORMATION_VERSION,
    })?;
    assert!(outcome.fresh);
    // Staging alone never advances the cursor: the durable relation commits first.
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 0);
    journal.commit(&outcome.key)?;
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 1);
    let record = journal
        .get(&outcome.key)
        .ok_or("allowed record must be stored")?;
    assert_eq!(record.transport_hash.as_str(), sha256_hex(&raw_allowed));
    assert_eq!(record.stored.bytes(), raw_allowed.as_slice());
    assert!(record.stored.redaction_receipt().is_none());
    assert_eq!(record.envelope_digest, record.envelope.compute_digest()?);
    assert!(record.disposition.committed);
    assert_eq!(record.envelope.sequence, 1);
    journal.acknowledge(STREAM, 1)?;

    // Privacy is fail-closed: denied content cannot persist as admissible raw.
    let raw_secret = b"acp-frame-1934-tool-result secret-value-hidden_reasoning".to_vec();
    assert!(contains_forbidden_content(&raw_secret));
    let denied_envelope = normalize(
        "evt-1934-2",
        "cursor-1934-2",
        2,
        &raw_secret,
        "restricted-source:1934-2",
        SessionLifecycleTransition::Resumed,
        HostEventPrivacyClass::RedactedSummary,
    )?;
    assert_eq!(
        journal.stage_allowed(StageAllowed {
            stream_id: STREAM,
            stream_sequence: 2,
            transport_bytes: &raw_secret,
            envelope: denied_envelope,
            requested_route_digest: None,
            actual_route_digest: None,
            predecessors: Vec::new(),
            warnings: Vec::new(),
            transformation_version: eliot_agent_acp::DURABLE_INGEST_TRANSFORMATION_VERSION,
        }),
        Err(IngestError::PrivacyViolation)
    );

    // Redacted payload: only the deterministic projection plus receipt persist.
    let classes = vec!["secret".to_owned(), "scope".to_owned()];
    let projection = deterministic_redacted_bytes(&sha256_hex(&raw_secret), &["scope", "secret"]);
    let envelope_redacted = normalize(
        "evt-1934-2",
        "cursor-1934-2",
        2,
        &projection,
        "restricted-source:1934-redacted-2",
        SessionLifecycleTransition::Resumed,
        HostEventPrivacyClass::RedactedSummary,
    )?;
    let outcome = journal.stage_redacted(StageRedacted {
        stream_id: STREAM,
        stream_sequence: 2,
        transport_bytes: &raw_secret,
        redacted_classes: classes,
        envelope: envelope_redacted,
        requested_route_digest: None,
        actual_route_digest: None,
        predecessors: Vec::new(),
        warnings: Vec::new(),
        transformation_version: eliot_agent_acp::DURABLE_INGEST_TRANSFORMATION_VERSION,
    })?;
    assert!(outcome.fresh);
    journal.commit(&outcome.key)?;
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 2);
    let record = journal
        .get(&outcome.key)
        .ok_or("redacted record must be stored")?;
    assert_eq!(record.transport_hash.as_str(), sha256_hex(&raw_secret));
    assert_eq!(record.stored.bytes(), projection.as_slice());
    assert!(
        !record
            .stored
            .bytes()
            .windows(12)
            .any(|window| window == b"secret-value")
    );
    let receipt = record
        .stored
        .redaction_receipt()
        .ok_or("redacted record must expose a receipt")?;
    assert_eq!(receipt.reason, RedactionReason::ForbiddenContentDetected);
    assert_eq!(receipt.transport_hash.as_str(), sha256_hex(&raw_secret));
    assert_eq!(record.envelope_digest, record.envelope.compute_digest()?);

    // Interrupted ingest: staged but never committed; cursor stays behind.
    let raw_pending = b"acp-frame-1934-benign-suspended".to_vec();
    let envelope_pending = normalize(
        "evt-1934-3",
        "cursor-1934-3",
        3,
        &raw_pending,
        "restricted-source:1934-3",
        SessionLifecycleTransition::Suspended,
        HostEventPrivacyClass::PublicSummary,
    )?;
    let staged = journal.stage_allowed(StageAllowed {
        stream_id: STREAM,
        stream_sequence: 3,
        transport_bytes: &raw_pending,
        envelope: envelope_pending,
        requested_route_digest: None,
        actual_route_digest: None,
        predecessors: Vec::new(),
        warnings: Vec::new(),
        transformation_version: eliot_agent_acp::DURABLE_INGEST_TRANSFORMATION_VERSION,
    })?;
    assert!(staged.fresh);
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 2);

    // Reconnect replays the unacknowledged event (staged, uncommitted).
    let pending = journal.pending_for_reconnect(STREAM);
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].sequence, 2);
    assert!(pending[0].committed);
    assert_eq!(pending[1].sequence, 3);
    assert!(!pending[1].committed);
    journal.acknowledge(STREAM, 2)?;

    // Commit recovery advances the cursor; application happens exactly once.
    journal.commit(&staged.key)?;
    assert_eq!(journal.cursor(STREAM).last_durable_sequence, 3);
    assert!(journal.record_application(&staged.key)?);
    assert!(!journal.record_application(&staged.key)?);
    let record = journal
        .get(&staged.key)
        .ok_or("recovered record must be stored")?;
    assert_eq!(record.disposition.applied_count, 1);
    journal.acknowledge(STREAM, 3)?;
    assert!(journal.pending_for_reconnect(STREAM).is_empty());

    // Duplicate replay of the first event: no second record, no second apply.
    let envelope_replay = normalize(
        "evt-1934-1",
        "cursor-1934-1",
        1,
        &raw_allowed,
        "restricted-source:1934-1",
        SessionLifecycleTransition::Started,
        HostEventPrivacyClass::PublicSummary,
    )?;
    let replay = journal.stage_allowed(StageAllowed {
        stream_id: STREAM,
        stream_sequence: 1,
        transport_bytes: &raw_allowed,
        envelope: envelope_replay,
        requested_route_digest: None,
        actual_route_digest: None,
        predecessors: Vec::new(),
        warnings: Vec::new(),
        transformation_version: eliot_agent_acp::DURABLE_INGEST_TRANSFORMATION_VERSION,
    })?;
    assert!(!replay.fresh);
    assert_eq!(
        replay.key,
        EventKey {
            stream_id: STREAM.to_owned(),
            sequence: 1
        }
    );
    assert_eq!(journal.record_count(), 3);
    assert!(journal.record_application(&replay.key)?);
    assert!(!journal.record_application(&replay.key)?);

    // Conflicting same-cursor delivery with different bytes is quarantined.
    let conflicting = normalize(
        "evt-1934-1",
        "cursor-1934-1",
        1,
        b"acp-frame-1934-tampered",
        "restricted-source:1934-1",
        SessionLifecycleTransition::Started,
        HostEventPrivacyClass::PublicSummary,
    )?;
    assert_eq!(
        journal.stage_allowed(StageAllowed {
            stream_id: STREAM,
            stream_sequence: 1,
            transport_bytes: b"acp-frame-1934-tampered",
            envelope: conflicting,
            requested_route_digest: None,
            actual_route_digest: None,
            predecessors: Vec::new(),
            warnings: Vec::new(),
            transformation_version: eliot_agent_acp::DURABLE_INGEST_TRANSFORMATION_VERSION,
        }),
        Err(IngestError::ConflictingDuplicate)
    );
    assert_eq!(journal.record_count(), 3);
    Ok(())
}
