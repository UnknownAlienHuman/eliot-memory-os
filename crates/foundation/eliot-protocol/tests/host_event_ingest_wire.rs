//! Wire proof for durable host-event ingest types (issue #1934, I7.23).
//!
//! Minimal only: a redacted record plus cursor validate and round-trip, while
//! malformed digests, mismatched redaction presence, and acked-past-durable
//! cursors fail closed.

use eliot_protocol::{
    HOST_EVENT_INGEST_RECORD_WIRE_ID, HOST_EVENT_INGEST_RECORD_WIRE_VERSION,
    HOST_EVENT_STREAM_CURSOR_WIRE_ID, HOST_EVENT_STREAM_CURSOR_WIRE_VERSION,
    HostEventIngestDispositionWire, HostEventIngestRecordWire, HostEventRedactionReceiptWire,
    HostEventStreamCursorWire,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(seed: &str) -> String {
    eliot_contracts::sha256_hex(seed.as_bytes())
}

fn receipt() -> HostEventRedactionReceiptWire {
    HostEventRedactionReceiptWire {
        transport_hash: digest("transport-1934"),
        reason: "FORBIDDEN_CONTENT_DETECTED".to_owned(),
        redacted_classes: vec!["scope".to_owned(), "secret".to_owned()],
        marker: "redacted/host-event-v1".to_owned(),
        normalizer_version: "eliot-agent-acp/v1".to_owned(),
    }
}

fn record() -> HostEventIngestRecordWire {
    HostEventIngestRecordWire {
        wire_id: HOST_EVENT_INGEST_RECORD_WIRE_ID.to_owned(),
        wire_version: HOST_EVENT_INGEST_RECORD_WIRE_VERSION,
        stream_id: "host-events:editor-1934".to_owned(),
        sequence: 2,
        transport_hash: digest("transport-1934"),
        stored_digest: digest("stored-1934"),
        envelope_digest: digest("envelope-1934"),
        redacted: true,
        adapter_version: "eliot-agent-acp/v1".to_owned(),
        transformation_version: "eliot-agent-acp/durable-ingest-v1".to_owned(),
        disposition: HostEventIngestDispositionWire::Committed,
        applied_count: 1,
        acked: false,
        redaction: Some(receipt()),
    }
}

#[test]
fn redacted_record_and_cursor_validate_and_round_trip() -> TestResult {
    let wire = record();
    wire.validate()?;
    let json = serde_json::to_string(&wire)?;
    let decoded: HostEventIngestRecordWire = serde_json::from_str(&json)?;
    assert_eq!(decoded, wire);

    let cursor = HostEventStreamCursorWire {
        wire_id: HOST_EVENT_STREAM_CURSOR_WIRE_ID.to_owned(),
        wire_version: HOST_EVENT_STREAM_CURSOR_WIRE_VERSION,
        stream_id: "host-events:editor-1934".to_owned(),
        last_durable_sequence: 2,
        last_acked_sequence: 1,
    };
    cursor.validate()?;
    let json = serde_json::to_string(&cursor)?;
    let decoded: HostEventStreamCursorWire = serde_json::from_str(&json)?;
    assert_eq!(decoded, cursor);
    Ok(())
}

#[test]
fn malformed_ingest_wires_fail_closed() {
    let mut wire = record();
    wire.transport_hash = "not-a-digest".to_owned();
    assert!(wire.validate().is_err());

    let mut wire = record();
    wire.redacted = false;
    assert!(wire.validate().is_err());

    let mut wire = record();
    wire.applied_count = 2;
    assert!(wire.validate().is_err());

    let cursor = HostEventStreamCursorWire {
        wire_id: HOST_EVENT_STREAM_CURSOR_WIRE_ID.to_owned(),
        wire_version: HOST_EVENT_STREAM_CURSOR_WIRE_VERSION,
        stream_id: "host-events:editor-1934".to_owned(),
        last_durable_sequence: 1,
        last_acked_sequence: 2,
    };
    assert!(cursor.validate().is_err());

    let unknown_field = r#"{"wire_id":"eliot.protocol.host-event-stream-cursor","wire_version":1,"stream_id":"s","last_durable_sequence":1,"last_acked_sequence":1,"extra":true}"#;
    assert!(serde_json::from_str::<HostEventStreamCursorWire>(unknown_field).is_err());
}
