//! Bounded unsafe-family boundaries for work unit 791.
//!
//! Scope is the `eliot-ipc` transport boundary only:
//! `crates/kernel/eliot-ipc/src/lib.rs` (12 `#[cfg(windows)]` unsafe tokens in
//! 4 families: SDDL conversion x2, `LocalFree` x3, Tokio
//! `SECURITY_ATTRIBUTES` handoff x2, `borrow_raw` x5) plus the coupled
//! `src/frame_codec.rs` buffer/length/partial-I/O invariants (zero unsafe
//! tokens; oversize-before-alloc, exact `4 + declared` range, one-over
//! `Backpressure`, distinct terminals).
//!
//! Every test below calls the real public `eliot-ipc` API: no mocks, no
//! pointer forging, no `unsafe` in this file. Invalid, overlong,
//! traversal-equivalent, NUL/control, oversize, partial, zero-length, and
//! trailing inputs must fail closed before any raw Windows pointer is formed
//! or any body-sized allocation is admitted. The single valid roundtrip
//! exercises the real `encode_frame` / `FrameDecoder::push` / `decode_frame`
//! path without creating pipes, threads, or credentials.
//!
//! Deferred residuals (not implemented in this bounded wave, listed in the
//! fixture and the PR body): live-OS SDDL conversion success allocation,
//! `LocalFree` exact-once Drop live proof, Tokio DACL-copy retention, borrowed
//! handle `.await` interleaving, cancellation/timeout/unknown-outcome racing,
//! late/duplicate completion, `Send`/`Sync`/thread-affinity witnesses,
//! callback/FFI unwind, migration-destination evidence, and the remaining
//! 22-case matrix rows.

use eliot_ipc::{
    AdmissionQueue, FrameDecoder, TransportError, TransportLimits, decode_frame, encode_frame,
    is_control_capacity_frame, validate_pipe_name,
};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolError, ProtocolPayload, ProtocolVersion,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => panic!("unexpected success: {value:?}"),
        Err(error) => error,
    }
}

fn test_limits(max_frame_bytes: usize) -> TransportLimits {
    TransportLimits {
        max_frame_bytes,
        queue_capacity: 4,
        queue_bytes: 8192,
        control_reserve: 1,
        operation_timeout: Duration::from_secs(1),
    }
}

fn heartbeat_frame() -> Frame {
    Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: "connection".to_owned(),
        request_id: None,
        kind: FrameKind::Heartbeat,
        message_type: MessageType::Health,
        request_identity: None,
        payload: ProtocolPayload::Json(serde_json::Value::Null),
        trace_context: BTreeMap::new(),
    }
}

fn fixture_text() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/unsafe_family_cases.json");
    ok(std::fs::read_to_string(&path))
}

// WORK_UNIT_CASE: 791/1
#[test]
fn pipe_name_boundaries_fail_closed_before_raw_handoff() {
    ok(validate_pipe_name(r"\\.\pipe\eliot\kernel\frontdoor"));
    let edge_path: String = "a".repeat(240);
    let edge_name = format!(r"\\.\pipe\eliot\{edge_path}");
    ok(validate_pipe_name(edge_name.as_str()));
    let over_path: String = "a".repeat(241);
    let over_name = format!(r"\\.\pipe\eliot\{over_path}");
    assert_eq!(
        validate_pipe_name(over_name.as_str()),
        Err(TransportError::InvalidPipeName)
    );
    for invalid in [
        r"\\.\pipe\other\kernel",
        r"\\.\pipe\eliot\",
        r"\\.\pipe\eliot\..\other",
        r"\\.\pipe\eliot\kernel\..",
        r"\\.\pipe\eliot\kernel\.",
        r"\\.\pipe\eliot\a\\b",
        r"\\.\pipe\eliot\kernel/other",
        r"\\.\pipe\eliot\kernel:tag",
    ] {
        assert_eq!(
            validate_pipe_name(invalid),
            Err(TransportError::InvalidPipeName),
            "pipe name must fail closed for {invalid:?}"
        );
    }
    let with_nul = "\\\\.\\pipe\\eliot\\kernel\0test";
    assert_eq!(
        validate_pipe_name(with_nul),
        Err(TransportError::InvalidPipeName)
    );
    let with_control = "\\\\.\\pipe\\eliot\\kernel\n";
    assert_eq!(
        validate_pipe_name(with_control),
        Err(TransportError::InvalidPipeName)
    );
}

// WORK_UNIT_CASE: 791/2
#[test]
fn partial_prefix_then_completion_uses_exact_transferred_length() {
    let limits = test_limits(2048);
    let frame = heartbeat_frame();
    let wire = ok(encode_frame(&frame, limits));
    assert!(!wire.is_empty(), "heartbeat must encode to bytes");
    let mut decoder = FrameDecoder::new();
    assert_eq!(decoder.push(&[], limits), Ok(None));
    let split = wire.len() / 2;
    assert!(split > 4, "split must keep both halves non-trivial");
    assert_eq!(decoder.push(&wire[..split], limits), Ok(None));
    assert_eq!(decoder.push(&wire[split..], limits), Ok(Some(frame)));
}

// WORK_UNIT_CASE: 791/3
#[test]
fn one_over_trailing_is_backpressure_never_truncation() {
    let limits = test_limits(2048);
    let frame = heartbeat_frame();
    let wire = ok(encode_frame(&frame, limits));
    let mut decoder = FrameDecoder::new();
    assert_eq!(decoder.push(&wire, limits), Ok(Some(frame.clone())));
    let mut trailing = wire.clone();
    trailing.push(0);
    let mut over_decoder = FrameDecoder::new();
    assert_eq!(
        over_decoder.push(&trailing, limits),
        Err(TransportError::Backpressure)
    );
    assert!(matches!(
        decode_frame(&trailing, limits),
        Err(TransportError::Protocol(ProtocolError::TrailingBytes))
    ));
}

// WORK_UNIT_CASE: 791/4
#[test]
fn zero_empty_oversize_stay_distinct_and_oversize_clears_for_resync() {
    let limits = test_limits(2048);
    assert!(matches!(
        decode_frame(&[0, 0, 0, 0], limits),
        Err(TransportError::Protocol(ProtocolError::ZeroLengthFrame))
    ));
    let mut decoder = FrameDecoder::new();
    assert_eq!(decoder.push(&[], limits), Ok(None));
    let mut oversized_prefix = 4096_u32.to_le_bytes().to_vec();
    oversized_prefix.extend_from_slice(&[0_u8; 10]);
    assert!(matches!(
        decoder.push(&oversized_prefix, limits),
        Err(TransportError::Protocol(ProtocolError::OversizeFrame { .. }))
    ));
    let frame = heartbeat_frame();
    let wire = ok(encode_frame(&frame, limits));
    assert_eq!(decoder.push(&wire, limits), Ok(Some(frame)));
}

// WORK_UNIT_CASE: 791/5
#[test]
fn bounded_malformed_input_never_panics_nor_reports_full_success() {
    let limits = test_limits(2048);
    let malformed: [&[u8]; 6] = [
        &[],
        &[1, 0],
        &[0, 0, 0, 0],
        &[5, 0, 0, 0, b'{'],
        &[255, 255, 255, 255],
        &[65, 0, 0, 0],
    ];
    for wire in malformed {
        let one_shot = decode_frame(wire, limits);
        assert!(one_shot.is_err(), "malformed must fail closed for {wire:?}");
        let mut incremental = FrameDecoder::new();
        if let Ok(Some(frame)) = incremental.push(wire, limits) {
            panic!("malformed must never decode: {frame:?}");
        }
    }
    let oversized_max = eliot_protocol::MAX_FRAME_BYTES + 1;
    let bad_limits = [
        TransportLimits {
            max_frame_bytes: 0,
            queue_capacity: 4,
            queue_bytes: 256,
            control_reserve: 1,
            operation_timeout: Duration::from_secs(1),
        },
        TransportLimits {
            max_frame_bytes: oversized_max,
            queue_capacity: 4,
            queue_bytes: oversized_max,
            control_reserve: 1,
            operation_timeout: Duration::from_secs(1),
        },
        TransportLimits {
            max_frame_bytes: 2048,
            queue_capacity: 4,
            queue_bytes: 512,
            control_reserve: 1,
            operation_timeout: Duration::from_secs(1),
        },
        TransportLimits {
            max_frame_bytes: 2048,
            queue_capacity: 4,
            queue_bytes: 8192,
            control_reserve: 1,
            operation_timeout: Duration::ZERO,
        },
    ];
    for invalid in bad_limits {
        let frame = heartbeat_frame();
        assert_eq!(
            encode_frame(&frame, invalid),
            Err(TransportError::InvalidLimits)
        );
        assert!(matches!(
            decode_frame(&[0, 0, 0, 0], invalid),
            Err(TransportError::InvalidLimits)
        ));
    }
    let invalid_empty = err(validate_pipe_name(""));
    assert_eq!(invalid_empty, TransportError::InvalidPipeName);
}

// WORK_UNIT_CASE: 1881/1
#[test]
fn in_flight_saturation_preserves_cancel_heartbeat_control_capacity() {
    let limits = TransportLimits {
        max_frame_bytes: 2048,
        queue_capacity: 4,
        queue_bytes: 8192,
        control_reserve: 1,
        operation_timeout: Duration::from_secs(1),
    };
    let mut queue = ok(AdmissionQueue::new(limits));
    let mut request = heartbeat_frame();
    request.kind = FrameKind::Request;
    request.message_type = MessageType::Execute;
    assert!(!is_control_capacity_frame(&request));
    let held = [
        ok(queue.admit_frame(&request, 8)),
        ok(queue.admit_frame(&request, 8)),
        ok(queue.admit_frame(&request, 8)),
    ];
    assert!(
        matches!(
            queue.admit_frame(&request, 8),
            Err(TransportError::Backpressure)
        ),
        "ordinary request must reject once normal in-flight capacity is exhausted"
    );
    for (kind, message_type) in [
        (FrameKind::Cancel, MessageType::Cancel),
        (FrameKind::Heartbeat, MessageType::Health),
        (FrameKind::Control, MessageType::Challenge),
    ] {
        let mut recovery = heartbeat_frame();
        recovery.kind = kind;
        recovery.message_type = message_type;
        assert!(
            is_control_capacity_frame(&recovery),
            "recovery lane must classify {kind:?}"
        );
        let reservation = ok(queue.admit_frame(&recovery, 8));
        ok(queue.release(reservation));
    }
    for reservation in held {
        ok(queue.release(reservation));
    }
    assert_eq!(queue.usage(), (0, 0));

    // Byte saturation (issue #1881): fill the ordinary byte budget with
    // ordinary traffic while item slots remain, then prove the reserved
    // control lane still admits a Cancel, heartbeat, and recovery frame.
    let byte_limits = TransportLimits {
        max_frame_bytes: 512,
        queue_capacity: 8,
        queue_bytes: 1024,
        control_reserve: 2,
        operation_timeout: Duration::from_secs(1),
    };
    // Proportional byte reserve: 1024 * 2 / 8 = 256 bytes stay reserved for
    // the control lane, so ordinary traffic saturates at 768 bytes with only
    // 3 of 8 item slots consumed.
    let mut bytes_queue = ok(AdmissionQueue::new(byte_limits));
    let held_bytes = [
        ok(bytes_queue.admit_frame(&request, 256)),
        ok(bytes_queue.admit_frame(&request, 256)),
        ok(bytes_queue.admit_frame(&request, 256)),
    ];
    assert_eq!(bytes_queue.usage(), (3, 768));
    assert!(
        matches!(
            bytes_queue.admit_frame(&request, 256),
            Err(TransportError::Backpressure)
        ),
        "ordinary traffic must reject once the normal byte budget is exhausted even though item slots remain"
    );
    for (kind, message_type) in [
        (FrameKind::Cancel, MessageType::Cancel),
        (FrameKind::Heartbeat, MessageType::Health),
        (FrameKind::Control, MessageType::Challenge),
    ] {
        let mut recovery = heartbeat_frame();
        recovery.kind = kind;
        recovery.message_type = message_type;
        assert!(is_control_capacity_frame(&recovery));
        let reservation = ok(bytes_queue.admit_frame(&recovery, 8));
        ok(bytes_queue.release(reservation));
    }
    for reservation in held_bytes {
        ok(bytes_queue.release(reservation));
    }
    assert_eq!(bytes_queue.usage(), (0, 0));
}

// WORK_UNIT_CASE: 1881/2
#[test]
fn inline_ceilings_reject_before_emit_and_prefix_rejects_before_alloc() {
    let limits = TransportLimits::default();
    assert_eq!(
        limits.max_frame_bytes,
        eliot_protocol::MAX_FRAME_BYTES,
        "default frame maximum must be 4 MiB"
    );
    assert_eq!(eliot_protocol::MAX_FRAME_BYTES, 4 * 1024 * 1024);
    assert_eq!(eliot_protocol::HOT_RESPONSE_BYTES, 64 * 1024);
    assert_eq!(eliot_protocol::HARD_STRUCTURED_RESPONSE_BYTES, 256 * 1024);

    let mut big_response = heartbeat_frame();
    big_response.kind = FrameKind::Response;
    big_response.message_type = MessageType::Result;
    big_response.payload =
        ProtocolPayload::Json(serde_json::json!({"blob": "x".repeat(257 * 1024)}));
    assert!(matches!(
        encode_frame(&big_response, limits),
        Err(TransportError::Protocol(ProtocolError::OversizeFrame {
            maximum,
            ..
        })) if maximum == 256 * 1024
    ));

    let mut hot = heartbeat_frame();
    hot.kind = FrameKind::Control;
    hot.message_type = MessageType::Challenge;
    hot.payload = ProtocolPayload::Json(serde_json::json!({"blob": "x".repeat(65 * 1024)}));
    assert!(matches!(
        encode_frame(&hot, limits),
        Err(TransportError::Protocol(ProtocolError::OversizeFrame {
            maximum,
            ..
        })) if maximum == 64 * 1024
    ));

    assert!(matches!(
        decode_frame(&[0, 0, 0, 0], limits),
        Err(TransportError::Protocol(ProtocolError::ZeroLengthFrame))
    ));
    let mut decoder = FrameDecoder::new();
    let over_4mib = ok(u32::try_from(eliot_protocol::MAX_FRAME_BYTES + 1));
    let mut prefix = over_4mib.to_le_bytes().to_vec();
    prefix.extend_from_slice(&[0_u8; 10]);
    assert!(matches!(
        decoder.push(&prefix, limits),
        Err(TransportError::Protocol(ProtocolError::OversizeFrame { .. }))
    ));
    let frame = heartbeat_frame();
    let wire = ok(encode_frame(&frame, limits));
    assert_eq!(decoder.push(&wire, limits), Ok(Some(frame)));
}

// WORK_UNIT_CASE: 1881/2 (receive-path tier enforcement)
#[test]
fn tier_ceilings_reject_from_prefix_before_decode() {
    // The 256 KiB structured and 64 KiB hot-response ceilings reject from
    // the length prefix before the body is decoded, with the 4 MiB codec
    // cap as the outer bound. These wires are hand-framed because
    // `encode_frame` already refuses to emit them.
    let limits = TransportLimits::default();
    let wire_for = |kind: FrameKind, message_type: MessageType, payload: serde_json::Value| {
        let mut frame = heartbeat_frame();
        frame.kind = kind;
        frame.message_type = message_type;
        frame.payload = ProtocolPayload::Json(payload);
        let body = ok(serde_json::to_vec(&frame));
        let mut wire = ok(u32::try_from(body.len())).to_le_bytes().to_vec();
        wire.extend_from_slice(&body);
        wire
    };
    let mut decoder = FrameDecoder::new();
    let big_response_wire = wire_for(
        FrameKind::Response,
        MessageType::Result,
        serde_json::json!({"blob": "x".repeat(257 * 1024)}),
    );
    assert!(big_response_wire.len() - 4 < eliot_protocol::MAX_FRAME_BYTES);
    assert!(matches!(
        decode_frame(&big_response_wire, limits),
        Err(TransportError::Protocol(ProtocolError::OversizeFrame {
            maximum,
            ..
        })) if maximum == 256 * 1024
    ));
    assert!(matches!(
        decoder.push(&big_response_wire, limits),
        Err(TransportError::Protocol(ProtocolError::OversizeFrame {
            maximum,
            ..
        })) if maximum == 256 * 1024
    ));
    let big_control_wire = wire_for(
        FrameKind::Control,
        MessageType::Challenge,
        serde_json::json!({"blob": "x".repeat(65 * 1024)}),
    );
    assert!(big_control_wire.len() - 4 < eliot_protocol::MAX_FRAME_BYTES);
    assert!(matches!(
        decode_frame(&big_control_wire, limits),
        Err(TransportError::Protocol(ProtocolError::OversizeFrame {
            maximum,
            ..
        })) if maximum == 64 * 1024
    ));
    assert!(matches!(
        decoder.push(&big_control_wire, limits),
        Err(TransportError::Protocol(ProtocolError::OversizeFrame {
            maximum,
            ..
        })) if maximum == 64 * 1024
    ));
    // Under-tier bodies still decode on receipt: the tier cap must not
    // over-restrict legitimate traffic below its ceiling.
    let small_response_wire = wire_for(
        FrameKind::Response,
        MessageType::Result,
        serde_json::json!({"blob": "x".repeat(200 * 1024)}),
    );
    let accepted = ok(decode_frame(&small_response_wire, limits));
    assert_eq!(accepted.kind, FrameKind::Response);
    assert_eq!(
        decoder.push(&small_response_wire, limits),
        Ok(Some(accepted))
    );
}

// WORK_UNIT_CASE: 791/6
#[test]
fn fixture_binds_sites_and_deferred_families() {
    let fixture = fixture_text();
    for required in [
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        "LocalFree",
        "create_with_security_attributes_raw",
        "borrow_raw",
        "encode_sddl_utf16",
        "validate_pipe_name",
        "FrameDecoder",
        "ZeroLengthFrame",
        "OversizeFrame",
        "Backpressure",
        "TrailingBytes",
    ] {
        assert!(
            fixture.contains(required),
            "fixture must bind unsafe site {required}"
        );
    }
    for deferred in [
        "live-OS",
        "cancellation",
        "Send/Sync",
        "unwind",
        "migration",
    ] {
        assert!(
            fixture.contains(deferred),
            "fixture must list deferred family {deferred}"
        );
    }
    for case in 1..=6 {
        let marker = format!("\"case\": {case}");
        assert!(
            fixture.contains(marker.as_str()),
            "fixture must bind case {case}"
        );
    }
}
