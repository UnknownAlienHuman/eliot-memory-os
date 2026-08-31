#![allow(clippy::unwrap_used)]

use eliot_contracts::RequestId;
use eliot_protocol::{ProtocolPayload, ProtocolVersion};
use eliot_store_api::{
    ReadinessReceipt, ReadinessStatus, StoreResponse, StoreWireError, decode_response_frame,
    response_frame,
};

const CONNECTION_ID: &str = "connection-1";

fn readiness_frame(receipt: ReadinessReceipt) -> eliot_protocol::Frame {
    response_frame(
        CONNECTION_ID,
        ProtocolVersion::CURRENT,
        Some(RequestId::new("request-1").unwrap()),
        StoreResponse::Readiness { receipt },
    )
    .unwrap()
}

#[test]
fn response_frame_and_decode_accept_equal_ready_generations() {
    let frame = readiness_frame(ReadinessReceipt::ready("schema-v2".to_owned()));

    let (_, response) =
        decode_response_frame(&frame, CONNECTION_ID, ProtocolVersion::CURRENT).unwrap();

    assert_eq!(
        response,
        StoreResponse::Readiness {
            receipt: ReadinessReceipt::ready("schema-v2".to_owned()),
        }
    );
}

#[test]
fn response_frame_rejects_mismatched_ready_generations() {
    let error = response_frame(
        CONNECTION_ID,
        ProtocolVersion::CURRENT,
        Some(RequestId::new("request-1").unwrap()),
        StoreResponse::Readiness {
            receipt: ReadinessReceipt {
                status: ReadinessStatus::Ready,
                expected_generation: Some("schema-v2".to_owned()),
                observed_generation: Some("schema-v1".to_owned()),
            },
        },
    )
    .unwrap_err();

    assert!(matches!(error, StoreWireError::Invalid(_)));
}

#[test]
fn decode_response_frame_rejects_mismatched_ready_generations() {
    let mut frame = readiness_frame(ReadinessReceipt::ready("schema-v2".to_owned()));
    let ProtocolPayload::Json(payload) = &mut frame.payload else {
        panic!("readiness fixture must use json-v1");
    };
    payload["receipt"]["observed_generation"] = serde_json::json!("schema-v1");

    let error = decode_response_frame(&frame, CONNECTION_ID, ProtocolVersion::CURRENT).unwrap_err();

    assert!(matches!(error, StoreWireError::Invalid(_)));
}

#[test]
fn response_frame_rejects_blank_ready_generation() {
    let error = response_frame(
        CONNECTION_ID,
        ProtocolVersion::CURRENT,
        Some(RequestId::new("request-1").unwrap()),
        StoreResponse::Readiness {
            receipt: ReadinessReceipt::ready("   ".to_owned()),
        },
    )
    .unwrap_err();

    assert!(matches!(error, StoreWireError::Invalid(_)));
}

#[test]
fn decode_response_frame_rejects_blank_ready_generation() {
    let mut frame = readiness_frame(ReadinessReceipt::ready("schema-v2".to_owned()));
    let ProtocolPayload::Json(payload) = &mut frame.payload else {
        panic!("readiness fixture must use json-v1");
    };
    payload["receipt"]["expected_generation"] = serde_json::json!(" ");

    let error = decode_response_frame(&frame, CONNECTION_ID, ProtocolVersion::CURRENT).unwrap_err();

    assert!(matches!(error, StoreWireError::Invalid(_)));
}
