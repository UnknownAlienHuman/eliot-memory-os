use eliot_process::{
    DurableStreamRepresentation, PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION, ProcessStreamEvidence,
    ProcessStreamKind, StreamPreviewRepresentation,
};

#[test]
fn durable_stream_contract_is_available_from_the_package_root() {
    let _schema = schemars::schema_for!(ProcessStreamEvidence);
    assert_eq!(
        PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION,
        "eliot-process-stream-evidence-v1"
    );
    assert_eq!(ProcessStreamKind::Stdout, ProcessStreamKind::Stdout);
    assert_eq!(
        StreamPreviewRepresentation::DurableSourceBytes,
        StreamPreviewRepresentation::DurableSourceBytes
    );
    assert_eq!(
        DurableStreamRepresentation::PolicyTransformed,
        DurableStreamRepresentation::PolicyTransformed
    );
}
