use eliot_process::{
    DurableStreamRepresentation, PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION, ProcessStreamEvidence,
    ProcessStreamKind, StreamPreviewRepresentation,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn durable_stream_contract_is_available_from_the_package_root() -> TestResult {
    let schema = schemars::schema_for!(ProcessStreamEvidence);
    assert!(!serde_json::to_vec(&schema)?.is_empty());
    assert_eq!(
        PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION,
        "eliot-process-stream-evidence-v1"
    );
    assert_eq!(
        serde_json::to_value(ProcessStreamKind::Stdout)?,
        serde_json::json!("STDOUT")
    );
    assert_eq!(
        serde_json::to_value(StreamPreviewRepresentation::DurableSourceBytes)?,
        serde_json::json!("DURABLE_SOURCE_BYTES")
    );
    assert_eq!(
        serde_json::to_value(DurableStreamRepresentation::PolicyTransformed)?,
        serde_json::json!("POLICY_TRANSFORMED")
    );
    Ok(())
}
