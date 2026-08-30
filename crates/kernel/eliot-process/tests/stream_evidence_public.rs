use eliot_process::{
    DurableProcessStreamSource, DurableStreamRepresentation,
    PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION, ProcessStreamEvidence, ProcessStreamKind,
    ProcessStreamPolicyBinding, ProcessStreamPrefixPreview, ProcessStreamTransformationBinding,
    ProcessStreamTransportPrefixIdentity, StreamByteRange, StreamPreviewRepresentation,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assert_closed_schema<T: schemars::JsonSchema>(type_name: &str) -> TestResult {
    let schema = serde_json::to_value(schemars::schema_for!(T))?;
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&serde_json::json!(false)),
        "{type_name} schema must reject unknown fields"
    );
    Ok(())
}

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
    let prefix = ProcessStreamTransportPrefixIdentity::new("a".repeat(64), 7)?;
    assert_eq!(prefix.byte_length(), 7);
    Ok(())
}

#[test]
fn public_custom_deserialized_schemas_are_closed() -> TestResult {
    assert_closed_schema::<StreamByteRange>("StreamByteRange")?;
    assert_closed_schema::<ProcessStreamPolicyBinding>("ProcessStreamPolicyBinding")?;
    assert_closed_schema::<ProcessStreamPrefixPreview>("ProcessStreamPrefixPreview")?;
    assert_closed_schema::<ProcessStreamTransformationBinding>(
        "ProcessStreamTransformationBinding",
    )?;
    assert_closed_schema::<ProcessStreamTransportPrefixIdentity>(
        "ProcessStreamTransportPrefixIdentity",
    )?;
    assert_closed_schema::<DurableProcessStreamSource>("DurableProcessStreamSource")?;
    assert_closed_schema::<ProcessStreamEvidence>("ProcessStreamEvidence")?;
    Ok(())
}
