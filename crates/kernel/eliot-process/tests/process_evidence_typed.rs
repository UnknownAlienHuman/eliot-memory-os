use eliot_contracts::sha256_hex;
use eliot_instrument_api::EvidenceAxes;
use eliot_process::{
    DurableProcessStreamSource, DurableStreamLocatorKind, PROCESS_EVIDENCE_SCHEMA_VERSION,
    ProcessEvidence, ProcessExecutionBinding, ProcessExecutionView, ProcessStreamEvidence,
    ProcessStreamKind, ProcessStreamPolicyBinding, ProcessStreamPrefixPreview,
    StreamPersistenceStatus, StreamTransportStatus,
};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn binding(operation_id: &str) -> TestResult<ProcessExecutionBinding> {
    Ok(serde_json::from_value(json!({
        "operation_id": operation_id,
        "process_tree_id": "tree-1",
        "job_id": "job-1",
        "image_id": "image-1",
        "session_id": "session-1",
        "generation": 3,
        "action_lease_ref": "lease-1",
        "authority_id": "authority-1",
        "authority_epoch": 7,
        "state_fence": {
            "authority_epoch": 7,
            "generation": 3,
            "nonce": "fence-1"
        },
        "request_digest": "a".repeat(64),
        "permit_digest": "b".repeat(64),
        "effect_digest": "c".repeat(64),
        "validation_revision": 2
    }))?)
}

fn view(binding: &ProcessExecutionBinding) -> TestResult<ProcessExecutionView> {
    Ok(serde_json::from_value(json!({
        "binding": serde_json::to_value(binding)?,
        "lifecycle": "running",
        "health": {
            "status": "healthy",
            "ready": true,
            "observed_at_unix_ms": 10,
            "detail": null
        },
        "cancellation": "not_requested",
        "identity": null,
        "exit": null,
        "descendants": null
    }))?)
}

fn policy() -> TestResult<ProcessStreamPolicyBinding> {
    Ok(ProcessStreamPolicyBinding::new(
        "policy:1",
        "privacy:project",
        "visibility:owner",
        "retention:task",
        "redaction:exact-v1",
    )?)
}

fn stream(
    binding: ProcessExecutionBinding,
    kind: ProcessStreamKind,
) -> TestResult<ProcessStreamEvidence> {
    let bytes = b"output";
    let digest = sha256_hex(bytes);
    Ok(ProcessStreamEvidence::new_raw(
        binding,
        kind,
        policy()?,
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::CompleteSource,
        digest.clone(),
        bytes.len() as u64,
        ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), bytes.len() as u64)?,
        Some(DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            format!("eliot://blob/{digest}"),
            format!("receipt:blob-ready:{digest}"),
            digest,
            bytes.len() as u64,
        )?),
        Vec::new(),
    )?)
}

fn legacy_wire(
    view: &ProcessExecutionView,
    stdout_ref: &Value,
    stderr_ref: &Value,
) -> TestResult<Value> {
    Ok(json!({
        "view": serde_json::to_value(view)?,
        "stdout_ref": stdout_ref,
        "stderr_ref": stderr_ref,
        "axes": serde_json::to_value(EvidenceAxes::observed())?
    }))
}

#[test]
fn typed_stdout_and_stderr_round_trip_without_legacy_fields() -> TestResult {
    let binding = binding("operation-1")?;
    let evidence = ProcessEvidence::new_typed(
        view(&binding)?,
        Some(stream(binding.clone(), ProcessStreamKind::Stdout)?),
        Some(stream(binding, ProcessStreamKind::Stderr)?),
        EvidenceAxes::observed(),
    )?;
    let wire = serde_json::to_value(&evidence)?;
    assert_eq!(wire["schema_version"], PROCESS_EVIDENCE_SCHEMA_VERSION);
    assert!(wire.get("stdout").is_some());
    assert!(wire.get("stderr").is_some());
    assert!(wire.get("stdout_ref").is_none());
    assert!(wire.get("stderr_ref").is_none());
    assert_eq!(serde_json::from_value::<ProcessEvidence>(wire)?, evidence);
    Ok(())
}

#[test]
fn typed_stream_identity_and_version_are_strict() -> TestResult {
    let initial_binding = binding("operation-1")?;
    let evidence = ProcessEvidence::new_typed(
        view(&initial_binding)?,
        Some(stream(initial_binding, ProcessStreamKind::Stdout)?),
        None,
        EvidenceAxes::observed(),
    )?;

    let mut unknown_version = serde_json::to_value(&evidence)?;
    unknown_version["schema_version"] = json!("eliot-process-evidence-v99");
    assert!(serde_json::from_value::<ProcessEvidence>(unknown_version).is_err());

    let mut missing_version = serde_json::to_value(&evidence)?;
    missing_version
        .as_object_mut()
        .ok_or("expected object")?
        .remove("schema_version");
    assert!(serde_json::from_value::<ProcessEvidence>(missing_version).is_err());

    let mut unknown_field = serde_json::to_value(evidence)?;
    unknown_field["unexpected"] = json!(true);
    assert!(serde_json::from_value::<ProcessEvidence>(unknown_field).is_err());

    let invalid_view_binding = binding("operation-2")?;
    let empty = ProcessEvidence::new_typed(
        view(&invalid_view_binding)?,
        None,
        None,
        EvidenceAxes::observed(),
    )?;
    let mut invalid_binding = serde_json::to_value(empty)?;
    invalid_binding["view"]["binding"]["authority_epoch"] = json!(0);
    assert!(serde_json::from_value::<ProcessEvidence>(invalid_binding).is_err());

    let null_schema_binding = crate::binding("operation-3")?;
    let mut null_schema = serde_json::to_value(ProcessEvidence::new_typed(
        view(&null_schema_binding)?,
        None,
        None,
        EvidenceAxes::observed(),
    )?)?;
    null_schema["schema_version"] = Value::Null;
    assert!(serde_json::from_value::<ProcessEvidence>(null_schema).is_err());
    Ok(())
}

#[test]
fn typed_stream_binding_and_kind_mismatches_fail_closed() -> TestResult {
    let expected = binding("operation-1")?;
    let wrong_binding = binding("operation-2")?;
    assert!(
        ProcessEvidence::new_typed(
            view(&expected)?,
            Some(stream(wrong_binding, ProcessStreamKind::Stdout)?),
            None,
            EvidenceAxes::observed(),
        )
        .is_err()
    );
    assert!(
        ProcessEvidence::new_typed(
            view(&expected)?,
            Some(stream(expected, ProcessStreamKind::Stderr)?),
            None,
            EvidenceAxes::observed(),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn legacy_raw_references_are_quarantined_as_unresolved_source_unavailable() -> TestResult {
    let binding = binding("operation-1")?;
    let view = view(&binding)?;
    let legacy = legacy_wire(
        &view,
        &json!(format!(
            "raw:p04-stream:sha256:{}:bytes:7:complete:true",
            "a".repeat(64)
        )),
        &Value::Null,
    )?;
    let evidence: ProcessEvidence = serde_json::from_value(legacy)?;
    let stdout = evidence.stdout().ok_or("missing quarantined stdout")?;
    assert_eq!(
        stdout.legacy_reference(),
        Some(
            "raw:p04-stream:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bytes:7:complete:true"
        )
    );
    assert_eq!(
        stdout.persistence(),
        StreamPersistenceStatus::SourceUnavailable
    );
    assert_eq!(stdout.source(), None);
    assert_eq!(stdout.observed_bytes(), 7);
    assert_eq!(evidence.stdout_ref(), stdout.legacy_reference());

    let reencoded = serde_json::to_value(evidence)?;
    assert!(reencoded.get("stdout_ref").is_none());
    assert_eq!(
        reencoded["stdout"]["persistence"],
        json!("SOURCE_UNAVAILABLE")
    );
    Ok(())
}

#[test]
fn malformed_legacy_references_and_completion_forgery_fail_closed() -> TestResult {
    let binding = binding("operation-1")?;
    let view = view(&binding)?;
    let malformed = legacy_wire(&view, &json!("raw:p04-stream:malformed"), &Value::Null)?;
    assert!(serde_json::from_value::<ProcessEvidence>(malformed).is_err());

    let legacy = legacy_wire(
        &view,
        &json!(format!(
            "raw:p04-stream:sha256:{}:bytes:0:complete:true",
            sha256_hex(&[])
        )),
        &Value::Null,
    )?;
    let evidence: ProcessEvidence = serde_json::from_value(legacy)?;
    let mut forged = serde_json::to_value(evidence)?;
    forged["stdout"]["persistence"] = json!("COMPLETE_SOURCE");
    assert!(serde_json::from_value::<ProcessEvidence>(forged).is_err());
    Ok(())
}

#[test]
fn typed_zero_byte_stream_remains_a_valid_complete_source() -> TestResult {
    let binding = binding("operation-1")?;
    let digest = sha256_hex(&[]);
    let empty = ProcessStreamEvidence::new_raw(
        binding.clone(),
        ProcessStreamKind::Stderr,
        policy()?,
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::CompleteSource,
        digest.clone(),
        0,
        ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
        Some(DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            format!("eliot://blob/{digest}"),
            format!("receipt:blob-ready:{digest}"),
            digest,
            0,
        )?),
        Vec::new(),
    )?;
    let evidence =
        ProcessEvidence::new_typed(view(&binding)?, None, Some(empty), EvidenceAxes::observed())?;
    assert_eq!(
        evidence.stderr().ok_or("missing stderr")?.observed_bytes(),
        0
    );
    assert_eq!(
        evidence.stderr().ok_or("missing stderr")?.persistence(),
        StreamPersistenceStatus::CompleteSource
    );
    Ok(())
}
