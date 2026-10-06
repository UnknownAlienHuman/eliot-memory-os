//! Issue #456 consumer proofs: typed `ProcessStreamEvidence` is consumed only
//! through the injected [`ProcessStreamSourceReadbackPort`].
//!
//! The port below is a test double, not a production adapter: it serves exact
//! bytes per immutable locator and asserts the exact job/attempt binding the
//! composition supplied. The Blob-backed production adapter belongs to #297.
//! Every test drives the real core chain
//! admit -> resolve -> apply_parsing -> apply_evaluation, proving that inline
//! preview bytes and caller-supplied bytes can never satisfy verification.

use eliot_contracts::{ClockReading, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_process::{
    DurableProcessStreamSource, DurableStreamLocatorKind, ProcessEvidence, ProcessExecutionBinding,
    ProcessExecutionView, ProcessStreamEvidence, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamPrefixPreview, StreamEvidenceGap, StreamPersistenceStatus, StreamTransportStatus,
};
use eliot_testd_core::{
    EphemeralSourceBytes, EvidenceCollector, ProcessStreamSourceReadbackObservation,
    ProcessStreamSourceReadbackPort, ProcessStreamSourceReadbackRequest, TestdArtifactBinding,
    TestdEvaluationObservation, TestdEvaluationStatus, TestdEvidenceDisposition,
    TestdEvidenceError, TestdParsingObservation, TestdParsingStatus, TestdProcessEvidenceBundle,
    TestdReadbackContext, TestdStreamDisposition, TestdStreamResolution, sha256_hex,
};
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Mutex;

const JOB_ID: &str = "job";
const INVOCATION_ID: &str = "invocation";
const LOCATOR_STDOUT: &str = "blob:locator-stdout-1";
const LOCATOR_STDERR: &str = "blob:locator-stderr-1";
const RECEIPT_STDOUT: &str = "ready-receipt-stdout-1";
const RECEIPT_STDERR: &str = "ready-receipt-stderr-1";

fn test_epoch(sequence: u64) -> EpochId {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
        .expect("canonical test lineage-A");
    EpochId::new(
        lineage,
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

fn test_fence(sequence: u64) -> StateFence {
    let generation = ResourceGeneration::new(1).expect("non-zero test generation");
    StateFence::new(test_epoch(sequence), generation)
}

fn test_binding() -> ProcessExecutionBinding {
    serde_json::from_value(serde_json::json!({
        "operation_id": "operation",
        "process_tree_id": "tree",
        "job_id": JOB_ID,
        "image_id": "image-1",
        "session_id": "session-1",
        "generation": 3,
        "action_lease_ref": "lease-1",
        "authority_id": "authority-1",
        "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 7},
        "state_fence": {
            "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 7},
            "generation": 3,
            "nonce": "fence-1"
        },
        "request_digest": "a".repeat(64),
        "permit_digest": "b".repeat(64),
        "effect_digest": "c".repeat(64),
        "validation_revision": 2
    }))
    .expect("valid test binding")
}

fn test_view(binding: &ProcessExecutionBinding) -> ProcessExecutionView {
    serde_json::from_value(serde_json::json!({
        "binding": serde_json::to_value(binding).expect("binding serializes"),
        "lifecycle": "running",
        "health": {"status": "healthy", "ready": true, "observed_at_unix_ms": 10, "detail": null},
        "cancellation": "not_requested",
        "identity": null,
        "exit": null,
        "descendants": null
    }))
    .expect("valid test view")
}

fn test_policy() -> ProcessStreamPolicyBinding {
    ProcessStreamPolicyBinding::new(
        "policy:1",
        "privacy:project",
        "visibility:owner",
        "retention:task",
        "redaction:exact-v1",
    )
    .expect("valid test policy")
}

fn byte_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).expect("test bytes fit in u64")
}

/// One complete typed stream: complete transport, complete durable source,
/// full transport preview, no gaps.
fn complete_stream(
    binding: &ProcessExecutionBinding,
    stream: ProcessStreamKind,
    bytes: &[u8],
    locator: &str,
    receipt: &str,
) -> ProcessStreamEvidence {
    let digest = sha256_hex(bytes);
    let source = DurableProcessStreamSource::exact_transport(
        DurableStreamLocatorKind::Blob,
        locator,
        receipt,
        digest.clone(),
        byte_len(bytes),
    )
    .expect("valid test source");
    let preview =
        ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), byte_len(bytes))
            .expect("valid test preview");
    ProcessStreamEvidence::new_raw(
        binding.clone(),
        stream,
        test_policy(),
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::CompleteSource,
        digest,
        byte_len(bytes),
        preview,
        Some(source),
        Vec::new(),
    )
    .expect("valid complete test stream")
}

/// One source-unavailable typed stream: no durable source, explicit gap.
fn unavailable_stream(
    binding: &ProcessExecutionBinding,
    stream: ProcessStreamKind,
    bytes: &[u8],
) -> ProcessStreamEvidence {
    let preview =
        ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), byte_len(bytes))
            .expect("valid test preview");
    ProcessStreamEvidence::new_raw(
        binding.clone(),
        stream,
        test_policy(),
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::SourceUnavailable,
        sha256_hex(bytes),
        byte_len(bytes),
        preview,
        None,
        vec![StreamEvidenceGap::PersistenceUnavailable],
    )
    .expect("valid unavailable test stream")
}

fn test_record(
    stdout: Option<ProcessStreamEvidence>,
    stderr: Option<ProcessStreamEvidence>,
) -> ProcessEvidence {
    let binding = test_binding();
    let view = test_view(&binding);
    ProcessEvidence::new_typed(
        view,
        stdout,
        stderr,
        eliot_instrument_api::EvidenceAxes::observed(),
    )
    .expect("valid test record")
}

fn test_context(fence_sequence: u64) -> TestdReadbackContext {
    TestdReadbackContext {
        job_id: JOB_ID.to_owned(),
        invocation_id: INVOCATION_ID.to_owned(),
        fence: test_fence(fence_sequence),
        max_bytes: 1 << 20,
        deadline_ms: 999,
    }
}

/// Per-locator served source behind the test port.
struct ServedSource {
    bytes: Vec<u8>,
    ready_receipt_override: Option<String>,
    digest_override: Option<String>,
    disposition: TestdStreamDisposition,
}

/// Test readback port: serves exact bytes per locator and asserts the exact
/// job/attempt binding. Unknown attempts are refused without bytes.
struct TestPort {
    job_id: String,
    invocation_id: String,
    table: HashMap<String, ServedSource>,
    calls: Mutex<u64>,
}

impl TestPort {
    fn for_attempt(job_id: &str, invocation_id: &str) -> Self {
        Self {
            job_id: job_id.to_owned(),
            invocation_id: invocation_id.to_owned(),
            table: HashMap::new(),
            calls: Mutex::new(0),
        }
    }

    fn serve(
        mut self,
        locator: &str,
        bytes: Vec<u8>,
        ready_receipt_override: Option<String>,
        digest_override: Option<String>,
        disposition: TestdStreamDisposition,
    ) -> Self {
        self.table.insert(
            locator.to_owned(),
            ServedSource {
                bytes,
                ready_receipt_override,
                digest_override,
                disposition,
            },
        );
        self
    }

    fn call_count(&self) -> u64 {
        *self.calls.lock().expect("port call counter is readable")
    }
}

impl ProcessStreamSourceReadbackPort for TestPort {
    fn resolve(
        &self,
        request: &ProcessStreamSourceReadbackRequest,
    ) -> Result<ProcessStreamSourceReadbackObservation, TestdEvidenceError> {
        *self.calls.lock().expect("port call counter is writable") += 1;
        if request.job_id != self.job_id || request.invocation_id != self.invocation_id {
            return Err(TestdEvidenceError::SourceUnknownOutcome {
                stream: request.stream,
                reason: "the readback names an unknown job or attempt",
            });
        }
        let served = self.table.get(&request.locator).ok_or({
            TestdEvidenceError::SourceUnavailable {
                stream: request.stream,
                reason: "the test port serves no source under this locator",
            }
        })?;
        assert_eq!(
            request.binding.job_id().as_str(),
            JOB_ID,
            "readback carries the admitted job binding"
        );
        Ok(ProcessStreamSourceReadbackObservation::new(
            served.bytes.clone(),
            served
                .digest_override
                .clone()
                .unwrap_or_else(|| sha256_hex(&served.bytes)),
            byte_len(&served.bytes),
            request.locator_kind,
            request.locator.clone(),
            served
                .ready_receipt_override
                .clone()
                .unwrap_or_else(|| request.ready_receipt_ref.clone()),
            11,
            format!("readback-{}", request.locator),
            request.fence.clone(),
            ClockReading::default(),
            served.disposition,
        ))
    }
}

fn parse_observation(
    record: &eliot_testd_core::TestdStreamEvidenceBinding,
    status: TestdParsingStatus,
    allows_partial: bool,
) -> TestdParsingObservation {
    TestdParsingObservation::new(
        "parser:test",
        "parser-rev:test-1",
        status,
        record.evidence_identity_sha256.clone(),
        record
            .readback_receipt_id
            .clone()
            .expect("source resolved before parsing"),
        allows_partial,
        ClockReading::default(),
    )
    .expect("valid test parsing observation")
}

fn evaluate_observation(
    record: &eliot_testd_core::TestdStreamEvidenceBinding,
    status: TestdEvaluationStatus,
    artifact: &str,
    artifact_partial: bool,
    fence_sequence: u64,
) -> TestdEvaluationObservation {
    TestdEvaluationObservation::new(
        "evaluator:test",
        "evaluator-rev:test-1",
        status,
        "property:exit-code",
        record.evidence_identity_sha256.clone(),
        "parser:test",
        "parser-rev:test-1",
        artifact,
        artifact_partial,
        test_fence(fence_sequence),
        ClockReading::default(),
    )
    .expect("valid test evaluation observation")
}

fn resolved_bytes(resolution: TestdStreamResolution) -> EphemeralSourceBytes {
    match resolution {
        TestdStreamResolution::Resolved { bytes, .. } => bytes,
        TestdStreamResolution::Refused { error, .. } => {
            panic!("expected resolved source bytes, refused: {error:?}")
        }
    }
}

/// `resolve_pending` pushes stdout first, then stderr: the head outcome is
/// always the stdout resolution.
fn stdout_outcome(outcomes: Vec<TestdStreamResolution>) -> TestdStreamResolution {
    outcomes.into_iter().next().expect("stdout outcome first")
}

fn refused_error(resolution: TestdStreamResolution) -> TestdEvidenceError {
    match resolution {
        TestdStreamResolution::Refused { error, .. } => error,
        TestdStreamResolution::Resolved { .. } => panic!("expected refusal, source resolved"),
    }
}

/// FIX1 / WA1 / WB3: typed complete stdout+stderr admit and resolve with no
/// legacy references anywhere on the path.
#[test]
fn typed_stdout_stderr_resolve_without_legacy_refs() {
    let binding = test_binding();
    let stdout_bytes = b"{\"ok\":true}\n";
    let stderr_bytes = b"warn: slow\n";
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            stdout_bytes,
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stderr,
            stderr_bytes,
            LOCATOR_STDERR,
            RECEIPT_STDERR,
        )),
    );
    assert_eq!(record.stdout_ref(), None);
    assert_eq!(record.stderr_ref(), None);

    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    // The durable receipt keeps bindings only: serialization carries no bytes.
    let value = serde_json::to_value(&bundle).expect("bundle serializes");
    let serialized = serde_json::to_string(&value).expect("bundle renders");
    assert!(!serialized.contains("readback-"));
    assert_eq!(
        bundle.disposition,
        TestdEvidenceDisposition::UnavailableEvidence,
        "pending readback is not complete evidence"
    );

    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID)
        .serve(
            LOCATOR_STDOUT,
            stdout_bytes.to_vec(),
            None,
            None,
            TestdStreamDisposition::CompleteSource,
        )
        .serve(
            LOCATOR_STDERR,
            stderr_bytes.to_vec(),
            None,
            None,
            TestdStreamDisposition::CompleteSource,
        );
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    assert_eq!(outcomes.len(), 2);
    let mut seen = 0;
    for outcome in outcomes {
        let bytes = resolved_bytes(outcome);
        assert!(
            bytes.bytes() == stdout_bytes || bytes.bytes() == stderr_bytes,
            "resolved bytes equal exactly one served stream"
        );
        seen += 1;
    }
    assert_eq!(seen, 2);
    assert_eq!(port.call_count(), 2);
    assert_eq!(
        bundle.disposition,
        TestdEvidenceDisposition::CompleteEvidence
    );
    for slot in [&bundle.stdout, &bundle.stderr] {
        let record = slot.binding.as_ref().expect("slot carries a binding");
        assert_eq!(slot.disposition, TestdStreamDisposition::CompleteSource);
        assert!(record.readback_receipt_id.is_some());
        assert!(record.fence.is_some());
        assert_eq!(record.legacy_reference, None);
        record.validate().expect("resolved binding validates");
    }
    bundle.validate().expect("resolved bundle validates");
}

/// INV2 / FIX2: bytes recorded through `record_raw_artifact` can never satisfy
/// current verification: the typed stream stays unavailable, parsing is
/// refused, the evaluator stays unassessed.
#[test]
fn caller_bytes_cannot_satisfy_current_verification() {
    let collector = EvidenceCollector::default();
    let caller_bytes = b"{\"ok\":true}\n";
    collector
        .record_raw_artifact(
            "attacker-handle",
            "application/x-nextest-libtest-json-plus",
            caller_bytes.to_vec(),
            false,
        )
        .expect("raw capture stores caller bytes");
    let binding = test_binding();
    let record = test_record(
        Some(unavailable_stream(
            &binding,
            ProcessStreamKind::Stdout,
            caller_bytes,
        )),
        None,
    );
    eliot_process::ProcessEvidenceSink::record(&collector, record).expect("sink records");
    let bundles = collector.typed_bundles();
    assert_eq!(bundles.len(), 1);
    assert_eq!(
        bundles[0].stdout.disposition,
        TestdStreamDisposition::SourceUnavailable
    );
    let slot = bundles[0]
        .stdout
        .binding
        .as_ref()
        .expect("slot carries a binding");
    assert_eq!(slot.legacy_reference, None);

    // No readback exists for this stream, so no parsing observation can bind.
    let observation = TestdParsingObservation::new(
        "parser:test",
        "parser-rev:test-1",
        TestdParsingStatus::Parsed,
        slot.evidence_identity_sha256.clone(),
        "readback-never-issued",
        false,
        ClockReading::default(),
    )
    .expect("observation builds");
    let mut binding_copy = slot.clone();
    let error = binding_copy
        .apply_parsing(&observation)
        .expect_err("parsing without verified readback fails");
    assert!(matches!(
        error,
        TestdEvidenceError::ParserIncompatible { .. }
            | TestdEvidenceError::ParserNotExecuted { .. }
    ));
    assert_eq!(
        binding_copy.evaluator.status,
        TestdEvaluationStatus::Unassessed
    );
}

/// INV3 / FIX3 / FIX4: digest and ready-receipt mismatches fail closed with
/// integrity dispositions and expose no bytes.
#[test]
fn readback_digest_and_receipt_mismatch_fail_closed() {
    let binding = test_binding();
    let bytes = b"stream bytes\n";
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            bytes,
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );

    // Wrong bytes under the right locator: digest mismatch.
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        b"forged bytes\n".to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    let error = refused_error(stdout_outcome(outcomes));
    assert!(matches!(
        error,
        TestdEvidenceError::ReadbackDigestMismatch { .. }
    ));
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::IntegrityBroken
    );

    // Right bytes under a foreign ready receipt: identity mismatch.
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        Some("ready-receipt-foreign".to_owned()),
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    let error = refused_error(stdout_outcome(outcomes));
    assert!(matches!(
        error,
        TestdEvidenceError::ReadbackIdentityMismatch { .. }
    ));
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::IntegrityBroken
    );
}

/// WB5 / FIX5 / INV5: a zero-byte complete source resolves exactly like any
/// other length and is distinct from a missing source.
#[test]
fn zero_byte_complete_source_resolves() {
    let binding = test_binding();
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            b"",
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::ReadbackPending
    );
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        Vec::new(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    let bytes = resolved_bytes(stdout_outcome(outcomes));
    assert!(bytes.is_empty());
    assert_eq!(bytes.len(), 0);
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::CompleteSource,
        "zero-byte complete source is valid raw evidence"
    );
}

/// FIX6 / INV4: a truncated preview expands through the port, but preview
/// bytes alone can never satisfy parsing.
#[test]
fn truncated_preview_expands_but_never_parses() {
    let binding = test_binding();
    let full = b"0123456789abcdef";
    let digest = sha256_hex(full);
    let source = DurableProcessStreamSource::exact_transport(
        DurableStreamLocatorKind::Blob,
        LOCATOR_STDOUT,
        RECEIPT_STDOUT,
        digest.clone(),
        byte_len(full),
    )
    .expect("valid test source");
    let preview =
        ProcessStreamPrefixPreview::from_transport_prefix(full[..6].to_vec(), byte_len(full))
            .expect("valid truncated preview");
    assert!(preview.is_truncated());
    let stream = ProcessStreamEvidence::new_raw(
        binding.clone(),
        ProcessStreamKind::Stdout,
        test_policy(),
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::CompleteSource,
        digest,
        byte_len(full),
        preview,
        Some(source),
        Vec::new(),
    )
    .expect("valid truncated-preview stream");
    let record = test_record(Some(stream), None);
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");

    // Preview bytes are navigation only: parsing without a verified readback
    // receipt is refused even though preview bytes exist.
    let slot = bundle
        .stdout
        .binding
        .as_ref()
        .expect("slot carries a binding");
    let preview_only = TestdParsingObservation::new(
        "parser:test",
        "parser-rev:test-1",
        TestdParsingStatus::Parsed,
        slot.evidence_identity_sha256.clone(),
        "readback-never-issued",
        false,
        ClockReading::default(),
    )
    .expect("observation builds");
    let mut pending = slot.clone();
    assert!(matches!(
        pending.apply_parsing(&preview_only),
        Err(TestdEvidenceError::ParserIncompatible { .. })
    ));

    // The complete immutable source expands through the port.
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        full.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    let bytes = resolved_bytes(stdout_outcome(outcomes));
    assert_eq!(bytes.bytes(), full);
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::CompleteSource
    );
}

/// FIX7: partial, unavailable, prohibited, redaction-failed, purged, corrupt
/// and unknown sources each stay in a distinct non-complete disposition.
#[test]
fn non_complete_sources_stay_distinct() {
    let binding = test_binding();
    let bytes = b"partial stream bytes\n";
    let digest = sha256_hex(bytes);

    // Partial: transport failed after bytes were observed; full-length exact
    // source with explicit coverage gaps.
    let partial_source = DurableProcessStreamSource::exact_transport(
        DurableStreamLocatorKind::Blob,
        "blob:locator-partial",
        "ready-receipt-partial",
        digest.clone(),
        byte_len(bytes),
    )
    .expect("valid test source");
    let partial_preview =
        ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), byte_len(bytes))
            .expect("valid test preview");
    let partial = ProcessStreamEvidence::new_raw(
        binding.clone(),
        ProcessStreamKind::Stdout,
        test_policy(),
        StreamTransportStatus::ReadFailed,
        StreamPersistenceStatus::PartialSource,
        digest,
        byte_len(bytes),
        partial_preview,
        Some(partial_source),
        vec![
            StreamEvidenceGap::PersistenceBackpressure,
            StreamEvidenceGap::TransportReadFailed,
        ],
    )
    .expect("valid partial test stream");
    let mut bundle = TestdProcessEvidenceBundle::admit(&test_record(Some(partial), None))
        .expect("bundle admits");
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::PartialSource
    );
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        "blob:locator-partial",
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    let resolved = resolved_bytes(stdout_outcome(outcomes));
    assert_eq!(resolved.bytes(), bytes);
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::PartialSource,
        "incomplete transport never promotes to complete"
    );

    // Unavailable: no durable source; the port is never called.
    let mut bundle = TestdProcessEvidenceBundle::admit(&test_record(
        Some(unavailable_stream(
            &binding,
            ProcessStreamKind::Stdout,
            bytes,
        )),
        None,
    ))
    .expect("bundle admits");
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID);
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    assert!(matches!(
        refused_error(stdout_outcome(outcomes)),
        TestdEvidenceError::SourceUnavailable { .. }
    ));
    assert_eq!(port.call_count(), 0);

    // Policy-prohibited and redaction-failed: refused before any provider call.
    for (gap, expected) in [
        (
            StreamEvidenceGap::PolicyProhibited,
            TestdStreamDisposition::PolicyProhibited,
        ),
        (
            StreamEvidenceGap::RedactionFailed,
            TestdStreamDisposition::RedactionFailed,
        ),
    ] {
        let withheld = ProcessStreamEvidence::new_raw(
            binding.clone(),
            ProcessStreamKind::Stdout,
            test_policy(),
            StreamTransportStatus::CaptureUnavailable,
            StreamPersistenceStatus::SourceUnavailable,
            sha256_hex(b""),
            0,
            ProcessStreamPrefixPreview::withheld_by_policy(),
            None,
            vec![gap, StreamEvidenceGap::CaptureUnavailable],
        )
        .expect("valid withheld test stream");
        let mut bundle = TestdProcessEvidenceBundle::admit(&test_record(Some(withheld), None))
            .expect("bundle admits");
        assert_eq!(bundle.stdout.disposition, expected);
        let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
            "blob:never",
            bytes.to_vec(),
            None,
            None,
            TestdStreamDisposition::CompleteSource,
        );
        let outcomes = bundle.resolve_pending(&port, &test_context(7));
        refused_error(stdout_outcome(outcomes));
        assert_eq!(port.call_count(), 0, "no byte path exists for {gap:?}");
        assert_eq!(bundle.stdout.disposition, expected);
    }

    // Provider-reported terminal outcomes each map to a distinct disposition.
    for (served_disposition, expected) in [
        (
            TestdStreamDisposition::Purged,
            TestdStreamDisposition::Purged,
        ),
        (
            TestdStreamDisposition::RetentionBlocked,
            TestdStreamDisposition::RetentionBlocked,
        ),
        (
            TestdStreamDisposition::IntegrityBroken,
            TestdStreamDisposition::IntegrityBroken,
        ),
        (TestdStreamDisposition::Stale, TestdStreamDisposition::Stale),
        (
            TestdStreamDisposition::UnknownOutcome,
            TestdStreamDisposition::UnknownOutcome,
        ),
    ] {
        let mut bundle = TestdProcessEvidenceBundle::admit(&test_record(
            Some(complete_stream(
                &binding,
                ProcessStreamKind::Stdout,
                bytes,
                LOCATOR_STDOUT,
                RECEIPT_STDOUT,
            )),
            None,
        ))
        .expect("bundle admits");
        let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
            LOCATOR_STDOUT,
            bytes.to_vec(),
            None,
            None,
            served_disposition,
        );
        let outcomes = bundle.resolve_pending(&port, &test_context(7));
        refused_error(stdout_outcome(outcomes));
        assert_eq!(bundle.stdout.disposition, expected);
    }
}

/// FIX8 / WC4: a successful process exit with no executed parser leaves the
/// evaluator unassessed and yields no verifier result.
#[test]
fn exit_zero_without_parse_stays_unverified() {
    let binding = test_binding();
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            b"exit 0\n",
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );
    let bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let slot = bundle
        .stdout
        .binding
        .as_ref()
        .expect("slot carries a binding");
    assert_eq!(
        slot.parser.status,
        TestdParsingStatus::NotExecuted,
        "admission sets no parser status"
    );
    let observation = TestdEvaluationObservation::new(
        "evaluator:test",
        "evaluator-rev:test-1",
        TestdEvaluationStatus::Pass,
        "property:exit-code",
        slot.evidence_identity_sha256.clone(),
        "parser:test",
        "parser-rev:test-1",
        "artifact:test",
        false,
        test_fence(7),
        ClockReading::default(),
    )
    .expect("observation builds");
    let mut pending = slot.clone();
    assert!(matches!(
        pending.apply_evaluation(&observation),
        Err(TestdEvidenceError::EvaluatorNotExecuted { .. })
    ));
    assert_eq!(pending.evaluator.status, TestdEvaluationStatus::Unassessed);
}

/// FIX9 / WC1: parser failure and evaluator failure are distinct axes; an
/// evaluator failure requires a prior successful parse.
#[test]
fn parser_and_evaluator_failures_stay_distinct() {
    let binding = test_binding();
    let bytes = b"output\n";
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            bytes,
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    assert_eq!(outcomes.len(), 2);

    // A failed parse records ParseFailed and leaves the evaluator unassessed.
    let failed = parse_observation(
        bundle
            .stdout
            .binding
            .as_ref()
            .expect("slot carries a binding"),
        TestdParsingStatus::ParseFailed,
        false,
    );
    let slot = bundle
        .stdout
        .binding
        .as_mut()
        .expect("slot carries a binding");
    slot.apply_parsing(&failed).expect("failed parse records");
    assert_eq!(slot.parser.status, TestdParsingStatus::ParseFailed);
    assert_eq!(slot.evaluator.status, TestdEvaluationStatus::Unassessed);

    // Evaluation after a failed parse is refused: only Parsed feeds evaluation.
    let evaluate = TestdEvaluationObservation::new(
        "evaluator:test",
        "evaluator-rev:test-1",
        TestdEvaluationStatus::Fail,
        "property:exit-code",
        slot.evidence_identity_sha256.clone(),
        "parser:test",
        "parser-rev:test-1",
        "artifact:test",
        false,
        test_fence(7),
        ClockReading::default(),
    )
    .expect("observation builds");
    assert!(matches!(
        slot.apply_evaluation(&evaluate),
        Err(TestdEvidenceError::EvaluatorNotExecuted { .. })
    ));
}

/// FIX10: an evaluator PASS with the wrong artifact binding, or under a stale
/// fence, can never verify.
#[test]
fn wrong_artifact_and_stale_fence_cannot_verify() {
    let binding = test_binding();
    let bytes = b"output\n";
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            bytes,
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let _ = bundle.resolve_pending(&port, &test_context(7));
    let parsed = parse_observation(
        bundle
            .stdout
            .binding
            .as_ref()
            .expect("slot carries a binding"),
        TestdParsingStatus::Parsed,
        false,
    );
    let slot = bundle
        .stdout
        .binding
        .as_mut()
        .expect("slot carries a binding");
    slot.apply_parsing(&parsed).expect("parse records");

    // A PASS bound only partially records a partial binding, never an exact
    // one: partial bindings are non-verifying by construction, and the named
    // artifact is recorded exactly as the evaluator stated it.
    let partial = evaluate_observation(slot, TestdEvaluationStatus::Pass, "artifact:test", true, 7);
    slot.apply_evaluation(&partial)
        .expect("partial evaluation records");
    assert_eq!(slot.evaluator.status, TestdEvaluationStatus::Pass);
    assert_eq!(
        slot.artifact_binding,
        TestdArtifactBinding::BoundPartial("artifact:test".to_owned())
    );
    assert_ne!(
        slot.artifact_binding,
        TestdArtifactBinding::BoundExact("artifact:test".to_owned())
    );

    // Stale fence: the readback fence (epoch sequence 7) is incompatible with
    // an advanced attempt fence (sequence 9).
    let stale = evaluate_observation(slot, TestdEvaluationStatus::Pass, "artifact:test", false, 9);
    assert!(matches!(
        slot.apply_evaluation(&stale),
        Err(TestdEvidenceError::EvaluationStale { .. })
    ));
    assert_eq!(slot.evaluator.status, TestdEvaluationStatus::Unassessed);

    // Exact artifact under the current fence verifies.
    let exact = evaluate_observation(slot, TestdEvaluationStatus::Pass, "artifact:test", false, 7);
    slot.apply_evaluation(&exact)
        .expect("exact evaluation records");
    assert_eq!(slot.evaluator.status, TestdEvaluationStatus::Pass);
    assert_eq!(
        slot.artifact_binding,
        TestdArtifactBinding::BoundExact("artifact:test".to_owned())
    );

    // A later fence advance marks the recorded PASS stale instead of keeping it.
    slot.revalidate_fence(&test_fence(9));
    assert_eq!(slot.evaluator.status, TestdEvaluationStatus::Stale);
}

/// FIX11 / INV8: a legacy reference is retained as provenance only; even
/// later-supplied matching bytes can never expand it or satisfy verification.
#[test]
fn legacy_reference_never_upgrades() {
    let binding = test_binding();
    let bytes = b"legacy output\n";
    let legacy = ProcessStreamEvidence::new_legacy_raw_reference(
        binding.clone(),
        ProcessStreamKind::Stdout,
        "raw:test-ref-1",
    )
    .expect("valid legacy reference");
    let record = test_record(Some(legacy), None);
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::LegacyMigrationRequired
    );
    assert_eq!(
        bundle
            .stdout
            .binding
            .as_ref()
            .expect("legacy slot carries a binding")
            .legacy_reference
            .as_deref(),
        Some("raw:test-ref-1")
    );

    // The port would serve matching bytes, but legacy records never call it.
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        "blob:legacy",
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    assert!(matches!(
        refused_error(stdout_outcome(outcomes)),
        TestdEvidenceError::LegacyStreamEvidenceUnavailable { .. }
    ));
    assert_eq!(port.call_count(), 0);
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::LegacyMigrationRequired
    );
}

/// FIX12 / WD2: daemon restart reconstructs the same evidence: a serialized
/// bundle deserializes into an equal bundle and re-resolves to the same
/// readback receipt, fence and evidence identity.
#[test]
fn restart_reconstructs_same_identities() {
    let binding = test_binding();
    let bytes = b"restart bytes\n";
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            bytes,
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let _ = bundle.resolve_pending(&port, &test_context(7));
    let receipt_id = bundle
        .stdout
        .binding
        .as_ref()
        .expect("slot carries a binding")
        .readback_receipt_id
        .clone();

    // Restart: the durable bundle crosses the restart as JSON; operation
    // memory (ephemeral bytes) does not.
    let durable = serde_json::to_string(&bundle).expect("bundle persists");
    assert!(!durable.contains("restart bytes"));
    let mut rebuilt: TestdProcessEvidenceBundle =
        serde_json::from_str(&durable).expect("bundle restores");
    rebuilt.validate().expect("restored bundle validates");
    assert_eq!(rebuilt, bundle);

    // Re-resolution by the same job/attempt identity yields the same binding.
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = rebuilt.resolve_pending(&port, &test_context(7));
    let resolved = resolved_bytes(stdout_outcome(outcomes));
    assert_eq!(resolved.bytes(), bytes);
    assert_eq!(
        rebuilt
            .stdout
            .binding
            .as_ref()
            .expect("slot carries a binding")
            .readback_receipt_id,
        receipt_id
    );
}

/// FIX13 / WB3 / INV1: a record without stderr carries an explicit
/// never-emitted denominator gap, never a silent omission.
#[test]
fn missing_stream_is_explicit_gap() {
    let binding = test_binding();
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            b"out\n",
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );
    let bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    assert_eq!(bundle.stderr.stream, ProcessStreamKind::Stderr);
    assert_eq!(
        bundle.stderr.disposition,
        TestdStreamDisposition::StreamNotEmitted
    );
    assert_eq!(bundle.stderr.binding, None);
    bundle.validate().expect("gapped bundle validates");
}

/// WB4 / WC1–WC3: the collector drives the full readback -> parse -> evaluate
/// chain with separate closed axes.
#[test]
fn collector_drives_resolve_parse_evaluate_chain() {
    let collector = EvidenceCollector::default();
    let binding = test_binding();
    let bytes = b"chain bytes\n";
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            bytes,
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stderr,
            b"chain err\n",
            LOCATOR_STDERR,
            RECEIPT_STDERR,
        )),
    );
    eliot_process::ProcessEvidenceSink::record(&collector, record).expect("sink records");
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID)
        .serve(
            LOCATOR_STDOUT,
            bytes.to_vec(),
            None,
            None,
            TestdStreamDisposition::CompleteSource,
        )
        .serve(
            LOCATOR_STDERR,
            b"chain err\n".to_vec(),
            None,
            None,
            TestdStreamDisposition::CompleteSource,
        );
    let resolutions = collector
        .resolve_typed_sources(&port, &test_context(7))
        .expect("collector resolves");
    assert_eq!(resolutions.len(), 1);
    assert_eq!(resolutions[0].len(), 2);

    let bundles = collector.typed_bundles();
    assert_eq!(bundles.len(), 1);
    assert_eq!(
        bundles[0].disposition,
        TestdEvidenceDisposition::CompleteEvidence
    );
}

/// WC5 / INV6–INV7: parser success never implies evaluator PASS; evaluation
/// stays unassessed until an evaluation observation is applied.
#[test]
fn parser_success_leaves_evaluator_unassessed() {
    let binding = test_binding();
    let bytes = b"parsed output\n";
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            bytes,
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let _ = bundle.resolve_pending(&port, &test_context(7));
    let parsed = parse_observation(
        bundle
            .stdout
            .binding
            .as_ref()
            .expect("slot carries a binding"),
        TestdParsingStatus::Parsed,
        false,
    );
    let slot = bundle
        .stdout
        .binding
        .as_mut()
        .expect("slot carries a binding");
    slot.apply_parsing(&parsed).expect("parse records");
    assert_eq!(slot.parser.status, TestdParsingStatus::Parsed);
    assert_eq!(
        slot.evaluator.status,
        TestdEvaluationStatus::Unassessed,
        "parser success is not evaluation"
    );
}

/// Readback request shape fails closed before any provider call.
#[test]
fn readback_request_shape_fails_closed() {
    let binding = test_binding();
    let bytes = b"shaped\n";
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            bytes,
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );
    let bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let slot = bundle
        .stdout
        .binding
        .as_ref()
        .expect("slot carries a binding");

    // A byte bound below the admitted source length is refused.
    let mut context = test_context(7);
    context.max_bytes = 1;
    let request = ProcessStreamSourceReadbackRequest {
        job_id: context.job_id.clone(),
        invocation_id: context.invocation_id.clone(),
        binding: slot.binding.clone(),
        stream: ProcessStreamKind::Stdout,
        locator_kind: slot.locator_kind.expect("admitted locator kind"),
        locator: slot.locator.clone().expect("admitted locator"),
        ready_receipt_ref: slot.ready_receipt_ref.clone().expect("admitted receipt"),
        expected_sha256: slot.source_sha256.clone().expect("admitted digest"),
        expected_byte_length: slot.source_byte_length.expect("admitted length"),
        policy: slot.policy.clone(),
        fence: context.fence.clone(),
        max_bytes: context.max_bytes,
        deadline_ms: context.deadline_ms,
    };
    assert!(matches!(
        request.validate(),
        Err(TestdEvidenceError::ReadbackRequestInvalid { .. })
    ));
}

/// WA1 / WD1: the port observes the exact job/attempt binding; a foreign
/// attempt is refused without bytes.
#[test]
fn readback_binds_exact_job_and_attempt() {
    let binding = test_binding();
    let bytes = b"bound\n";
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            bytes,
            LOCATOR_STDOUT,
            RECEIPT_STDOUT,
        )),
        None,
    );
    let mut bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    // The exact composition context resolves.
    let outcomes = bundle.resolve_pending(&port, &test_context(7));
    let resolved = resolved_bytes(stdout_outcome(outcomes));
    assert_eq!(resolved.bytes(), bytes);

    // A foreign attempt carrying the same admitted record is refused.
    let mut foreign = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let foreign_context = TestdReadbackContext {
        job_id: "foreign-job".to_owned(),
        invocation_id: "foreign-invocation".to_owned(),
        fence: test_fence(7),
        max_bytes: 1 << 20,
        deadline_ms: 999,
    };
    let outcomes = foreign.resolve_pending(&port, &foreign_context);
    assert!(matches!(
        refused_error(stdout_outcome(outcomes)),
        TestdEvidenceError::SourceUnknownOutcome { .. }
    ));
    assert_ne!(
        foreign.stdout.disposition,
        TestdStreamDisposition::CompleteSource
    );
}
