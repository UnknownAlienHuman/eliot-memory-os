//! Issue #456 WD1-WD3: daemon-restart reconstruction, reopen/reconcile by
//! identity, and the real-process edge through restart into parse/evaluate.
//!
//! WD1 persists admitted typed bundles with the durable job row as a
//! [`TypedEvidenceRestartRecord`] (bindings only, never bytes) and reopens
//! the persisted bytes after a restart with byte-identical identities and no
//! operation memory. WD2 reconciles persisted pending, complete (re-expansion
//! for re-parse), and unknown-outcome slots through the port by the same
//! session identity; a foreign attempt is refused without bytes. WD3 runs a
//! real OS child, captures its real stdout bytes into a durable immutable
//! source, drops all memory state, reopens the persisted record, re-expands
//! the immutable output, and parses/evaluates it to `Pass` — while a
//! truncated preview alone and an exit-zero view without parsing stay
//! unverified.
//!
//! The file-backed port below is a test double standing in for the #297
//! Blob-backed production adapter: files in a temp dir are the durable
//! immutable source that survives the simulated restart, exactly as Blob
//! objects would. The in-memory [`TestPort`] asserts the same job/attempt
//! binding the composition supplies.

use eliot_contracts::{ClockReading, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_process::ProcessEvidenceSink;
use eliot_process::{
    DurableStreamLocatorKind, ProcessEvidence, ProcessExecutionBinding, ProcessExecutionView,
    ProcessStreamEvidence, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamPrefixPreview, StreamEvidenceGap, StreamPersistenceStatus, StreamTransportStatus,
};
use eliot_testd_core::{
    EphemeralSourceBytes, EvidenceCollector, ProcessStreamSourceReadbackObservation,
    ProcessStreamSourceReadbackPort, ProcessStreamSourceReadbackRequest, TestdArtifactBinding,
    TestdEvaluationObservation, TestdEvaluationStatus, TestdEvidenceError, TestdParsingObservation,
    TestdParsingStatus, TestdProcessEvidenceBundle, TestdStreamDisposition, TestdStreamResolution,
    TypedEvidenceRestartRecord, sha256_hex,
};
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Mutex;

const JOB_ID: &str = "restart-job";
const INVOCATION_ID: &str = "restart-invocation";
const LOCATOR_STDOUT: &str = "blob:restart-stdout-1";
const RECEIPT_STDOUT: &str = "ready-receipt-restart-stdout-1";

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
        "policy:restart-1",
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
    let source = eliot_process::DurableProcessStreamSource::exact_transport(
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

/// Durable file-backed port: resolves each locator to a file under a temp
/// dir. Files persist across the simulated restart while every in-memory
/// object is dropped, exactly the durability contract the #297 Blob-backed
/// production adapter must honor.
struct FilePort {
    job_id: String,
    invocation_id: String,
    dir: std::path::PathBuf,
}

impl FilePort {
    fn fresh_for_attempt(job_id: &str, invocation_id: &str, dir: &std::path::Path) -> Self {
        Self {
            job_id: job_id.to_owned(),
            invocation_id: invocation_id.to_owned(),
            dir: dir.to_owned(),
        }
    }

    fn source_path(&self, locator: &str) -> std::path::PathBuf {
        let file = locator
            .strip_prefix("blob:")
            .expect("test locators stay blob-scoped");
        self.dir.join(format!("{file}.bin"))
    }
}

impl ProcessStreamSourceReadbackPort for FilePort {
    fn resolve(
        &self,
        request: &ProcessStreamSourceReadbackRequest,
    ) -> Result<ProcessStreamSourceReadbackObservation, TestdEvidenceError> {
        if request.job_id != self.job_id || request.invocation_id != self.invocation_id {
            return Err(TestdEvidenceError::SourceUnknownOutcome {
                stream: request.stream,
                reason: "the readback names an unknown job or attempt",
            });
        }
        let bytes = std::fs::read(self.source_path(&request.locator)).map_err(|_| {
            TestdEvidenceError::SourceUnavailable {
                stream: request.stream,
                reason: "the durable source file is absent",
            }
        })?;
        Ok(ProcessStreamSourceReadbackObservation::new(
            bytes.clone(),
            sha256_hex(&bytes),
            byte_len(&bytes),
            request.locator_kind,
            request.locator.clone(),
            request.ready_receipt_ref.clone(),
            11,
            format!("readback-{}", request.locator),
            request.fence.clone(),
            ClockReading::default(),
            TestdStreamDisposition::CompleteSource,
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

/// `reconcile` returns one outcome vec per persisted bundle: the head vec is
/// the single bundle these tests persist.
fn first_bundle(outcomes: Vec<Vec<TestdStreamResolution>>) -> Vec<TestdStreamResolution> {
    outcomes.into_iter().next().expect("one bundle reconciled")
}

fn refused_error(resolution: TestdStreamResolution) -> TestdEvidenceError {
    match resolution {
        TestdStreamResolution::Refused { error, .. } => error,
        TestdStreamResolution::Resolved { .. } => panic!("expected refusal, source resolved"),
    }
}

fn stdout_slot(
    bundle: &TestdProcessEvidenceBundle,
) -> &eliot_testd_core::TestdStreamEvidenceBinding {
    bundle
        .stdout
        .binding
        .as_ref()
        .expect("stdout slot carries a binding")
}

/// WD1: the persisted restart record reopens with byte-identical identities
/// and no operation memory; the serialized record carries no source bytes.
#[test]
fn restart_record_reopen_keeps_exact_identities() {
    let binding = test_binding();
    let bytes = b"{\"payload_marker\":\"qk7z-unique-source-bytes\"}\n";
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
    let fence_sequence = 7;
    let context = eliot_testd_core::TestdReadbackContext {
        job_id: JOB_ID.to_owned(),
        invocation_id: INVOCATION_ID.to_owned(),
        fence: test_fence(fence_sequence),
        max_bytes: 1 << 20,
        deadline_ms: 999,
    };
    let resolved = resolved_bytes(stdout_outcome(bundle.resolve_pending(&port, &context)));
    assert_eq!(resolved.bytes(), bytes);

    // The daemon checkpoints the admitted bundle with the durable job row.
    let collector = EvidenceCollector::default();
    collector
        .record(
            eliot_process::ProcessEvidence::new_typed(
                test_view(&binding),
                Some(complete_stream(
                    &binding,
                    ProcessStreamKind::Stdout,
                    bytes,
                    LOCATOR_STDOUT,
                    RECEIPT_STDOUT,
                )),
                None,
                eliot_instrument_api::EvidenceAxes::observed(),
            )
            .expect("record builds"),
        )
        .expect("collector records");
    let checkpoint = collector
        .checkpoint_typed_evidence(JOB_ID, INVOCATION_ID, &test_fence(fence_sequence))
        .expect("checkpoint captures");
    assert_eq!(checkpoint.bundles.len(), 1);

    // Persist: only bindings travel. The payload bytes must not appear.
    let persisted = serde_json::to_string(&checkpoint).expect("record serializes");
    assert!(
        !persisted.contains("qk7z-unique-source-bytes"),
        "no source byte payload in the durable record"
    );
    assert!(
        persisted.contains(RECEIPT_STDOUT),
        "the durable record keeps the ready-receipt binding"
    );

    // Restart: every in-memory object is dropped; only `persisted` survives.
    drop(bundle);
    drop(checkpoint);
    drop(port);
    drop(collector);
    let mut reopened =
        TypedEvidenceRestartRecord::reopen(&persisted).expect("persisted record reopens");
    let reopened_context = reopened
        .context(1 << 20, 999)
        .expect("context rebuilds from durable identities");
    assert_eq!(reopened_context.job_id, JOB_ID);
    assert_eq!(reopened_context.invocation_id, INVOCATION_ID);

    // Re-resolve through a fresh port: the same identities come back.
    let fresh = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = reopened
        .reconcile(&fresh, 1 << 20, 999)
        .expect("reconcile runs");
    let again = resolved_bytes(stdout_outcome(first_bundle(outcomes)));
    assert_eq!(again.bytes(), bytes);
    let slot = stdout_slot(&reopened.bundles[0]);
    let receipt = slot
        .readback_receipt_id
        .clone()
        .expect("resolved readback receipt");
    assert!(receipt.starts_with("readback-blob:restart-stdout-1"));
    let reparsed = parse_observation(slot, TestdParsingStatus::Parsed, false);
    let slot_mut = reopened.bundles[0]
        .stdout
        .binding
        .as_mut()
        .expect("slot carries a binding");
    slot_mut.apply_parsing(&reparsed).expect("re-parse binds");
    assert_eq!(slot_mut.parser.status, TestdParsingStatus::Parsed);
}

/// WD1 negative: malformed JSON, a re-keyed job, and a zero deadline are
/// refused at reopen; nothing is repaired.
#[test]
fn reopen_refuses_corrupt_and_foreign_records() {
    let binding = test_binding();
    let bytes = b"reopen-gate\n";
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
    let checkpoint =
        TypedEvidenceRestartRecord::capture(JOB_ID, INVOCATION_ID, &test_fence(7), vec![bundle])
            .expect("capture holds");
    let persisted = serde_json::to_string(&checkpoint).expect("record serializes");

    assert!(matches!(
        TypedEvidenceRestartRecord::reopen("not json at all"),
        Err(TestdEvidenceError::BindingMismatch { .. })
    ));
    assert!(matches!(
        TypedEvidenceRestartRecord::reopen(""),
        Err(TestdEvidenceError::BindingMismatch { .. })
    ));

    // A bundle bound to another job cannot be re-keyed by editing the row.
    let mut tampered: serde_json::Value = serde_json::from_str(&persisted).expect("value parses");
    tampered["job_id"] = serde_json::Value::String("foreign-job".to_owned());
    assert!(matches!(
        TypedEvidenceRestartRecord::reopen(&tampered.to_string()),
        Err(TestdEvidenceError::BindingMismatch { .. })
    ));

    // A blank invocation identity is refused even when the JSON shape holds.
    let mut blanked: serde_json::Value = serde_json::from_str(&persisted).expect("value parses");
    blanked["invocation_id"] = serde_json::Value::String(String::new());
    assert!(matches!(
        TypedEvidenceRestartRecord::reopen(&blanked.to_string()),
        Err(TestdEvidenceError::BindingMismatch { .. })
    ));

    // A zero provider deadline is refused at context rebuild.
    let reopened =
        TypedEvidenceRestartRecord::reopen(&persisted).expect("persisted record reopens");
    assert!(matches!(
        reopened.context(1 << 20, 0),
        Err(TestdEvidenceError::ReadbackRequestInvalid { .. })
    ));
}

/// WD2: an unknown outcome persisted before the restart reconciles by the
/// same session identity after it; parse and evaluation then bind the
/// readback receipt, reaching `Pass`.
#[test]
fn restart_reconciles_unknown_outcome_by_session_identity() {
    let binding = test_binding();
    let bytes = b"unknown then settled\n";
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

    // Before the restart the provider reports an unknown outcome: the slot
    // keeps the unknown disposition and no bytes are exposed.
    let unsettled = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::UnknownOutcome,
    );
    let context = eliot_testd_core::TestdReadbackContext {
        job_id: JOB_ID.to_owned(),
        invocation_id: INVOCATION_ID.to_owned(),
        fence: test_fence(7),
        max_bytes: 1 << 20,
        deadline_ms: 999,
    };
    let first = refused_error(stdout_outcome(bundle.resolve_pending(&unsettled, &context)));
    assert!(
        matches!(first, TestdEvidenceError::SourceUnknownOutcome { .. }),
        "unknown outcome stays unknown, got {first:?}"
    );
    assert_eq!(
        bundle.stdout.disposition,
        TestdStreamDisposition::UnknownOutcome
    );

    // Persist the unknown outcome with the durable row and restart.
    let persisted = serde_json::to_string(
        &TypedEvidenceRestartRecord::capture(JOB_ID, INVOCATION_ID, &test_fence(7), vec![bundle])
            .expect("capture holds"),
    )
    .expect("record serializes");
    let mut reopened =
        TypedEvidenceRestartRecord::reopen(&persisted).expect("persisted record reopens");
    assert_eq!(
        reopened.bundles[0].stdout.disposition,
        TestdStreamDisposition::UnknownOutcome,
        "the unknown outcome survives the restart"
    );

    // After the restart the same session identity settles the source: the
    // exact bytes arrive and the evidence identity is unchanged.
    let settled = TestPort::for_attempt(JOB_ID, INVOCATION_ID).serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = reopened
        .reconcile(&settled, 1 << 20, 999)
        .expect("reconcile runs");
    let settled_bytes = resolved_bytes(stdout_outcome(first_bundle(outcomes)));
    assert_eq!(settled_bytes.bytes(), bytes);
    assert_eq!(
        reopened.bundles[0].stdout.disposition,
        TestdStreamDisposition::CompleteSource
    );

    // The readback-bound chain parses and evaluates to Pass after restart.
    let slot = stdout_slot(&reopened.bundles[0]);
    let parsed = parse_observation(slot, TestdParsingStatus::Parsed, false);
    let slot_mut = reopened.bundles[0]
        .stdout
        .binding
        .as_mut()
        .expect("slot carries a binding");
    slot_mut.apply_parsing(&parsed).expect("parse binds");
    let passed = evaluate_observation(
        slot_mut,
        TestdEvaluationStatus::Pass,
        "artifact:test",
        false,
        7,
    );
    slot_mut
        .apply_evaluation(&passed)
        .expect("evaluation binds");
    assert_eq!(slot_mut.evaluator.status, TestdEvaluationStatus::Pass);
    assert_eq!(
        slot_mut.artifact_binding,
        TestdArtifactBinding::BoundExact("artifact:test".to_owned())
    );
}

/// WD2 negative: a foreign attempt reconciling the reopened record is
/// refused without bytes; the persisted disposition is not promoted.
#[test]
fn reconcile_refuses_foreign_attempt_without_bytes() {
    let binding = test_binding();
    let bytes = b"same-session-only\n";
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
    let persisted = serde_json::to_string(
        &TypedEvidenceRestartRecord::capture(JOB_ID, INVOCATION_ID, &test_fence(7), vec![bundle])
            .expect("capture holds"),
    )
    .expect("record serializes");
    let mut reopened =
        TypedEvidenceRestartRecord::reopen(&persisted).expect("persisted record reopens");

    let foreign = TestPort::for_attempt("foreign-job", "foreign-invocation").serve(
        LOCATOR_STDOUT,
        bytes.to_vec(),
        None,
        None,
        TestdStreamDisposition::CompleteSource,
    );
    let outcomes = reopened
        .reconcile(&foreign, 1 << 20, 999)
        .expect("reconcile runs");
    assert!(matches!(
        refused_error(stdout_outcome(first_bundle(outcomes))),
        TestdEvidenceError::SourceUnknownOutcome { .. }
    ));
    assert_ne!(
        reopened.bundles[0].stdout.disposition,
        TestdStreamDisposition::CompleteSource,
        "a foreign attempt never promotes the persisted slot"
    );
}

/// Runs a real OS child and returns its exact captured stdout bytes.
///
/// This is the WD3 physical edge: real process bytes, not literals. The
/// payload is alphanumeric so shell echo passes it through verbatim.
// Disallowed-methods escape hatch (clippy.toml I10.8.2). Owner: the issue
// #456 WD3 acceptance fixture in this crate's test surface. Operation: this
// TEST-ONLY helper launches one real `cmd`/`sh` echo child to capture real
// OS process bytes for the restart edge proof. Removal condition: deleted
// with the WD3 proof, or as soon as the test binds the Kernel
// `ProcessExecutor`, at which point the launch goes through that owner
// instead of a raw spawn.
#[allow(clippy::disallowed_methods)]
fn spawn_real_child_stdout() -> Vec<u8> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("cmd")
            .args(["/C", "echo", "WD3realprocessedge1"])
            .output()
            .expect("real child process runs");
        assert!(
            output.status.success(),
            "real child exits zero, got {status:?}",
            status = output.status
        );
        output.stdout
    }
    #[cfg(not(windows))]
    {
        let output = std::process::Command::new("sh")
            .args(["-c", "printf WD3realprocessedge1"])
            .output()
            .expect("real child process runs");
        assert!(
            output.status.success(),
            "real child exits zero, got {status:?}",
            status = output.status
        );
        output.stdout
    }
}

/// Unique scratch dir under the system temp dir; removed best-effort.
fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("eliot-456-wd3-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir builds");
    dir
}

/// WD3: a real child process runs, its real stdout bytes enter a durable
/// immutable source, the daemon restarts (all memory dropped, only files
/// survive), the immutable output re-expands through a fresh port, and
/// parsing plus evaluation reach `Pass` on the exact artifact.
#[test]
fn real_process_output_survives_restart_into_pass() {
    let dir = scratch_dir("pass");
    let source_dir = dir.join("immutable");
    let durable_path = dir.join("restart-record.json");
    std::fs::create_dir_all(&source_dir).expect("immutable dir builds");

    // Instrument edge: a real OS child runs and its real bytes are captured.
    let real_bytes = spawn_real_child_stdout();
    assert!(
        real_bytes.windows(19).any(|w| w == b"WD3realprocessedge1"),
        "the real child emitted the payload, got {real_bytes:?}"
    );

    // The captured bytes become the durable immutable source before parsing.
    let locator = "blob:wd3-stdout-real";
    let receipt = "ready-receipt-wd3-stdout-real";
    std::fs::write(source_dir.join("wd3-stdout-real.bin"), &real_bytes)
        .expect("immutable source persists");
    let binding = test_binding();
    let record = test_record(
        Some(complete_stream(
            &binding,
            ProcessStreamKind::Stdout,
            &real_bytes,
            locator,
            receipt,
        )),
        None,
    );
    let bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");

    // Pre-restart resolution proves the immutable source expands.
    let pre = FilePort::fresh_for_attempt(JOB_ID, INVOCATION_ID, &source_dir);
    let mut live =
        TypedEvidenceRestartRecord::capture(JOB_ID, INVOCATION_ID, &test_fence(7), vec![bundle])
            .expect("capture holds");
    let first = live.reconcile(&pre, 1 << 20, 999).expect("reconcile runs");
    assert_eq!(
        resolved_bytes(stdout_outcome(first_bundle(first))).bytes(),
        real_bytes
    );

    // Daemon restart: persist the record bytes, drop every memory object.
    std::fs::write(
        &durable_path,
        serde_json::to_string(&live).expect("record serializes"),
    )
    .expect("restart record persists");
    drop(live);
    drop(pre);
    drop(record);

    // Post-restart: a fresh port over the surviving files re-expands the
    // exact immutable output, and parse plus evaluation reach Pass.
    let persisted =
        std::fs::read_to_string(&durable_path).expect("durable record survives restart");
    let mut reopened =
        TypedEvidenceRestartRecord::reopen(&persisted).expect("persisted record reopens");
    let post = FilePort::fresh_for_attempt(JOB_ID, INVOCATION_ID, &source_dir);
    let outcomes = reopened
        .reconcile(&post, 1 << 20, 999)
        .expect("reconcile runs");
    let expanded = resolved_bytes(stdout_outcome(first_bundle(outcomes)));
    assert_eq!(
        expanded.bytes(),
        real_bytes,
        "the immutable output re-expands byte-identically after restart"
    );
    let slot = stdout_slot(&reopened.bundles[0]);
    let parsed = parse_observation(slot, TestdParsingStatus::Parsed, false);
    let slot_mut = reopened.bundles[0]
        .stdout
        .binding
        .as_mut()
        .expect("slot carries a binding");
    slot_mut.apply_parsing(&parsed).expect("parse binds");
    let passed = evaluate_observation(
        slot_mut,
        TestdEvaluationStatus::Pass,
        "artifact:wd3",
        false,
        7,
    );
    slot_mut
        .apply_evaluation(&passed)
        .expect("evaluation binds");
    assert_eq!(slot_mut.evaluator.status, TestdEvaluationStatus::Pass);
    assert_eq!(
        slot_mut.artifact_binding,
        TestdArtifactBinding::BoundExact("artifact:wd3".to_owned())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// WD3 negative: after a restart a truncated preview alone cannot satisfy
/// parsing, and an exit-zero view without parsing cannot satisfy evaluation.
#[test]
fn restart_never_promotes_preview_or_exit_zero() {
    let binding = test_binding();
    let preview_bytes = b"truncated preview\n";
    let record = test_record(
        Some(unavailable_stream(
            &binding,
            ProcessStreamKind::Stdout,
            preview_bytes,
        )),
        None,
    );
    let bundle = TestdProcessEvidenceBundle::admit(&record).expect("bundle admits");
    let persisted = serde_json::to_string(
        &TypedEvidenceRestartRecord::capture(JOB_ID, INVOCATION_ID, &test_fence(7), vec![bundle])
            .expect("capture holds"),
    )
    .expect("record serializes");
    let mut reopened =
        TypedEvidenceRestartRecord::reopen(&persisted).expect("persisted record reopens");

    // The preview bytes exist, but no immutable source does: resolution is
    // refused without a port call, exactly as before the restart.
    let port = TestPort::for_attempt(JOB_ID, INVOCATION_ID);
    let outcomes = reopened
        .reconcile(&port, 1 << 20, 999)
        .expect("reconcile runs");
    assert!(matches!(
        refused_error(stdout_outcome(first_bundle(outcomes))),
        TestdEvidenceError::SourceUnavailable { .. }
    ));
    assert_eq!(port.call_count(), 0);

    // Parsing without a verified readback receipt is incompatible, and an
    // exit-zero view with no executed parser leaves evaluation unassessed.
    let slot = stdout_slot(&reopened.bundles[0]);
    let unbound = TestdParsingObservation::new(
        "parser:test",
        "parser-rev:test-1",
        TestdParsingStatus::Parsed,
        slot.evidence_identity_sha256.clone(),
        "readback receipt absent",
        false,
        ClockReading::default(),
    )
    .expect("observation builds");
    let slot_mut = reopened.bundles[0]
        .stdout
        .binding
        .as_mut()
        .expect("slot carries a binding");
    assert!(matches!(
        slot_mut.apply_parsing(&unbound),
        Err(TestdEvidenceError::ParserIncompatible { .. })
    ));
    let unevaluated = evaluate_observation(
        slot_mut,
        TestdEvaluationStatus::Pass,
        "artifact:test",
        false,
        7,
    );
    assert!(matches!(
        slot_mut.apply_evaluation(&unevaluated),
        Err(TestdEvidenceError::EvaluatorNotExecuted { .. })
    ));
    assert_eq!(slot_mut.evaluator.status, TestdEvaluationStatus::Unassessed);
}
