//! Acceptance proof for issue 1831: one-shot Rust semantic bridge.
//!
//! The smallest proof named under acceptance:
//! 1. a one-shot diagnostics request through the shared process layer returns
//!    a normalized result carrying the exact analyzer executable identity,
//!    configuration hash, candidate reference, freshness, and coverage;
//! 2. a rename request returns an unapplied edit candidate and modifies no
//!    files.
//!
//! Documentation routing: route `sha256:cef8c2c1…`, read `sha256:770ab430…`,
//! bundle `589015768a…` (29 required items read before mutation).

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::future::Future;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use eliot_contracts::{EpochId, EpochLineageId, sha256_hex};
use eliot_instrument_api::EvidenceAxes;
use eliot_lsp_bridge::{
    AnalyzerConfig, Coverage, FailureDisposition, Freshness, LspBridge, LspCommand,
    NormalizedResult, RUST_ANALYZER_EXECUTABLE, SemanticOperation, SourceCandidate,
    finalize_diagnostics, finalize_scip, rename_candidate,
};
use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, CancellationReceipt, DescendantEvidence, DispatchAuthorityId,
    DispatchPermitAuthority, DispatchValidationContext, EnvironmentProjection, EvidenceSinkError,
    ExitDisposition, ExitStatus, FencingToken, Generation, ImageId, JobId, KernelDispatchKey,
    OperationId, PermitIssuance, PhysicalProcessBinding, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessHealth,
    ProcessHealthStatus, ProcessId, ProcessIntent, ProcessRequest, ProcessStartReceipt,
    ProcessState, ProcessStreamEvidence, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamPrefixPreview, ProcessTreeId, ResourceLimits, SessionId, StreamEvidenceGap,
    StreamPersistenceStatus, StreamTransportStatus, SuspendedProcessIdentity,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const INVOKED_AT_MS: u64 = 1_786_000_000_000;

/// Real `rust-analyzer diagnostics` output captured from rust-analyzer 1.97.1
/// against a probe crate (progress noise plus one E0308 observation).
const SCRIPTED_DIAGNOSTICS: &str = "0/1 0% processing C:\\Temp\\ra-probe\\src\\main.rs\r\nat crate ra_probe, file C:\\Temp\\ra-probe\\src\\main.rs: Error RustcHardError(\"E0308\") from LineCol { line: 1, col: 17 } to LineCol { line: 1, col: 23 }: expected i32, found &'static str\r\ndiagnostic scan complete\r\n";

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
        NonZeroU64::new(1).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn revisions() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("authority".to_owned(), "a".repeat(64)),
        ("state".to_owned(), "b".repeat(64)),
    ])
}

fn process_request_for(
    executable: &str,
    argv: Vec<String>,
    cwd: &str,
) -> TestResult<ProcessRequest> {
    let generation = Generation::new(1)?;
    let intent = ProcessIntent::new(
        OperationId::new("operation-lsp-1")?,
        ProcessTreeId::new("tree-lsp-1")?,
        JobId::new("job-lsp-1")?,
        ImageId::new("image-lsp-1")?,
        SessionId::new("session-lsp-1")?,
        generation,
        executable,
        "a".repeat(64),
        argv,
        cwd,
        EnvironmentProjection::default(),
        ResourceLimits::new(5_000, Some(1_000), Some(1_048_576), 4_096, 4_096, 2)?,
    )?;
    let fence = FencingToken::new(test_epoch(), generation, "process-fence-lsp-1".to_owned())?;
    let mut authority = DispatchPermitAuthority::activate(
        DispatchAuthorityId::new("lsp-bridge-authority")?,
        KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
    );
    let permit = authority.issue(
        &intent,
        PermitIssuance::new(
            ActionLeaseRef::new("lsp-bridge-lease")?,
            fence,
            revisions(),
            100,
            10_000,
            "nonce-lsp-bridge-1",
        )?,
    )?;
    Ok(ProcessRequest::new(intent, permit)?)
}

fn observed_axes() -> TestResult<EvidenceAxes> {
    Ok(serde_json::from_value(serde_json::json!({
        "status": "OBSERVED",
        "assertability": "NON_ASSERTABLE_UNVERIFIED",
        "accessibility": "AVAILABLE",
        "influence": "ALLOWED",
        "physical": "PRESENT",
        "taint": "CLEAR"
    }))?)
}

fn evidence_with_stdout(
    request: ProcessRequest,
    stdout: &[u8],
    exit_code: i32,
) -> TestResult<(ProcessStartReceipt, ProcessEvidence)> {
    let intent = request.intent().clone();
    let fence = request.fence().clone();
    let mut authority = DispatchPermitAuthority::activate(
        DispatchAuthorityId::new("lsp-bridge-authority")?,
        KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
    );
    let _permit = authority.issue(
        &intent,
        PermitIssuance::new(
            ActionLeaseRef::new("lsp-bridge-lease")?,
            fence.clone(),
            revisions(),
            100,
            10_000,
            "nonce-lsp-bridge-1",
        )?,
    )?;
    let observed = SuspendedProcessIdentity::new(
        ProcessId::new("process-lsp-1")?,
        intent.process_tree_id().clone(),
        intent.job_id().clone(),
        intent.image_id().clone(),
        intent.session_id().clone(),
        intent.generation(),
        PhysicalProcessBinding::new(
            4242,
            11,
            intent.executable(),
            "Local\\Eliot-Lsp-Bridge-Test",
        )?,
        120,
        intent.executable_sha256(),
    )?;
    let clock: ClockObservation = serde_json::from_value(serde_json::json!({
        "valid_time_ms": 150,
        "known_time_ms": 150,
        "transaction_sequence": null,
        "monotonic_ns": 1
    }))?;
    let context = DispatchValidationContext::new(clock, fence, test_epoch(), revisions(), 41)?;
    let validated = authority.validate_and_consume(request, observed, &context)?;
    let mut state = ProcessState::from_validated(&validated);
    state.mark_resumed(
        151,
        ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)?,
    )?;
    // The start receipt binds the running state before the scripted exit.
    let receipt = ProcessStartReceipt::new(&state)?;
    let identity = state
        .view()
        .identity()
        .expect("running identity")
        .process_id()
        .clone();
    let descendants = DescendantEvidence::new(
        state.binding().clone(),
        identity,
        Vec::new(),
        false,
        false,
        None,
    )?;
    state.exit(
        ExitStatus::new(ExitDisposition::Completed, Some(exit_code), None, 202)?,
        descendants,
    )?;
    let view = state.view().clone();
    let preview =
        ProcessStreamPrefixPreview::from_transport_prefix(stdout.to_vec(), stdout.len() as u64)?;
    let stream = ProcessStreamEvidence::new_raw(
        view.binding().clone(),
        ProcessStreamKind::Stdout,
        ProcessStreamPolicyBinding::new(
            "test:policy",
            "test:privacy",
            "test:visibility",
            "test:retention",
            "test:redaction",
        )?,
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::SourceUnavailable,
        sha256_hex(stdout),
        stdout.len() as u64,
        preview,
        None,
        vec![StreamEvidenceGap::PersistenceUnavailable],
    )?;
    let evidence = ProcessEvidence::new_typed(view, Some(stream), None, observed_axes()?)?;
    Ok((receipt, evidence))
}

struct FakeExecutor {
    state: Mutex<FakeState>,
}

struct FakeState {
    starts: usize,
    stdout: Vec<u8>,
    exit_code: i32,
    evidence: Option<ProcessEvidence>,
    last_executable: Option<String>,
    last_argv: Vec<String>,
}

impl FakeExecutor {
    fn new(stdout: Vec<u8>, exit_code: i32) -> Self {
        Self {
            state: Mutex::new(FakeState {
                starts: 0,
                stdout,
                exit_code,
                evidence: None,
                last_executable: None,
                last_argv: Vec::new(),
            }),
        }
    }
}

impl ProcessExecutor for FakeExecutor {
    async fn start(
        &self,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        let (receipt, evidence) = {
            let mut state = self.state.lock().expect("executor lock");
            state.starts += 1;
            state.last_executable = Some(request.executable().to_owned());
            state.last_argv = request.argv().to_vec();
            let stdout = state.stdout.clone();
            let exit_code = state.exit_code;
            evidence_with_stdout(request, &stdout, exit_code)
                .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?
        };
        sink.record(evidence.clone())?;
        self.state.lock().expect("executor lock").evidence = Some(evidence);
        Ok(receipt)
    }

    async fn inspect(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        Err(ProcessExecutionError::NotFound)
    }

    async fn cancel(
        &self,
        _operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError> {
        Err(ProcessExecutionError::NotFound)
    }

    async fn reconcile(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        self.state
            .lock()
            .expect("executor lock")
            .evidence
            .clone()
            .ok_or(ProcessExecutionError::NotFound)
    }
}

#[derive(Default)]
struct RecordingSink {
    evidence: Mutex<Vec<ProcessEvidence>>,
}

impl ProcessEvidenceSink for RecordingSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        self.evidence
            .lock()
            .map_err(|_| EvidenceSinkError {
                message: "lock".to_owned(),
            })?
            .push(evidence);
        Ok(())
    }
}

fn test_candidate() -> SourceCandidate {
    SourceCandidate {
        workspace_root: "C:/Temp/ra-probe".to_owned(),
        path: Some("src/main.rs".to_owned()),
        symbol: None,
    }
}

fn test_config() -> AnalyzerConfig {
    AnalyzerConfig {
        executable: RUST_ANALYZER_EXECUTABLE.to_owned(),
        disable_build_scripts: false,
        disable_proc_macros: false,
        severity_minimum: None,
        scip_output_path: None,
    }
}

#[test]
fn one_shot_diagnostics_returns_normalized_result_with_receipt() -> TestResult {
    let config = test_config();
    let candidate = test_candidate();
    let command = LspCommand::diagnostics(&config, &candidate)?;
    assert_eq!(command.executable, RUST_ANALYZER_EXECUTABLE);

    let executor = Arc::new(FakeExecutor::new(
        SCRIPTED_DIAGNOSTICS.as_bytes().to_vec(),
        1,
    ));
    let bridge = LspBridge::new(executor.clone());
    let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink::default());
    let request = process_request_for(
        &command.executable,
        command.arguments.clone(),
        &command.working_directory,
    )?;

    // One-shot: exactly one process is launched and reconciled; no session.
    let operation = request.operation_id().clone();
    block_on(bridge.launch(&command, request, sink))?;
    let evidence = block_on(bridge.reconcile(&operation))?;
    assert_eq!(executor.state.lock().expect("lock").starts, 1);

    let stdout = LspBridge::<FakeExecutor>::stdout_bytes(&evidence).to_vec();
    assert_eq!(stdout, SCRIPTED_DIAGNOSTICS.as_bytes());
    assert!(LspBridge::<FakeExecutor>::completed(&evidence));
    assert_eq!(LspBridge::<FakeExecutor>::exit_code(&evidence), Some(1));

    let result = finalize_diagnostics(
        &config,
        &candidate,
        Some("rust-analyzer 1.97.1 (8bab26f4 2026-07-14)"),
        &stdout,
        false,
        LspBridge::<FakeExecutor>::exit_code(&evidence),
        LspBridge::<FakeExecutor>::completed(&evidence),
        INVOKED_AT_MS,
    );
    let NormalizedResult::Diagnostics {
        observations,
        receipt,
    } = result
    else {
        return Err("expected diagnostics result".into());
    };
    // Acceptance: exact analyzer identity, config hash, candidate ref,
    // freshness, and coverage on the receipt.
    assert_eq!(receipt.executable, RUST_ANALYZER_EXECUTABLE);
    assert_eq!(
        receipt.executable_version.as_deref(),
        Some("rust-analyzer 1.97.1 (8bab26f4 2026-07-14)")
    );
    assert_eq!(receipt.config_hash, config.config_hash());
    assert_eq!(receipt.candidate, candidate.reference());
    assert_eq!(receipt.invoked_at_unix_ms, INVOKED_AT_MS);
    assert_eq!(receipt.freshness, Freshness::Current);
    assert_eq!(
        receipt.coverage,
        Coverage::Workspace {
            root: "C:/Temp/ra-probe".to_owned()
        }
    );
    assert_eq!(receipt.disposition, FailureDisposition::Success);
    assert_eq!(receipt.tool_exit_code, Some(1));
    assert_eq!(receipt.output_handles.len(), 1);
    // The E0308 tool observation normalized; diagnostics stay observations.
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].code, "E0308");
    Ok(())
}

/// Minimal SCIP wire encoder (index/document/symbol/occurrence subset) for
/// the acceptance proof.
fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn tag(field: u32, wire: u8) -> Vec<u8> {
    varint(u64::from(field) << 3 | u64::from(wire))
}

fn field_bytes(field: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = tag(field, 2);
    out.extend(varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

fn field_varint(field: u32, value: u64) -> Vec<u8> {
    let mut out = tag(field, 0);
    out.extend(varint(value));
    out
}

/// Encodes a one-document SCIP index: symbol `test-symbol` defined at
/// (0,3) and referenced at (4,0) of `src/main.rs`.
fn scripted_scip_index() -> Vec<u8> {
    let mut symbol_msg = field_bytes(1, b"test-symbol");
    symbol_msg.extend(field_varint(2, 6));
    symbol_msg.extend(field_bytes(3, b"main"));

    let mut occurrences = Vec::new();
    for (line, col, roles) in [(0_u64, 3_u64, 1_u64), (4_u64, 0_u64, 0_u64)] {
        let mut range = varint(line);
        range.extend(varint(col));
        let mut occurrence = field_bytes(1, &range);
        occurrence.extend(field_bytes(2, b"test-symbol"));
        occurrence.extend(field_varint(3, roles));
        occurrences.extend(field_bytes(4, &occurrence));
    }

    let mut document = field_bytes(1, b"src/main.rs");
    document.extend(field_bytes(3, &symbol_msg));
    document.extend(occurrences);
    field_bytes(2, &document)
}

#[test]
fn rename_returns_unapplied_candidate_and_modifies_no_files() -> TestResult {
    // Witness file the bridge must never touch.
    let dir = std::env::temp_dir().join("eliot-lsp-bridge-rename-proof");
    std::fs::create_dir_all(&dir)?;
    let witness = dir.join("witness.rs");
    std::fs::write(&witness, "fn main_entry() {}\n")?;
    let before = std::fs::read(&witness)?;

    let index = eliot_instrument_scip::ScipIndex {
        documents: vec![eliot_instrument_scip::ScipDocument {
            relative_path: "src/main.rs".to_owned(),
            symbols: Vec::new(),
            occurrences: vec![
                eliot_instrument_scip::ScipOccurrence {
                    symbol: "rust-analyzer cargo ra_probe 0.1.0 main()".to_owned(),
                    line: 0,
                    column: 3,
                    roles: eliot_lsp_bridge::SCIP_ROLE_DEFINITION,
                },
                eliot_instrument_scip::ScipOccurrence {
                    symbol: "rust-analyzer cargo ra_probe 0.1.0 main()".to_owned(),
                    line: 4,
                    column: 0,
                    roles: 0,
                },
            ],
        }],
    };
    let candidate = rename_candidate(
        &index,
        "rust-analyzer cargo ra_probe 0.1.0 main()",
        "main_entry",
    )?;
    assert!(candidate.is_unapplied());
    assert!(!candidate.applied);
    assert_eq!(candidate.edits.len(), 2);

    // The same candidate through the SCIP finalize path decodes genuine
    // index bytes and stays unapplied.
    let config = AnalyzerConfig {
        scip_output_path: Some("C:/Temp/ra-probe/index.scip".to_owned()),
        ..test_config()
    };
    let owner = test_candidate();
    let operation = SemanticOperation::Rename {
        symbol: "test-symbol".to_owned(),
        new_name: "renamed_symbol".to_owned(),
    };
    let index_bytes = scripted_scip_index();
    let result = finalize_scip(
        &config,
        &owner,
        &operation,
        &index_bytes,
        "C:/Temp/ra-probe/index.scip",
        INVOKED_AT_MS,
    );
    let NormalizedResult::Rename {
        candidate: finalized_candidate,
        receipt,
    } = result
    else {
        return Err("expected rename result".into());
    };
    assert!(finalized_candidate.is_unapplied());
    assert!(!finalized_candidate.applied);
    assert_eq!(finalized_candidate.edits.len(), 2);
    assert_eq!(receipt.disposition, FailureDisposition::Success);
    assert_eq!(receipt.config_hash, config.config_hash());
    assert_eq!(receipt.candidate, owner.reference());
    assert!(matches!(receipt.coverage, Coverage::SingleSymbol { .. }));

    // No files were modified by either rename path.
    assert_eq!(std::fs::read(&witness)?, before);
    std::fs::remove_file(&witness)?;
    Ok(())
}
