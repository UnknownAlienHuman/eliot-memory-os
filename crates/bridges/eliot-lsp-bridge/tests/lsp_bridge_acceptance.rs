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
    NormalizedResult, RUST_ANALYZER_EXECUTABLE, ScipIndexerProvenance, ScipProjectionCache,
    SemanticOperation, SourceCandidate, finalize_diagnostics, finalize_scip, rename_candidate,
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
        None,
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

/// Acceptance proof for issue #1898: derived-cache reuse on the SCIP
/// finalize path (I2.22).
///
/// Fixture emission context stands in for sidecar-emitter observations: the
/// enforcement logic (exact closure match, trust authentication, content
/// integrity, rejection records) runs for real over real decode bytes and a
/// real configuration hash; only the emitter labels are fixtures, exactly
/// like registry test tool versions. No verdict exists anywhere on this
/// path: receipts are assembled fresh per call.
const PROOF_INDEXER: &str = "scip-indexer";
const PROOF_INDEXER_VERSION: &str = "0.0.0-fixture-emission";
const PROOF_PRODUCER: &str = "acceptance-sidecar-emitter";
const PROOF_ROOT: &str = "C:/Temp/ra-probe";
const PROOF_SIDECAR: &str = "C:/Temp/ra-probe/index.scip";

fn proof_provenance() -> ScipIndexerProvenance {
    ScipIndexerProvenance {
        indexer_name: PROOF_INDEXER.to_owned(),
        indexer_version: PROOF_INDEXER_VERSION.to_owned(),
        producer_id: PROOF_PRODUCER.to_owned(),
        producer_generation: 3,
        root_identity: PROOF_ROOT.to_owned(),
        root_acl_digest: sha256_hex(b"acceptance-root-acl-fixture"),
        root_disposition: eliot_build_test_graph::RootDisposition::Direct,
    }
}

fn proof_cache() -> TestResult<ScipProjectionCache> {
    let trust = eliot_build_test_graph::TrustPolicy::new(
        vec![PROOF_PRODUCER.to_owned()],
        vec![PROOF_ROOT.to_owned()],
    )?;
    Ok(ScipProjectionCache::new(
        eliot_build_test_graph::DerivedCacheStore::new(
            eliot_build_test_graph::CacheLimits::default(),
        ),
        trust,
        proof_provenance(),
    )?)
}

fn proof_setup() -> (AnalyzerConfig, SourceCandidate, SemanticOperation, Vec<u8>) {
    let config = AnalyzerConfig {
        scip_output_path: Some(PROOF_SIDECAR.to_owned()),
        ..test_config()
    };
    let owner = test_candidate();
    let operation = SemanticOperation::Definitions {
        symbol: "test-symbol".to_owned(),
    };
    (config, owner, operation, scripted_scip_index())
}

#[test]
fn scip_projection_cache_hit_skips_decode_with_fresh_receipts() -> TestResult {
    let (config, owner, operation, index_bytes) = proof_setup();
    let mut cache = proof_cache()?;

    // Cold call: genuine decode plus projection run, items publish.
    let cold = finalize_scip(
        &config,
        &owner,
        &operation,
        &index_bytes,
        PROOF_SIDECAR,
        INVOKED_AT_MS,
        Some(&mut cache),
    );
    let NormalizedResult::Definitions {
        items: cold_items,
        receipt: cold_receipt,
    } = cold
    else {
        return Err("expected definitions".into());
    };
    assert_eq!(cold_items.len(), 1);
    assert_eq!(cold_items[0].symbol, "test-symbol");
    assert_eq!((cold_items[0].line, cold_items[0].column), (0, 3));
    assert_eq!(cold_receipt.disposition, FailureDisposition::Success);
    assert_eq!(cache.decodes_performed(), 1);
    let Some(cold_telemetry) = cache.last_telemetry() else {
        return Err("telemetry recorded".into());
    };
    assert_eq!(cold_telemetry.cache_hit, Some(false));
    assert_eq!(cold_telemetry.target_identity, owner.reference());
    let cold_identity = cold_telemetry.cache_identity.clone();
    assert!(cold_identity.is_some());
    assert!(cache.rejected().is_empty());

    // Warm call: identical closure hits; decode and projection are skipped,
    // items are identical, and the receipt is freshly assembled.
    let warm = finalize_scip(
        &config,
        &owner,
        &operation,
        &index_bytes,
        PROOF_SIDECAR,
        INVOKED_AT_MS + 1,
        Some(&mut cache),
    );
    let NormalizedResult::Definitions {
        items: warm_items,
        receipt: warm_receipt,
    } = warm
    else {
        return Err("expected definitions".into());
    };
    assert_eq!(warm_items, cold_items);
    assert_eq!(cache.decodes_performed(), 1);
    assert_eq!(warm_receipt.disposition, FailureDisposition::Success);
    assert_eq!(warm_receipt.invoked_at_unix_ms, INVOKED_AT_MS + 1);
    assert_ne!(
        warm_receipt.invoked_at_unix_ms,
        cold_receipt.invoked_at_unix_ms
    );
    let Some(warm_telemetry) = cache.last_telemetry() else {
        return Err("telemetry recorded".into());
    };
    assert_eq!(warm_telemetry.cache_hit, Some(true));
    assert_eq!(warm_telemetry.cache_identity, cold_identity);
    assert_eq!(warm_telemetry.target_identity, owner.reference());
    assert_eq!(cache.counters().hits, 1);

    // No-cache path behaves identically to the cold path.
    let plain = finalize_scip(
        &config,
        &owner,
        &operation,
        &index_bytes,
        PROOF_SIDECAR,
        INVOKED_AT_MS + 2,
        None,
    );
    let NormalizedResult::Definitions {
        items: plain_items,
        receipt: plain_receipt,
    } = plain
    else {
        return Err("expected definitions".into());
    };
    assert_eq!(plain_items, cold_items);
    assert_eq!(plain_receipt.disposition, FailureDisposition::Success);
    assert_eq!(cache.decodes_performed(), 1);
    Ok(())
}

#[test]
fn scip_projection_cache_untrusted_producer_derives_for_real() -> TestResult {
    let (config, owner, operation, index_bytes) = proof_setup();
    let mut cache = proof_cache()?;

    let cold = finalize_scip(
        &config,
        &owner,
        &operation,
        &index_bytes,
        PROOF_SIDECAR,
        INVOKED_AT_MS,
        Some(&mut cache),
    );
    let NormalizedResult::Definitions {
        items: cold_items, ..
    } = cold
    else {
        return Err("expected definitions".into());
    };
    assert_eq!(cache.decodes_performed(), 1);
    assert_eq!(cache.counters().stores, 1);

    // An untrusted producer misses: the genuine derivation runs for real,
    // fresh items return, the rejection is recorded, and correctness never
    // depends on the cache.
    let mut evil = proof_provenance();
    evil.producer_id = "untrusted-emitter".to_owned();
    cache.reattest(evil)?;
    let outcome = finalize_scip(
        &config,
        &owner,
        &operation,
        &index_bytes,
        PROOF_SIDECAR,
        INVOKED_AT_MS + 1,
        Some(&mut cache),
    );
    let NormalizedResult::Definitions { items, receipt } = outcome else {
        return Err("expected definitions".into());
    };
    assert_eq!(items, cold_items);
    assert_eq!(cache.decodes_performed(), 2);
    assert_eq!(receipt.disposition, FailureDisposition::Success);
    let Some(outcome_telemetry) = cache.last_telemetry() else {
        return Err("telemetry recorded".into());
    };
    assert_eq!(outcome_telemetry.cache_hit, Some(false));
    let Some(last) = cache.rejected().pop() else {
        return Err("rejection recorded".into());
    };
    assert!(matches!(
        last.reason,
        eliot_build_test_graph::CacheRejectReason::UntrustedProducer
    ));

    // The valid entry survived the invalid attempt: it hits with no decode.
    cache.reattest(proof_provenance())?;
    let again = finalize_scip(
        &config,
        &owner,
        &operation,
        &index_bytes,
        PROOF_SIDECAR,
        INVOKED_AT_MS + 2,
        Some(&mut cache),
    );
    let NormalizedResult::Definitions {
        items: again_items, ..
    } = again
    else {
        return Err("expected definitions".into());
    };
    assert_eq!(again_items, cold_items);
    assert_eq!(cache.decodes_performed(), 2);
    let Some(again_telemetry) = cache.last_telemetry() else {
        return Err("telemetry recorded".into());
    };
    assert_eq!(again_telemetry.cache_hit, Some(true));
    Ok(())
}

#[test]
fn scip_projection_cache_malformed_input_never_publishes() -> TestResult {
    let (config, owner, operation, index_bytes) = proof_setup();
    let mut cache = proof_cache()?;

    let cold = finalize_scip(
        &config,
        &owner,
        &operation,
        &index_bytes,
        PROOF_SIDECAR,
        INVOKED_AT_MS,
        Some(&mut cache),
    );
    assert!(matches!(cold, NormalizedResult::Definitions { .. }));
    assert_eq!(cache.decodes_performed(), 1);
    assert_eq!(cache.counters().stores, 1);

    // Malformed input is never cached: it fails honestly on every call and
    // never publishes, so no poisoned entry can lodge.
    let bad = finalize_scip(
        &config,
        &owner,
        &operation,
        b"\xff",
        PROOF_SIDECAR,
        INVOKED_AT_MS + 3,
        Some(&mut cache),
    );
    let NormalizedResult::Definitions {
        items: bad_items,
        receipt: bad_receipt,
    } = bad
    else {
        return Err("expected definitions".into());
    };
    assert!(bad_items.is_empty());
    assert!(matches!(
        bad_receipt.disposition,
        FailureDisposition::ParseFailed { .. }
    ));
    assert_eq!(cache.decodes_performed(), 2);
    assert_eq!(cache.counters().stores, 1);
    let repeat = finalize_scip(
        &config,
        &owner,
        &operation,
        b"\xff",
        PROOF_SIDECAR,
        INVOKED_AT_MS + 4,
        Some(&mut cache),
    );
    let NormalizedResult::Definitions {
        items: repeat_items,
        ..
    } = repeat
    else {
        return Err("expected definitions".into());
    };
    assert!(repeat_items.is_empty());
    assert_eq!(cache.decodes_performed(), 3);
    assert_eq!(cache.counters().stores, 1);

    // Any changed closure element misses even when the bytes still decode.
    let mut changed = index_bytes.clone();
    let tail = changed.len() - 1;
    changed[tail] ^= 0x01;
    let before = cache.decodes_performed();
    let altered = finalize_scip(
        &config,
        &owner,
        &operation,
        &changed,
        PROOF_SIDECAR,
        INVOKED_AT_MS + 5,
        Some(&mut cache),
    );
    assert!(matches!(altered, NormalizedResult::Definitions { .. }));
    assert_eq!(cache.decodes_performed(), before + 1);
    let Some(altered_telemetry) = cache.last_telemetry() else {
        return Err("telemetry recorded".into());
    };
    assert_eq!(altered_telemetry.cache_hit, Some(false));
    Ok(())
}
