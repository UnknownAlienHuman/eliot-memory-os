use super::provider_terminalization::{
    record_post_dispatch_supervisor_failure, record_terminal_process,
    terminalize_historical_unknown,
};
use super::supervised_process::{
    ChildCriticality, ProcessRestartPolicy, RestartStrategy, SupervisedChildKind,
    SupervisedProcessSpec, run_supervised_process,
};
use super::*;
use eliot_engine::adapter::BoxAdapterFuture;
use eliot_engine::runtime_supervision::AdapterExecutionContext;
use eliot_engine::{
    Adapter, AdapterRegistry, AdapterSupervisor, AntigravityCommandInput, ClaudeCodeCommandInput,
    ExternalResultCompletenessService, OpenCodeCommandInput, ProviderCallCampaignRequest,
    ProviderCallReservationDecision, ProviderCallReservationOwner, ProviderCallReservationRequest,
    ProviderCommandPlan, ProviderCompletenessInput, ProviderInvocationJournal, ProviderOutputSpool,
    ProviderProcessOutcome, ProviderProcessRunner, ProviderProcessSpec,
    ProviderReconciliationInput, ProviderReconciliationService, ProviderTerminalResult,
    build_antigravity_command, build_claude_code_command, build_opencode_command,
    parse_antigravity_output, parse_claude_code_stream, parse_opencode_stream,
    seal_provider_runtime_contract, validate_external_agent_execution_request,
};
use eliot_types::{
    AdapterAuthorityProfile, AdapterCapability, AdapterClass, AdapterError, AdapterHealth,
    AdapterLimits, AdapterObservation, AdapterRequest, AdapterResult, AdapterResultStatus,
    AdapterState, AgentResultEnvelope, AgentResultStatus, AgentRole, ExternalAgentExecutionRequest,
    ExternalAgentPurpose, OperationJobState, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
    ProcessExecutionPolicy, ProviderCallLedger, ProviderCallReservationState,
    ProviderExecutionEvidence, ProviderIdentityCheck, ProviderInvocationAttempt,
    ProviderInvocationState, ProviderMcpServerContract, ProviderReconciliationMethod,
    ProviderRuntimeContract, ProviderStructuredOutputMode, ProviderTimeoutClass, TaintClass,
};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::os::windows::process::ExitStatusExt as _;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

const MAX_PROVIDER_OUTPUT_BYTES: u64 = 1_048_576;
const MAX_MCP_REFERENCE_OUTPUT_BYTES: u64 = 1_048_576;
const MCP_REFERENCE_TIMEOUT: Duration = Duration::from_secs(20);
const MCP_SMOKE_PRE_PROVIDER_TIMEOUT: Duration = Duration::from_secs(60);
const PROVIDER_CLEANUP_GRACE_SECONDS: u64 = 15;
const EXTERNAL_ADAPTER_VERSION: &str = "eliot-external-agent-adapter-v1";
const MCP_SMOKE_PHASE_SCHEMA_VERSION: &str = "eliot-external-agent-smoke-phase-v1";
const SAFE_INHERITED_ENVIRONMENT: &[&str] = &[
    "SystemRoot",
    "WINDIR",
    "ComSpec",
    "PATH",
    "PATHEXT",
    "USERPROFILE",
    "HOME",
    "LOCALAPPDATA",
    "APPDATA",
    "TEMP",
    "TMP",
];

#[derive(Clone)]
struct ExternalAgentAdapterCore {
    host: AgentHostId,
    adapter_id: String,
    executable: Option<PathBuf>,
    version: Option<String>,
    governor_executable: PathBuf,
    config_path: PathBuf,
    manifest: eliot_types::CapabilityManifest,
    process_runner: Arc<dyn ProviderProcessRunner>,
    authority_boundary: Arc<dyn ExternalAgentAuthorityBoundary>,
}

trait ExternalAgentAuthorityBoundary: Send + Sync {
    fn ensure_dispatch_safe<'a>(&'a self, config_path: &'a Path) -> BoxAdapterFuture<'a, ()>;

    fn enqueue<'a>(
        &'a self,
        config_path: &'a Path,
        host: AgentHostId,
        execution: &'a ExternalAgentExecutionRequest,
    ) -> BoxAdapterFuture<'a, String>;

    fn start<'a>(&'a self, config_path: &'a Path, job_id: &'a str) -> BoxAdapterFuture<'a, ()>;

    fn canonicalize<'a>(
        &'a self,
        config_path: &'a Path,
        execution: &'a ExternalAgentExecutionRequest,
        result: AgentResultEnvelope,
    ) -> BoxAdapterFuture<'a, AgentResultEnvelope>;
}

struct ProductionExternalAgentAuthorityBoundary;

impl ExternalAgentAuthorityBoundary for ProductionExternalAgentAuthorityBoundary {
    fn ensure_dispatch_safe<'a>(&'a self, config_path: &'a Path) -> BoxAdapterFuture<'a, ()> {
        Box::pin(async move {
            let runtime_store =
                super::supervised_process::daemon_operation_runtime_handle_for_instance(
                    config_path,
                    Some(DEFAULT_INSTANCE_NAME),
                )
                .map_err(anyhow_engine)?;
            let runtime_integrity =
                crate::runtime_integrity::inspect(config_path, &runtime_store, true, None)
                    .await
                    .map_err(anyhow_engine)?;
            if !runtime_integrity.provider_dispatch_safe {
                return Err(eliot_engine::EngineError::WriteRejected(format!(
                    "runtime integrity blocks external provider dispatch: {}",
                    runtime_integrity.integrity_errors.join(", ")
                )));
            }
            Ok(())
        })
    }

    fn enqueue<'a>(
        &'a self,
        config_path: &'a Path,
        host: AgentHostId,
        execution: &'a ExternalAgentExecutionRequest,
    ) -> BoxAdapterFuture<'a, String> {
        Box::pin(enqueue_external_agent_broker_invocation(
            config_path,
            host,
            execution,
        ))
    }

    fn start<'a>(&'a self, config_path: &'a Path, job_id: &'a str) -> BoxAdapterFuture<'a, ()> {
        Box::pin(start_external_agent_broker_job(config_path, job_id))
    }

    fn canonicalize<'a>(
        &'a self,
        config_path: &'a Path,
        execution: &'a ExternalAgentExecutionRequest,
        result: AgentResultEnvelope,
    ) -> BoxAdapterFuture<'a, AgentResultEnvelope> {
        Box::pin(canonicalize_external_agent_broker_result(
            config_path,
            execution,
            result,
        ))
    }
}

#[derive(Clone)]
pub(crate) struct ClaudeCodeCliAdapter {
    core: ExternalAgentAdapterCore,
}

#[derive(Clone)]
pub(crate) struct AntigravityCliAdapter {
    core: ExternalAgentAdapterCore,
}

#[derive(Clone)]
pub(crate) struct OpenCodeCliAdapter {
    core: ExternalAgentAdapterCore,
}

#[derive(Clone, Debug)]
pub(crate) struct ExternalAgentRuntimePreview {
    pub adapter_id: String,
    pub adapter_version: String,
    pub runtime_contract: ProviderRuntimeContract,
}

struct PreparedExternalAgentExecution {
    executable: PathBuf,
    provider_hash_before: String,
    schema: Value,
    cwd: PathBuf,
    plan: ProviderCommandPlan,
    environment: BTreeMap<String, String>,
    runtime_contract: ProviderRuntimeContract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimePreparationMode {
    Preview,
    Dispatch,
}

struct CanonicalAgentResultWrite {
    key: String,
    receipt_kind: &'static str,
    body: Value,
}

pub(crate) fn production_external_agent_supervisor(
    config_path: &Path,
) -> Result<AdapterSupervisor> {
    let provider_runtime = super::ProviderRuntime::production(config_path)?;
    external_agent_supervisor(config_path, &provider_runtime)
}

fn external_agent_supervisor(
    config_path: &Path,
    provider_runtime: &super::ProviderRuntime,
) -> Result<AdapterSupervisor> {
    let governor_executable = resolved_governor_executable()?;
    let process_runner = provider_runtime.runner();
    let mut registry = AdapterRegistry::new();
    registry.register(ClaudeCodeCliAdapter::new(
        config_path,
        &governor_executable,
        Arc::clone(&process_runner),
    )?)?;
    registry.register(AntigravityCliAdapter::new(
        config_path,
        &governor_executable,
        Arc::clone(&process_runner),
    )?)?;
    registry.register(OpenCodeCliAdapter::new(
        config_path,
        &governor_executable,
        process_runner,
    )?)?;
    Ok(AdapterSupervisor::with_runtime(
        registry,
        provider_runtime.operation_runtime(),
    ))
}

pub(crate) async fn half_open_external_agent_circuit(
    config_path: &Path,
    requested_adapter_id: &str,
) -> Result<Value> {
    anyhow::ensure!(
        matches!(
            requested_adapter_id,
            "external-agent:claude" | "external-agent:antigravity" | "external-agent:opencode"
        ),
        "adapter is not in the bounded external-agent inventory"
    );
    let supervisor = production_external_agent_supervisor(config_path)?;
    let health = supervisor.half_open_probe(requested_adapter_id).await;
    anyhow::ensure!(
        health.healthy && !health.circuit_open,
        "external adapter half-open probe failed: {}",
        health.message
    );
    Ok(json!({
        "schema_version": "eliot-external-agent-circuit-probe-v1",
        "adapter_id": requested_adapter_id,
        "status": "closed",
        "provider_calls": 0,
        "health": health,
    }))
}

pub(crate) fn prepare_external_agent_runtime(
    config_path: &Path,
    host: AgentHostId,
    execution: &ExternalAgentExecutionRequest,
) -> Result<ExternalAgentRuntimePreview> {
    anyhow::ensure!(
        host != AgentHostId::Codex,
        "Codex does not use an external-agent adapter"
    );
    validate_external_agent_execution_request(execution)?;
    let process_runner = super::ProviderRuntime::production(config_path)?.runner();
    let core = ExternalAgentAdapterCore::new(
        host,
        config_path,
        &resolved_governor_executable()?,
        process_runner,
    )?;
    let prepared = core.prepare_governed(execution, RuntimePreparationMode::Preview)?;
    Ok(ExternalAgentRuntimePreview {
        adapter_id: core.adapter_id,
        adapter_version: core.manifest.version,
        runtime_contract: prepared.runtime_contract,
    })
}

pub(crate) fn external_agent_blob_path(config_path: &Path, reference: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        !reference.trim().is_empty(),
        "external-agent blob reference is empty"
    );
    let root = runtime_root(config_path);
    let root = std::fs::canonicalize(&root).with_context(|| {
        format!(
            "canonicalize external-agent runtime root {}",
            root.display()
        )
    })?;
    let path = std::fs::canonicalize(root.join(reference))
        .with_context(|| format!("resolve external-agent blob {reference}"))?;
    anyhow::ensure!(
        path.starts_with(&root) && path.is_file(),
        "external-agent blob escaped its runtime root"
    );
    Ok(path)
}

fn resolved_governor_executable() -> Result<PathBuf> {
    let executable =
        std::env::var_os("ELIOT_GOVERNOR_EXE").map_or(std::env::current_exe()?, PathBuf::from);
    std::fs::canonicalize(&executable)
        .with_context(|| format!("canonicalize Governor executable {}", executable.display()))
}

pub(crate) async fn dispatch(
    config_path: &Path,
    command: crate::ExternalAgentCommand,
) -> Result<()> {
    match command {
        crate::ExternalAgentCommand::Doctor { host } => {
            let host = parse_host(&host)?;
            anyhow::ensure!(
                host != AgentHostId::Codex,
                "Codex is not an external adapter"
            );
            let supervisor = production_external_agent_supervisor(config_path)?;
            let adapter_id = adapter_id(host);
            let health = supervisor.health_probe(adapter_id).await;
            let manifest = supervisor.registry().inspect(adapter_id)?;
            let mcp_preflight = mcp_reference_exchange(
                config_path,
                None,
                Some(host),
                None,
                None,
                None,
                "doctor_mcp",
            )
            .await
            .map_or_else(
                |error| {
                    json!({
                        "passed": false,
                        "error": error.to_string(),
                    })
                },
                |value| {
                    json!({
                        "passed": true,
                        "tool_names": value.tool_names,
                        "raw_database_absent": value.raw_database_absent,
                    })
                },
            );
            write_json(&json!({
                "schema_version": "eliot-external-agent-doctor-v1",
                "host": host,
                "adapter_id": adapter_id,
                "manifest": manifest,
                "health": health,
                "installed": health.healthy,
                "provider_authenticated": false,
                "exact_model_selectable": false,
                "mcp_preflight": mcp_preflight,
                "structured_output_ready": false,
                "console_headless_ready": false,
                "model_calls": 0,
                "note": "static doctor cannot attest authentication, exact model resolution, or structured cognition"
            }))
        }
        crate::ExternalAgentCommand::AuthSmoke { host, model } => {
            let host = parse_host(&host)?;
            let report = run_auth_smoke(config_path, host, &model).await?;
            write_json(&report)
        }
        crate::ExternalAgentCommand::McpSmoke { host, model } => {
            let host = parse_host(&host)?;
            let report = Box::pin(run_mcp_smoke(config_path, host, &model)).await?;
            write_json(&report)
        }
        crate::ExternalAgentCommand::McpPreflight { host, model } => {
            let host = parse_host(&host)?;
            let report = Box::pin(run_mcp_preflight(config_path, host, &model)).await?;
            write_json(&report)
        }
        crate::ExternalAgentCommand::Inspect { invocation } => {
            anyhow::ensure!(
                !invocation.trim().is_empty()
                    && !invocation.contains(['/', '\\'])
                    && invocation != "."
                    && invocation != "..",
                "invalid external-agent invocation ID"
            );
            let journal = ProviderInvocationJournal::new(runtime_root(config_path));
            let direct = journal.load(&invocation);
            let attempt = direct
                .or_else(|_| journal.load(&format!("external-agent-attempt-{invocation}")))?;
            write_json(&attempt)
        }
        crate::ExternalAgentCommand::Reconcile {
            invocation,
            dry_run,
        } => {
            let result =
                reconcile_historical_provider_attempt(config_path, &invocation, dry_run).await?;
            write_json(&result)
        }
    }
}

async fn reconcile_historical_provider_attempt(
    config_path: &Path,
    invocation: &str,
    dry_run: bool,
) -> Result<Value> {
    validate_invocation_component(invocation)?;
    let root = runtime_root(config_path);
    let journal = ProviderInvocationJournal::new(&root);
    let mut attempt = journal
        .load(invocation)
        .or_else(|_| journal.load(&format!("external-agent-attempt-{invocation}")))?;
    anyhow::ensure!(
        attempt.provider == "antigravity",
        "historical provider reconciliation is bounded to Antigravity"
    );
    ensure_historical_process_facts_absent(&attempt)?;
    let attempt_path = root.join("runtime/provider-invocations").join(format!(
        "{}.json",
        safe_component(&attempt.invocation_attempt_id)
    ));
    let resolution_relative = format!(
        "runtime/provider-invocation-reconciliation/{}.resolution.json",
        safe_component(&attempt.invocation_attempt_id)
    );
    let resolution_path = root.join(&resolution_relative);
    if resolution_path.exists() {
        let resolution = read_json_value(&resolution_path)?;
        validate_existing_resolution(&resolution, &attempt.invocation_attempt_id)?;
        if dry_run {
            return Ok(json!({
                "status": "dry_run_existing_resolution",
                "provider_calls": 0,
                "provider_redispatch_forbidden": true,
                "resolution_ref": resolution_relative,
                "resolution": resolution,
                "attempt": attempt,
            }));
        }
        terminalize_historical_unknown(&journal, &mut attempt, &resolution_relative)?;
        ensure_historical_process_facts_absent(&attempt)?;
        return Ok(json!({
            "status": "idempotent_replay",
            "provider_calls": 0,
            "provider_redispatch_forbidden": true,
            "resolution_ref": resolution_relative,
            "resolution": resolution,
            "attempt": attempt,
        }));
    }

    let source_attempt_bytes = std::fs::read(&attempt_path)?;
    let evidence = collect_historical_reconciliation_evidence(
        config_path,
        &root,
        &attempt,
        &source_attempt_bytes,
    )
    .await?;
    let resolution = build_historical_resolution(&attempt, &source_attempt_bytes, &evidence)?;
    if dry_run {
        return Ok(json!({
            "status": "dry_run",
            "provider_calls": 0,
            "provider_redispatch_forbidden": true,
            "would_write_resolution_ref": resolution_relative,
            "would_transition_to": "NON_RECONCILABLE_UNKNOWN",
            "resolution": resolution,
            "attempt": attempt,
        }));
    }
    crate::runtime_instance::atomic_write_json(&resolution_path, &resolution)?;
    terminalize_historical_unknown(&journal, &mut attempt, &resolution_relative)?;
    ensure_historical_process_facts_absent(&attempt)?;
    Ok(json!({
        "status": "reconciled",
        "provider_calls": 0,
        "provider_redispatch_forbidden": true,
        "resolution_ref": resolution_relative,
        "resolution": resolution,
        "attempt": attempt,
    }))
}

fn build_historical_resolution(
    attempt: &ProviderInvocationAttempt,
    source_attempt_bytes: &[u8],
    evidence: &Value,
) -> Result<Value> {
    let completeness = ExternalResultCompletenessService.evaluate(ProviderCompletenessInput {
        receipt_id: format!(
            "provider-completeness:historical:{}",
            attempt.invocation_attempt_id
        ),
        invocation_attempt_ref: attempt.invocation_attempt_id.clone(),
        raw_output_ref: None,
        expected_schema: "unknown_historical_provider_output".to_owned(),
        terminal_marker_or_protocol_status: None,
        required_fields_present: false,
        truncation_detected: false,
        stream_closed_cleanly: false,
        process_exit_success: false,
    });
    let evidence_refs = reconciliation_evidence_refs(evidence)?;
    let result = ProviderReconciliationService.reconcile(ProviderReconciliationInput {
        reconciliation_id: format!(
            "provider-reconciliation:historical:{}",
            attempt.invocation_attempt_id
        ),
        outcome_id: format!(
            "provider-outcome:historical:{}",
            attempt.invocation_attempt_id
        ),
        invocation_attempt_ref: attempt.invocation_attempt_id.clone(),
        methods_attempted: vec![
            ProviderReconciliationMethod::LocalWal,
            ProviderReconciliationMethod::RawOutputSpool,
            ProviderReconciliationMethod::ProcessExitRecord,
            ProviderReconciliationMethod::JobObjectRecord,
            ProviderReconciliationMethod::AdapterLog,
        ],
        identity_checks: historical_identity_checks(attempt, evidence)?,
        recovered_artifacts: Vec::new(),
        mismatched_artifacts_quarantined: Vec::new(),
        completeness,
        recovered_review_id: None,
        terminal_failure_proven: false,
        terminal_failure_class: None,
        dispatch_proven: true,
        slot_consumed: true,
        raw_output_preserved: false,
        timeout_class: Some(ProviderTimeoutClass::FirstOutputTimeout),
        exact_failure_evidence_refs: evidence_refs.clone(),
        unresolved_questions: vec![
            "historical process exit timestamp was not persisted".to_owned(),
            "historical cleanup timestamp and ProcessReapReceipt were not persisted".to_owned(),
            "provider-side outcome and output remain unknown".to_owned(),
        ],
        verifier_refs: evidence_refs,
        started_at: OffsetDateTime::now_utc(),
        completed_at: OffsetDateTime::now_utc(),
    });
    anyhow::ensure!(
        result.outcome.effective_state == ProviderInvocationState::NonReconcilableUnknown
            && !result.record.provider_generating_call_performed
            && !result.outcome.retry_same_campaign_allowed
            && result.record.review_id_if_recovered.is_none(),
        "historical reconciliation did not resolve fail-closed"
    );
    Ok(json!({
        "schema_version": "provider-historical-reconciliation-v1",
        "invocation_attempt_id": attempt.invocation_attempt_id,
        "source_attempt_sha256": sha256_bytes(source_attempt_bytes),
        "provider_redispatch_forbidden": true,
        "provider_calls": 0,
        "process_facts_synthesized": false,
        "reconciliation": result.record,
        "outcome": result.outcome,
        "evidence": evidence,
    }))
}

fn validate_invocation_component(invocation: &str) -> Result<()> {
    anyhow::ensure!(
        !invocation.trim().is_empty()
            && !invocation.contains(['/', '\\'])
            && invocation != "."
            && invocation != "..",
        "invalid external-agent invocation ID"
    );
    Ok(())
}

fn ensure_historical_process_facts_absent(attempt: &ProviderInvocationAttempt) -> Result<()> {
    anyhow::ensure!(
        matches!(
            attempt
                .state_transitions
                .last()
                .map(|transition| transition.to),
            Some(
                ProviderInvocationState::Running
                    | ProviderInvocationState::TimeoutPendingReconciliation
                    | ProviderInvocationState::NonReconcilableUnknown
            )
        ),
        "attempt is not a historical post-dispatch unknown outcome"
    );
    anyhow::ensure!(
        attempt.first_output_at.is_none()
            && attempt.last_output_at.is_none()
            && attempt.process_exit_at.is_none()
            && attempt.cleanup_completed_at.is_none()
            && attempt.stdout_blob_or_hash.is_none()
            && attempt.stderr_blob_or_hash.is_none()
            && attempt.structured_output_blob_or_hash.is_none()
            && attempt.exit_code_or_signal.is_none()
            && attempt.process_reap_receipt.is_none()
            && attempt.process_timed_out.is_none()
            && attempt.process_cancelled.is_none()
            && attempt.process_worker_error.is_none()
            && attempt.stdout_total_bytes.is_none()
            && attempt.stderr_total_bytes.is_none()
            && attempt.stdout_truncated.is_none()
            && attempt.stderr_truncated.is_none(),
        "attempt contains process or output facts and requires a different reconciliation path"
    );
    Ok(())
}

async fn collect_historical_reconciliation_evidence(
    config_path: &Path,
    root: &Path,
    attempt: &ProviderInvocationAttempt,
    source_attempt_bytes: &[u8],
) -> Result<Value> {
    let pid = historical_attempt_pid(attempt)?;
    let process_alive = eliot_windows_ipc::process_is_alive(pid)?;
    anyhow::ensure!(
        !process_alive,
        "historical provider PID {pid} is still alive"
    );
    let smoke_id = attempt
        .external_invocation_ref
        .as_deref()
        .and_then(|value| value.strip_prefix("external-agent-attempt-"))
        .context("historical attempt has no exact external invocation reference")?;
    let ledger = historical_ledger_evidence(root, attempt)?;
    let (broker, authority) = historical_broker_evidence(root, smoke_id)?;
    let adapter_log = historical_adapter_log_evidence(root, smoke_id)?;
    let spool_path = root
        .join("spool/provider-invocations")
        .join(safe_component(&attempt.invocation_attempt_id));
    anyhow::ensure!(
        !directory_contains_file(&spool_path)?,
        "historical attempt has raw spool artifacts and requires exact output reconciliation"
    );

    let runtime_value = historical_runtime_snapshot(config_path).await?;
    Ok(json!({
        "source_attempt": {
            "path": relative_evidence_path(root, &root.join("runtime/provider-invocations").join(format!("{}.json", safe_component(&attempt.invocation_attempt_id))))?,
            "sha256": sha256_bytes(source_attempt_bytes),
            "last_transition": attempt.state_transitions.last(),
        },
        "provider_call_ledger": ledger,
        "host_broker": broker,
        "authority_revocation": authority,
        "adapter_log": adapter_log,
        "raw_output_spool": {
            "path": relative_evidence_path(root, &spool_path)?,
            "artifacts_present": false,
        },
        "process_exit_record": {
            "pid": pid,
            "alive_at_reconciliation": false,
            "exit_timestamp_known": false,
            "exit_code_known": false,
            "captured_at": OffsetDateTime::now_utc(),
        },
        "job_object_record": {
            "historical_receipt_present": false,
            "process_reap_receipt_synthesized": false,
        },
        "runtime_supervision_snapshot": runtime_value,
    }))
}

fn historical_ledger_evidence(root: &Path, attempt: &ProviderInvocationAttempt) -> Result<Value> {
    let path = root.join("runtime/provider-call-ledger.json");
    let bytes = std::fs::read(&path)?;
    let ledger: ProviderCallLedger = serde_json::from_slice(&bytes)?;
    let reservation = ledger
        .reservations
        .into_iter()
        .find(|reservation| reservation.reservation_id == attempt.reservation_id)
        .context("historical provider reservation is absent")?;
    anyhow::ensure!(
        reservation.state == ProviderCallReservationState::UnknownOutcome
            && reservation.consumes_budget
            && reservation.terminal_at.is_some()
            && reservation.external_invocation_ref.as_deref()
                == attempt.external_invocation_ref.as_deref(),
        "historical provider reservation is not a consumed terminal unknown outcome"
    );
    Ok(json!({
        "path": relative_evidence_path(root, &path)?,
        "sha256": sha256_bytes(&bytes),
        "reservation": reservation,
    }))
}

fn historical_broker_evidence(root: &Path, smoke_id: &str) -> Result<(Value, Value)> {
    let path = root.join("reports/host-broker/latest.json");
    let bytes = std::fs::read(&path)?;
    let broker = serde_json::from_slice::<Value>(&bytes)?;
    let operation_job = find_array_object(&broker, "operation_jobs", "job_id", smoke_id)?;
    anyhow::ensure!(
        operation_job["state"] == "failed"
            && operation_job["phase"] == "failed"
            && operation_job["restart_count"] == 0,
        "historical HostBroker operation is not a non-restarted terminal failure"
    );
    let host_session = find_array_object(&broker, "host_sessions", "owner_operation_id", smoke_id)?;
    anyhow::ensure!(
        host_session["state"] == "retired",
        "historical HostBroker session is not retired"
    );
    let role_lease_id = operation_job["role_lease_id"]
        .as_str()
        .context("historical operation has no role lease")?;
    let authority = find_authority_revocation(root, role_lease_id, smoke_id)?;
    Ok((
        json!({
            "path": relative_evidence_path(root, &path)?,
            "sha256": sha256_bytes(&bytes),
            "operation_job": operation_job,
            "host_session": host_session,
        }),
        authority,
    ))
}

fn historical_adapter_log_evidence(root: &Path, smoke_id: &str) -> Result<Value> {
    let path = root
        .join("external-agent-smokes")
        .join(smoke_id)
        .join("phases.jsonl");
    let bytes = std::fs::read(&path)?;
    let (line, entry) = historical_timeout_phase(&bytes)?;
    Ok(json!({
        "path": relative_evidence_path(root, &path)?,
        "sha256": sha256_bytes(&bytes),
        "line": line,
        "entry": entry,
    }))
}

async fn historical_runtime_snapshot(config_path: &Path) -> Result<Value> {
    let runtime_store = super::supervised_process::daemon_operation_runtime_handle(config_path)?;
    let report = crate::runtime_integrity::inspect(config_path, &runtime_store, true, None).await?;
    let value = serde_json::to_value(report)?;
    for field in [
        "active",
        "stuck",
        "awaiting_reconciliation",
        "cleanup_pending",
        "orphan_processes",
    ] {
        anyhow::ensure!(
            value["operations"][field] == 0,
            "runtime supervision is not clean at field {field}"
        );
    }
    anyhow::ensure!(
        value["runtime_integrity"]["clean"] == true,
        "runtime integrity is not clean"
    );
    Ok(value)
}

fn historical_attempt_pid(attempt: &ProviderInvocationAttempt) -> Result<u32> {
    let identity = attempt
        .process_or_job_identity
        .as_deref()
        .context("historical attempt has no process identity")?;
    identity
        .strip_prefix("pid:")
        .and_then(|value| value.split(';').next())
        .context("historical attempt process identity is malformed")?
        .parse()
        .context("historical attempt PID is malformed")
}

fn find_array_object(value: &Value, array: &str, key: &str, expected: &str) -> Result<Value> {
    value[array]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item[key].as_str() == Some(expected))
        })
        .cloned()
        .with_context(|| format!("{array} has no exact {key}={expected}"))
}

fn find_authority_revocation(root: &Path, role_lease_id: &str, smoke_id: &str) -> Result<Value> {
    let authority_root = root.join("reports/role-lease-authority");
    let mut paths = std::fs::read_dir(&authority_root)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        let bytes = std::fs::read(&path)?;
        let value = serde_json::from_slice::<Value>(&bytes)?;
        if value["role_lease_id"].as_str() == Some(role_lease_id)
            && value["close_idempotency_key"]
                .as_str()
                .is_some_and(|key| key.contains(smoke_id))
            && value["canonical_revoked_role_receipt"].is_object()
            && value["canonical_retired_binding_receipt"].is_object()
            && value["canonical_terminal_job_receipt"].is_object()
        {
            return Ok(json!({
                "path": relative_evidence_path(root, &path)?,
                "sha256": sha256_bytes(&bytes),
                "receipt": value,
            }));
        }
    }
    anyhow::bail!("canonical authority revocation receipt is absent")
}

fn historical_timeout_phase(bytes: &[u8]) -> Result<(usize, Value)> {
    String::from_utf8_lossy(bytes)
        .lines()
        .enumerate()
        .find_map(|(index, line)| {
            let value = serde_json::from_str::<Value>(line).ok()?;
            let detail = value["detail"].as_str().unwrap_or_default();
            (value["status"] == "failed"
                && detail.contains("first output deadline exceeded")
                && detail.contains("no ProviderExecutionEvidence"))
            .then_some((index + 1, value))
        })
        .context("historical first-output timeout adapter evidence is absent")
}

fn directory_contains_file(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() || entry.file_type()?.is_dir() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn relative_evidence_path(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .with_context(|| format!("evidence path {} escaped runtime root", path.display()))?
        .to_string_lossy()
        .replace('\\', "/"))
}

fn reconciliation_evidence_refs(evidence: &Value) -> Result<Vec<String>> {
    let mut refs = Vec::new();
    for key in [
        "source_attempt",
        "provider_call_ledger",
        "host_broker",
        "authority_revocation",
        "adapter_log",
        "raw_output_spool",
    ] {
        let path = evidence[key]["path"]
            .as_str()
            .with_context(|| format!("reconciliation evidence {key} has no path"))?;
        refs.push(path.to_owned());
    }
    refs.push("embedded:process_exit_record:attempted-and-absent".to_owned());
    refs.push("embedded:job_object_record:attempted-and-absent".to_owned());
    refs.push("embedded:runtime_supervision_snapshot".to_owned());
    Ok(refs)
}

fn historical_identity_checks(
    attempt: &ProviderInvocationAttempt,
    evidence: &Value,
) -> Result<Vec<ProviderIdentityCheck>> {
    let reservation = &evidence["provider_call_ledger"]["reservation"];
    let job = &evidence["host_broker"]["operation_job"];
    let check = |field: &str, expected: String, observed: String, evidence_ref: &str| {
        ProviderIdentityCheck {
            field: field.to_owned(),
            matched: Some(expected == observed),
            expected: Some(expected),
            observed: Some(observed),
            evidence_ref: evidence_ref.to_owned(),
        }
    };
    let mut checks = vec![
        check(
            "provider",
            attempt.provider.clone(),
            reservation["provider"]
                .as_str()
                .context("reservation provider missing")?
                .to_owned(),
            "provider_call_ledger",
        ),
        check(
            "reservation_id",
            attempt.reservation_id.clone(),
            reservation["reservation_id"]
                .as_str()
                .context("reservation ID missing")?
                .to_owned(),
            "provider_call_ledger",
        ),
        check(
            "campaign_id",
            attempt.campaign_id.clone(),
            reservation["campaign_id"]
                .as_str()
                .context("campaign ID missing")?
                .to_owned(),
            "provider_call_ledger",
        ),
        check(
            "idempotency_key",
            attempt.idempotency_key.clone(),
            reservation["idempotency_key"]
                .as_str()
                .context("idempotency key missing")?
                .to_owned(),
            "provider_call_ledger",
        ),
        check(
            "external_invocation_ref",
            attempt
                .external_invocation_ref
                .clone()
                .context("external invocation ref missing")?,
            reservation["external_invocation_ref"]
                .as_str()
                .context("reservation external invocation missing")?
                .to_owned(),
            "provider_call_ledger",
        ),
        check(
            "broker_invocation",
            attempt
                .external_invocation_ref
                .as_deref()
                .and_then(|value| value.strip_prefix("external-agent-attempt-"))
                .context("broker invocation identity missing")?
                .to_owned(),
            job["invocation_id"]
                .as_str()
                .context("broker invocation missing")?
                .to_owned(),
            "host_broker",
        ),
    ];
    for field in ["raw_output_checksum", "time_window"] {
        checks.push(ProviderIdentityCheck {
            field: field.to_owned(),
            expected: None,
            observed: None,
            matched: None,
            evidence_ref: "not-persisted".to_owned(),
        });
    }
    anyhow::ensure!(
        checks
            .iter()
            .all(|identity| identity.matched != Some(false)),
        "historical reconciliation identity mismatch"
    );
    Ok(checks)
}

fn validate_existing_resolution(resolution: &Value, attempt_id: &str) -> Result<()> {
    anyhow::ensure!(
        resolution["schema_version"] == "provider-historical-reconciliation-v1"
            && resolution["invocation_attempt_id"] == attempt_id
            && resolution["provider_redispatch_forbidden"] == true
            && resolution["provider_calls"] == 0
            && resolution["process_facts_synthesized"] == false
            && resolution["reconciliation"]["provider_generating_call_performed"] == false
            && resolution["outcome"]["effective_state"] == "NON_RECONCILABLE_UNKNOWN",
        "existing provider reconciliation record is invalid or conflicting"
    );
    Ok(())
}

fn read_json_value(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

#[derive(Clone, Debug)]
struct McpReferenceExchange {
    tool_names: Vec<String>,
    raw_database_absent: bool,
    tool_call: Option<Value>,
}

#[allow(
    clippy::too_many_lines,
    reason = "one supervised MCP child state machine keeps spawn, drain, timeout, and reap evidence together"
)]
async fn run_bounded_mcp_child(
    config_path: &Path,
    command: Command,
    request_bytes: Vec<u8>,
    phase: &str,
    timeout: Duration,
) -> Result<std::process::Output> {
    let executable = PathBuf::from(command.get_program());
    let args = command.get_args().map(OsString::from).collect();
    let cwd = command
        .get_current_dir()
        .map(ToOwned::to_owned)
        .map_or_else(std::env::current_dir, Ok)?;
    let mut environment = SAFE_INHERITED_ENVIRONMENT
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
        .collect::<BTreeMap<_, _>>();
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            environment.insert(name.into(), value.into());
        } else {
            environment.remove(name);
        }
    }
    let operation_id = format!(
        "mcp-preflight-{}-{}",
        phase
            .chars()
            .map(|character| if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            })
            .collect::<String>(),
        Uuid::now_v7()
    );
    let cancellation = eliot_engine::runtime_supervision::CancellationToken::new();
    let context = AdapterExecutionContext {
        operation_id: operation_id.clone(),
        generation: 1,
        cancellation,
        deadline: tokio::time::Instant::now() + timeout,
        runtime_store: super::supervised_process::daemon_operation_runtime_handle(config_path)?,
        role_lease_id: None,
        role_lease_epoch: None,
        runtime_contract_sha256: None,
    };
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let output = run_supervised_process(
        SupervisedProcessSpec {
            operation_id,
            invocation_id: None,
            generation: 1,
            child_kind: SupervisedChildKind::McpPreflight,
            criticality: ChildCriticality::InvocationDependency,
            restart_policy: ProcessRestartPolicy {
                strategy: RestartStrategy::OneForOne,
                max_restarts: 1,
                restart_window_seconds: 60,
                base_backoff_ms: 100,
                pre_dispatch_only: true,
            },
            executable: executable.clone(),
            args,
            cwd,
            environment,
            stdin_payload: Some(request_bytes),
            stdout_limit_bytes: MAX_MCP_REFERENCE_OUTPUT_BYTES,
            stderr_limit_bytes: MAX_MCP_REFERENCE_OUTPUT_BYTES,
            timeout_profile: eliot_types::ProviderRoutePolicy::for_route(
                AgentHostId::Codex,
                phase,
                eliot_types::ProviderDeclaredBudget::new(
                    timeout_ms,
                    MAX_MCP_REFERENCE_OUTPUT_BYTES,
                )
                .with_idle_output_deadline_ms(Some(timeout_ms))
                .with_cancellation_grace_ms(25)
                .with_reconciliation_window_ms(0),
            )
            .timeout_profile()
            .clone(),
            runtime_contract_sha256: None,
            role_lease_id: None,
            role_lease_epoch: None,
        },
        context,
    )
    .await?;
    let pid = output.reap_receipt.root_pid.unwrap_or_default();
    if output.timed_out {
        anyhow::ensure!(
            output.reap_receipt.proves_complete_reap(),
            "Rust MCP reference exchange phase={phase} exceeded {} seconds; pid={pid}; cleanup receipt incomplete",
            timeout.as_secs_f64()
        );
        anyhow::bail!(
            "Rust MCP reference exchange phase={phase} exceeded {} seconds; pid={pid}; child killed and reaped",
            timeout.as_secs_f64()
        );
    }
    anyhow::ensure!(
        output.worker_error.is_none(),
        "Rust MCP reference exchange phase={phase} cleanup failed: {:?}",
        output.worker_error
    );
    anyhow::ensure!(
        !output.stdout_truncated,
        "Rust MCP reference exchange phase={phase} stdout exceeded {MAX_MCP_REFERENCE_OUTPUT_BYTES} bytes"
    );
    anyhow::ensure!(
        !output.stderr_truncated,
        "Rust MCP reference exchange phase={phase} stderr exceeded {MAX_MCP_REFERENCE_OUTPUT_BYTES} bytes"
    );
    Ok(std::process::Output {
        status: std::process::ExitStatus::from_raw(
            output.exit_code.unwrap_or(i32::MAX).cast_unsigned(),
        ),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the reference exchange keeps one auditable MCP process lifecycle"
)]
async fn mcp_reference_exchange(
    config_path: &Path,
    profile: Option<&str>,
    host: Option<AgentHostId>,
    scope: Option<&HostLaunchScope>,
    tool_name: Option<&str>,
    tool_arguments: Option<&Value>,
    phase: &str,
) -> Result<McpReferenceExchange> {
    let executable =
        std::env::var_os("ELIOT_GOVERNOR_EXE").map_or(std::env::current_exe()?, PathBuf::from);
    let executable = std::fs::canonicalize(executable)?;
    let mut command = Command::new(executable);
    if config_path.is_file() {
        command.args(["--config", &path_string(config_path)]);
    }
    command.args(["mcp", "stdio"]);
    if let Some(host) = host {
        command.args(["--host", host.as_str()]);
    }
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    command.args(["--instance", "default"]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in [
        "SURREAL_USER",
        "SURREAL_PASS",
        "ELIOT_TEST_SURREAL_BIND",
        "ELIOT_TEST_SURREAL_ENDPOINT",
        "ELIOT_TEST_SURREAL_PASSWORD_FILE",
        "ELIOT_TEST_SURREAL_STORAGE",
    ] {
        command.env_remove(name);
    }
    command.env("ELIOT_GOVERNOR_CONFIG", config_path);
    if let Some(scope) = scope {
        if let Some(value) = scope.agent_session_id {
            command.env("ELIOT_AGENT_SESSION_ID", value.to_string());
        }
        if let Some(value) = scope.project_id {
            command.env("ELIOT_PROJECT_ID", value.to_string());
        }
        if let Some(value) = scope.task_id {
            command.env("ELIOT_TASK_ID", value.to_string());
        }
        if let Some(value) = scope.work_item_id {
            command.env("ELIOT_WORK_ITEM_ID", value.to_string());
        }
        if let Some(value) = &scope.role_lease_id {
            command.env("ELIOT_ROLE_LEASE_ID", value);
        }
    }
    let mut requests = vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "eliot-rust-external-agent-preflight",
                    "version": "1.0.0"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    ];
    if let Some(tool_name) = tool_name {
        requests.push(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": tool_arguments.cloned().unwrap_or_else(|| json!({}))
            }
        }));
    }
    let mut request_bytes = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        request_bytes.extend_from_slice(&serde_json::to_vec(request)?);
        request_bytes.push(b'\n');
        if index == 0 {
            request_bytes.extend_from_slice(&serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }))?);
            request_bytes.push(b'\n');
        }
    }
    let output = run_bounded_mcp_child(
        config_path,
        command,
        request_bytes,
        phase,
        MCP_REFERENCE_TIMEOUT,
    )
    .await?;
    anyhow::ensure!(
        output.status.success(),
        "Rust MCP reference exchange failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = String::from_utf8(output.stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let initialize = response_by_id(&responses, 1)?;
    anyhow::ensure!(
        initialize.get("error").is_none(),
        "MCP initialize returned an error: {initialize}"
    );
    let tools = response_by_id(&responses, 2)?;
    anyhow::ensure!(
        tools.get("error").is_none(),
        "MCP tools/list returned an error: {tools}"
    );
    let tool_names = tools
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .context("MCP tools/list returned no tools array")?
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let raw_database_absent = !tool_names.iter().any(|name| {
        let lower = name.to_ascii_lowercase();
        lower.contains("surrealdb") || lower == "query"
    });
    anyhow::ensure!(
        raw_database_absent,
        "raw database tool was exposed by the Governor MCP facade"
    );
    let tool_call = if tool_name.is_some() {
        let response = response_by_id(&responses, 3)?;
        anyhow::ensure!(
            response.get("error").is_none(),
            "MCP tools/call returned an error: {response}"
        );
        response.pointer("/result/structuredContent").cloned()
    } else {
        None
    };
    Ok(McpReferenceExchange {
        tool_names,
        raw_database_absent,
        tool_call,
    })
}

fn response_by_id(responses: &[Value], id: u64) -> Result<&Value> {
    responses
        .iter()
        .find(|response| response.get("id").and_then(Value::as_u64) == Some(id))
        .with_context(|| format!("MCP response {id} is absent"))
}

#[derive(Clone)]
struct SmokePhaseTrace {
    path: PathBuf,
    smoke_id: String,
    active: Arc<Mutex<Option<ActiveSmokePhase>>>,
}

struct ActiveSmokePhase {
    name: String,
    started: Instant,
}

impl SmokePhaseTrace {
    fn new(smoke_root: &Path, smoke_id: &str) -> Result<Self> {
        std::fs::create_dir_all(smoke_root)?;
        Ok(Self {
            path: smoke_root.join("phases.jsonl"),
            smoke_id: smoke_id.to_owned(),
            active: Arc::new(Mutex::new(None)),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn append(
        &self,
        phase: &str,
        status: &str,
        elapsed: Duration,
        detail: Option<&str>,
    ) -> Result<()> {
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let entry = json!({
            "schema_version": MCP_SMOKE_PHASE_SCHEMA_VERSION,
            "smoke_id": self.smoke_id,
            "phase": phase,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "observed_at": OffsetDateTime::now_utc(),
            "diagnostic_only": true,
            "host_broker_receipt": false,
            "detail": detail,
        });
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open smoke phase journal {}", self.path.display()))?;
        serde_json::to_writer(&mut file, &entry)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        Ok(())
    }

    fn start(&self, phase: &str) -> Result<()> {
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| anyhow::anyhow!("smoke phase mutex is poisoned"))?;
            anyhow::ensure!(
                active.is_none(),
                "cannot start smoke phase {phase}; another phase is active"
            );
            *active = Some(ActiveSmokePhase {
                name: phase.to_owned(),
                started: Instant::now(),
            });
        }
        if let Err(error) = self.append(phase, "started", Duration::ZERO, None) {
            let mut active = self
                .active
                .lock()
                .map_err(|_| anyhow::anyhow!("smoke phase mutex is poisoned"))?;
            *active = None;
            return Err(error);
        }
        Ok(())
    }

    fn finish(&self, phase: &str, status: &str, detail: Option<&str>) -> Result<()> {
        let active = self
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("smoke phase mutex is poisoned"))?
            .take()
            .context("no active smoke phase to finish")?;
        anyhow::ensure!(
            active.name == phase,
            "smoke phase mismatch: active={} finished={phase}",
            active.name
        );
        self.append(phase, status, active.started.elapsed(), detail)
    }

    async fn run<T, F>(&self, phase: &str, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.start(phase)?;
        match future.await {
            Ok(value) => {
                self.finish(phase, "passed", None)?;
                Ok(value)
            }
            Err(error) => {
                let detail = error.to_string();
                self.finish(phase, "failed", Some(&detail))?;
                Err(error)
            }
        }
    }

    fn run_sync<T, F>(&self, phase: &str, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        self.start(phase)?;
        match operation() {
            Ok(value) => {
                self.finish(phase, "passed", None)?;
                Ok(value)
            }
            Err(error) => {
                let detail = error.to_string();
                self.finish(phase, "failed", Some(&detail))?;
                Err(error)
            }
        }
    }

    fn abort_active(&self, detail: &str) -> Result<()> {
        let active = self
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("smoke phase mutex is poisoned"))?
            .take();
        if let Some(active) = active {
            self.append(
                &active.name,
                "aborted",
                active.started.elapsed(),
                Some(detail),
            )?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct OperationBoundHostScope {
    open_receipt: OperationAuthorityOpenReceipt,
    launch_scope: HostLaunchScope,
    instance: RuntimeInstance,
}

async fn with_operation_bound_host_scope<T, F, Fut>(
    config_path: &Path,
    open: OperationAuthorityOpenRequest,
    operation: F,
) -> Result<T>
where
    F: FnOnce(OperationBoundHostScope) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let instance = host_governor_instance(config_path)?;
    let response = named_pipe_ipc::host_governor_request(
        &instance,
        "host/operation-scope-open",
        serde_json::to_value(&open)?,
    )
    .await
    .context("open operation-bound host authority")?;
    let open_receipt: OperationAuthorityOpenReceipt =
        serde_json::from_value(response).context("decode operation scope open receipt")?;
    let scope = OperationBoundHostScope {
        launch_scope: open_receipt.launch_scope.clone(),
        open_receipt: open_receipt.clone(),
        instance: instance.clone(),
    };
    let body = operation(scope).await;
    let (terminal_outcome, result_or_failure_ref, reason) = match &body {
        Ok(_) => (
            OperationAuthorityTerminalOutcome::Completed,
            Some(format!("operation-completed:{}", open.operation_id)),
            "operation_body_completed".to_owned(),
        ),
        Err(error) => (
            if open.purpose == ExternalAgentPurpose::McpPreflight {
                OperationAuthorityTerminalOutcome::FailedBeforeDispatch
            } else {
                OperationAuthorityTerminalOutcome::FailedAfterDispatch
            },
            Some(format!(
                "operation-error:{}",
                blake3::hash(error.to_string().as_bytes()).to_hex()
            )),
            format!("operation_body_failed: {error}"),
        ),
    };
    let role_lease_id = open_receipt
        .launch_scope
        .role_lease_id
        .clone()
        .context("operation scope open receipt has no role lease")?;
    let close = OperationAuthorityCloseRequest {
        schema_version: OPERATION_AUTHORITY_SCHEMA_VERSION.to_owned(),
        operation_id: open.operation_id.clone(),
        purpose: open.purpose,
        generation: open.generation,
        project_id: open.project_id,
        task_id: open.task_id,
        agent_session_id: open.agent_session_id,
        role_lease_id,
        expected_epoch: open_receipt.launch_scope.role_lease_epoch,
        terminal_outcome,
        result_or_failure_ref,
        reason,
        idempotency_key: format!("{}:close", open.idempotency_key),
    };
    let close_result = named_pipe_ipc::host_governor_request(
        &instance,
        "host/operation-scope-close",
        serde_json::to_value(close)?,
    )
    .await
    .and_then(|response| {
        serde_json::from_value::<OperationAuthorityCloseReceipt>(response)
            .context("decode operation scope close receipt")
    });
    match (body, close_result) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(body_error), Ok(_)) => Err(body_error),
        (Ok(_), Err(close_error)) => {
            Err(close_error).context("operation body passed but authority cleanup failed")
        }
        (Err(body_error), Err(close_error)) => Err(anyhow::anyhow!(
            "operation body failed: {body_error}; authority cleanup also failed: {close_error}"
        )),
    }
}

struct McpSmokePreparation {
    smoke_id: String,
    smoke_root: PathBuf,
    workspace: PathBuf,
    project_id: ProjectId,
    task_id: TaskId,
    agent_session_id: AgentSessionId,
    work_item_id: WorkItemId,
    trace: SmokePhaseTrace,
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded preparation keeps phase attribution and canonical identity setup together"
)]
async fn prepare_mcp_smoke(
    config_path: &Path,
    host: AgentHostId,
    model: &str,
) -> Result<McpSmokePreparation> {
    anyhow::ensure!(
        host != AgentHostId::Codex,
        "Codex is not an external adapter"
    );
    anyhow::ensure!(
        !model.trim().is_empty(),
        "MCP smoke preparation requires an exact non-empty model"
    );
    let smoke_id = format!("external-agent-smoke-{}-{}", host.as_str(), Uuid::now_v7());
    let smoke_root = runtime_root(config_path)
        .join("external-agent-smokes")
        .join(&smoke_id);
    let workspace = smoke_root.join("workspace");
    let trace = SmokePhaseTrace::new(&smoke_root, &smoke_id)?;

    let preparation = async {
        trace
            .run("workspace_create", async {
                std::fs::create_dir_all(&workspace)?;
                Ok(())
            })
            .await?;
        let identity = trace
            .run(
                "project_identity",
                mcp_reference_exchange(
                    config_path,
                    Some("codex_controller"),
                    None,
                    None,
                    Some("eliot_project_identity"),
                    Some(&json!({"project_key": path_string(&workspace)})),
                    "project_identity",
                ),
            )
            .await?;
        let identity = identity
            .tool_call
            .context("project identity tool returned no structured content")?;
        let project_id = identity
            .get("project_id")
            .or_else(|| identity.pointer("/tool_call/project_id"))
            .and_then(Value::as_str)
            .context("project identity returned no project_id")
            .and_then(|value| ProjectId::from_str(value).context("parse smoke project_id"))?;
        let task_id = TaskId::new_v7();
        let task_create = trace
            .run(
                "task_contract_create",
                mcp_reference_exchange(
                    config_path,
                    Some("codex_controller"),
                    None,
                    None,
                    Some("eliot_task_contract_create"),
                    Some(&json!({
                        "project_id": project_id,
                        "task_id": task_id,
                        "write_id": Uuid::now_v7(),
                        "title": format!("{} production adapter current_state smoke", host.as_str()),
                        "acceptance_items": [
                            {
                                "item_id": "headless_transport",
                                "description": "official headless provider invokes exactly one Governor MCP server",
                                "required_evidence": "observation"
                            },
                            {
                                "item_id": "current_state",
                                "description": "provider returns the canonical bound project/task revision",
                                "required_evidence": "verification"
                            }
                        ]
                    })),
                    "task_contract_create",
                ),
            )
            .await?;
        anyhow::ensure!(
            task_create
                .tool_call
                .as_ref()
                .is_some_and(|value| value.get("task_contract").is_some()),
            "smoke task contract was not created canonically"
        );
        let agent_session_id = AgentSessionId::new_v7();
        let work_item_id = WorkItemId::new_v7();
        Ok(McpSmokePreparation {
            smoke_id,
            smoke_root,
            workspace,
            project_id,
            task_id,
            agent_session_id,
            work_item_id,
            trace: trace.clone(),
        })
    };
    let Ok(result) = tokio::time::timeout(MCP_SMOKE_PRE_PROVIDER_TIMEOUT, preparation).await else {
        trace.abort_active("whole pre-provider deadline exceeded")?;
        anyhow::bail!(
            "MCP smoke pre-provider preparation exceeded {} seconds; phase journal={}",
            MCP_SMOKE_PRE_PROVIDER_TIMEOUT.as_secs(),
            trace.path().display()
        )
    };
    result
}

async fn run_mcp_preflight(config_path: &Path, host: AgentHostId, model: &str) -> Result<Value> {
    let preparation = prepare_mcp_smoke(config_path, host, model).await?;
    let report_path = runtime_root(config_path)
        .join("reports")
        .join("external-agent-smokes")
        .join(format!("{}-preflight-latest.json", host.as_str()));
    let smoke_report_path = preparation.smoke_root.join("preflight-report.json");
    let open = OperationAuthorityOpenRequest {
        schema_version: OPERATION_AUTHORITY_SCHEMA_VERSION.to_owned(),
        operation_id: preparation.smoke_id.clone(),
        purpose: ExternalAgentPurpose::McpPreflight,
        generation: 1,
        host,
        project_id: preparation.project_id,
        task_id: preparation.task_id,
        agent_session_id: preparation.agent_session_id,
        role: AgentRole::Auditor,
        capability_scope: external_auditor_capability_scope(),
        ttl_seconds: 5 * 60,
        client_instance_id: preparation.smoke_id.clone(),
        idempotency_key: format!("operation-authority:{}", preparation.smoke_id),
    };
    let report = Box::pin(with_operation_bound_host_scope(
        config_path,
        open,
        |operation_scope| async move {
            let mut scope = operation_scope.launch_scope.clone();
            scope.work_item_id = Some(preparation.work_item_id);
            scope.planned_verifier_ref = Some(format!(
                "external-agent-smoke-verifier:{}",
                preparation.smoke_id
            ));
            let preflight = preparation
                .trace
                .run(
                    "current_state_preflight",
                    mcp_reference_exchange(
                        config_path,
                        if host == AgentHostId::OpenCode {
                            Some("default")
                        } else {
                            Some("external_auditor")
                        },
                        Some(host),
                        Some(&scope),
                        Some("eliot_current_state"),
                        Some(&json!({"scope": "memory_free_control"})),
                        "current_state_preflight",
                    ),
                )
                .await?;
            anyhow::ensure!(
                preflight
                    .tool_names
                    .iter()
                    .any(|name| name == "eliot_current_state"),
                "zero-model preflight did not expose eliot_current_state"
            );
            let current_state = preflight
                .tool_call
                .as_ref()
                .context("zero-model current_state preflight returned no structured content")?;
            let memory_revision = current_state
                .get("memory_revision")
                .or_else(|| current_state.get("revision"))
                .and_then(Value::as_u64)
                .context("zero-model current_state returned no memory revision")?;
            anyhow::ensure!(
                operation_scope.instance == host_governor_instance(config_path)?,
                "operation scope daemon instance changed during preflight"
            );
            Ok(json!({
                "schema_version": "eliot-external-agent-mcp-preflight-v2",
                "status": "passed",
                "smoke_id": preparation.smoke_id,
                "host": host,
                "model": model,
                "project_id": preparation.project_id,
                "task_id": preparation.task_id,
                "memory_revision": memory_revision,
                "tool_names": preflight.tool_names,
                "raw_database_absent": preflight.raw_database_absent,
                "phase_journal_ref": path_string(preparation.trace.path()),
                "authority_open_state_hash": operation_scope.open_receipt.state_hash,
                "provider_calls": 0,
                "gui_used": false,
            }))
        },
    ))
    .await?;
    atomic_write_json(&report_path, &report)?;
    atomic_write_json(&smoke_report_path, &report)?;
    Ok(report)
}

fn mcp_smoke_prompt(model: &str) -> String {
    format!(
        "Use the configured ELIOT MCP server. Call eliot_current_state exactly once with the sole argument {{\"scope\":\"memory_free_control\"}}; do not pass project_id or task_id because the Governor binds them. Return one plain JSON object, without Markdown fences or prose, containing only the schema-bound project_id, task_id, memory_revision and resolved_model={model}. Do not edit files."
    )
}

fn memory_revision_within_execution_window(
    preflight_revision: u64,
    observed_revision: u64,
    postflight_revision: u64,
) -> bool {
    observed_revision >= preflight_revision && observed_revision <= postflight_revision
}

#[allow(clippy::too_many_lines)]
async fn run_mcp_smoke(config_path: &Path, host: AgentHostId, model: &str) -> Result<Value> {
    let McpSmokePreparation {
        smoke_id,
        smoke_root,
        workspace,
        project_id,
        task_id,
        agent_session_id: prepared_agent_session_id,
        work_item_id,
        trace,
    } = prepare_mcp_smoke(config_path, host, model).await?;
    let report_path = runtime_root(config_path)
        .join("reports")
        .join("external-agent-smokes")
        .join(format!("{}-latest.json", host.as_str()));
    let smoke_report_path = smoke_root.join("smoke-report.json");
    let open = OperationAuthorityOpenRequest {
        schema_version: OPERATION_AUTHORITY_SCHEMA_VERSION.to_owned(),
        operation_id: smoke_id.clone(),
        purpose: ExternalAgentPurpose::ProviderSmoke,
        generation: 1,
        host,
        project_id,
        task_id,
        agent_session_id: prepared_agent_session_id,
        role: AgentRole::Auditor,
        capability_scope: external_auditor_capability_scope(),
        ttl_seconds: 5 * 60,
        client_instance_id: smoke_id.clone(),
        idempotency_key: format!("external-agent-smoke:{smoke_id}"),
    };
    let report = Box::pin(with_operation_bound_host_scope(
        config_path,
        open,
        |operation_scope| async move {
        let mut scope = operation_scope.launch_scope.clone();
        scope.work_item_id = Some(work_item_id);
        scope.planned_verifier_ref = Some(format!("external-agent-smoke-verifier:{smoke_id}"));
        let preflight = trace
            .run(
                "current_state_preflight",
                mcp_reference_exchange(
                    config_path,
                    if host == AgentHostId::OpenCode {
                        Some("default")
                    } else {
                        Some("external_auditor")
                    },
                    Some(host),
                    Some(&scope),
                    Some("eliot_current_state"),
                    Some(&json!({"scope": "memory_free_control"})),
                    "current_state_preflight",
                ),
            )
            .await?;
        anyhow::ensure!(
            preflight
                .tool_names
                .iter()
                .any(|name| name == "eliot_current_state"),
            "zero-model preflight did not expose eliot_current_state"
        );
        let current_state = preflight
            .tool_call
            .as_ref()
            .context("zero-model current_state preflight returned no structured content")?;
        let memory_revision = current_state
            .get("memory_revision")
            .or_else(|| current_state.get("revision"))
            .and_then(Value::as_u64)
            .context("zero-model current_state returned no memory revision")?;

        let (_schema, prompt, prompt_path, schema_path) = trace.run_sync("prompt_build", || {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["project_id", "task_id", "memory_revision", "resolved_model"],
            "properties": {
                "project_id": {"const": project_id.to_string()},
                "task_id": {"const": task_id.to_string()},
                "memory_revision": {
                    "type": "integer",
                    "minimum": memory_revision
                },
                "resolved_model": {"const": model}
            }
        });
        let prompt = mcp_smoke_prompt(model);
        let prompt_path = smoke_root.join("prompt.txt");
        let schema_path = smoke_root.join("schema.json");
        atomic_write_bytes(&prompt_path, prompt.as_bytes())?;
        atomic_write_json(&schema_path, &schema)?;
        Ok((schema, prompt, prompt_path, schema_path))
    })?;
    let (agent_session_id, adapter_request) = trace.run_sync("launch_contract", || {
        let agent_session_id = scope
            .agent_session_id
            .context("smoke scope has no AgentSession")?;
        let role_lease_id = scope
            .role_lease_id
            .clone()
            .context("smoke scope has no TaskRoleLease")?;
        let mut launch_contract = eliot_types::HostLaunchContract {
            invocation_id: smoke_id.clone(),
            host_profile_ref: format!("external-agent-adapter:{}", host.as_str()),
            mode: HostMode::Supervised,
            project_id: Some(project_id),
            agent_session_id: Some(agent_session_id),
            task_id: Some(task_id),
            work_item_id: Some(work_item_id),
            role_lease_id: Some(role_lease_id.clone()),
            role_lease_epoch: scope.role_lease_epoch,
            operation_generation: scope.operation_generation,
            work_lease_id: None,
            worktree_lease_id: None,
            planned_verifier_ref: scope.planned_verifier_ref.clone(),
            cwd_or_worktree: path_string(&workspace),
            baseline_commit: None,
            allowed_paths: Vec::new(),
            forbidden_paths: vec![
                "truth-promotion".to_owned(),
                "raw-database".to_owned(),
                "provider-credential-roots".to_owned(),
            ],
            integration_bundle_ref: path_string(&smoke_root),
            mcp_config_ref: path_string(&smoke_root.join("provider-mcp.json")),
            skill_bundle_ref: path_string(&smoke_root.join("skills")),
            lifecycle_bridge_ref: "external-agent-adapter".to_owned(),
            environment_allowlist: SAFE_INHERITED_ENVIRONMENT
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            permission_profile: "external_auditor".to_owned(),
            model_route_if_selected: Some(model.to_owned()),
            max_turns_or_steps: Some(4),
            wall_clock_budget_seconds: 120,
            cost_budget_if_supported: None,
            session_id: None,
            resume_policy: "fresh_only".to_owned(),
            structured_output_schema_ref: Some(path_string(&schema_path)),
            stdout_stderr_spool: path_string(&smoke_root.join("spool")),
            artifact_manifest_ref: path_string(&smoke_root.join("artifacts.json")),
            idempotency_key: format!("external-agent-smoke:{smoke_id}"),
            expected_result_kind: "provider_execution_evidence".to_owned(),
            contract_hash: String::new(),
        };
        launch_contract.contract_hash = blake3::hash(&serde_json::to_vec(&launch_contract)?)
            .to_hex()
            .to_string();
        let invocation = eliot_types::AgentInvocationRequest {
            invocation_id: smoke_id.clone(),
            project_id,
            task_id,
            work_item_id,
            requested_capabilities: vec![
                "emit_candidate_observation".to_owned(),
                "request_controller_review".to_owned(),
            ],
            role_lease_id,
            role_lease_epoch: scope.role_lease_epoch,
            operation_generation: scope.operation_generation,
            runtime_contract_sha256: Some(launch_contract.contract_hash.clone()),
            work_lease_id: None,
            packet_refs: Vec::new(),
            expected_result_kind: "provider_execution_evidence".to_owned(),
            verifier_ref: format!("external-agent-smoke-verifier:{smoke_id}"),
            idempotency_key: format!("external-agent-smoke:{smoke_id}"),
        };
        let provider_route_policy = eliot_types::ProviderRoutePolicy::for_route(
            host,
            "external-agent-smoke",
            eliot_types::ProviderDeclaredBudget::new(120_000, MAX_PROVIDER_OUTPUT_BYTES),
        );
        let mcp_tool_profile = crate::mcp_stdio::catalog::provider_mcp_tool_profile(
            provider_mcp_access_profile(ExternalAgentPurpose::UnderstandingReader),
        );
        let execution = ExternalAgentExecutionRequest {
            invocation,
            launch_contract,
            campaign_id: format!("external-agent-smoke:{smoke_id}"),
            purpose: ExternalAgentPurpose::UnderstandingReader,
            mcp_tool_profile: mcp_tool_profile.clone(),
            prompt_ref: path_string(&prompt_path),
            prompt_sha256: sha256_bytes(prompt.as_bytes()),
            output_schema_ref: path_string(&schema_path),
            output_schema_sha256: sha256_bytes(&std::fs::read(&schema_path)?),
            requested_model: model.to_owned(),
            max_turns_or_steps: 4,
            timeout_profile_ref: provider_route_policy.policy_id().to_owned(),
            provider_route_policy,
            allowed_provider_tools: provider_allowed_tools(host, &mcp_tool_profile.tool_names),
            denied_provider_tools: vec![
                "Bash".to_owned(),
                "Edit".to_owned(),
                "Write".to_owned(),
                "NotebookEdit".to_owned(),
                "WebFetch".to_owned(),
                "WebSearch".to_owned(),
            ],
            expected_mcp_tool_names: mcp_tool_profile.tool_names,
            forbidden_mcp_server_names: vec!["eliot_surrealdb".to_owned(), "surrealdb".to_owned()],
            read_only: true,
            candidate_only: true,
        };
        ProviderCallReservationOwner::new(runtime_root(config_path)).open_campaign(
            ProviderCallCampaignRequest {
                campaign_id: execution.campaign_id.clone(),
                max_calls: 1,
                closed: false,
            },
        )?;
        let adapter_request = AdapterRequest {
            request_id: format!("adapter-request:{smoke_id}"),
            adapter_id: adapter_id(host).to_owned(),
            requested_capability: AdapterCapability::EmitCandidateObservation,
            context: eliot_types::AdapterContext {
                project_id,
                task_id,
                session_id: Some(agent_session_id),
                trace_id: format!("external-agent-smoke:{smoke_id}"),
                created_at: OffsetDateTime::now_utc(),
                role_lease_id: Some(execution.invocation.role_lease_id.clone()),
                role_lease_epoch: Some(execution.invocation.role_lease_epoch),
                operation_generation: Some(execution.invocation.operation_generation),
                runtime_contract_sha256: Some(execution.launch_contract.contract_hash.clone()),
            },
            input: serde_json::to_value(execution)?,
        };
        Ok((agent_session_id, adapter_request))
    })?;
    let supervisor = production_external_agent_supervisor(config_path)?;
    let result = trace
        .run("provider_dispatch", async {
            supervisor
                .execute(adapter_id(host), adapter_request, None)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))
        })
        .await?;
    let postflight = trace
        .run(
            "current_state_postflight",
            mcp_reference_exchange(
                config_path,
                if host == AgentHostId::OpenCode {
                    Some("default")
                } else {
                    Some("external_auditor")
                },
                Some(host),
                Some(&scope),
                Some("eliot_current_state"),
                Some(&json!({"scope": "memory_free_control"})),
                "current_state_postflight",
            ),
        )
        .await?;
    let postflight_memory_revision = postflight
        .tool_call
        .as_ref()
        .and_then(|value| {
            value
                .get("memory_revision")
                .or_else(|| value.get("revision"))
        })
        .and_then(Value::as_u64)
        .context("zero-model current_state postflight returned no memory revision")?;
    trace.run_sync("provider_result_validation", || {
        let evidence = result
            .output
            .get("provider_execution_evidence")
            .with_context(|| {
                format!(
                    "adapter smoke returned no ProviderExecutionEvidence; status={:?}; error={:?}; output={}",
                    result.status, result.error, result.output
                )
            })?;
        let structured = evidence
            .get("structured_output")
            .context("adapter smoke returned no structured output")?;
        let observed_tool_names = evidence
            .get("observed_mcp_tool_names")
            .and_then(Value::as_array)
            .context("adapter smoke returned no observed MCP tool-name array")?;
        let observed_current_state = observed_tool_names.iter().any(|name| {
            name.as_str().is_some_and(|name| {
                name == "eliot_current_state"
                    || name == "eliot-governor_eliot_current_state"
                    || name.ends_with("__eliot_current_state")
                    || name.ends_with("/eliot_current_state")
            })
        });
        let observed_memory_revision = structured
            .get("memory_revision")
            .and_then(Value::as_u64)
            .context("adapter smoke returned no unsigned memory_revision")?;
        anyhow::ensure!(
            result.status == AdapterResultStatus::Succeeded
                && observed_current_state
                && structured.get("project_id").and_then(Value::as_str)
                == Some(project_id.to_string().as_str())
                && structured.get("task_id").and_then(Value::as_str)
                    == Some(task_id.to_string().as_str())
                && memory_revision_within_execution_window(
                    memory_revision,
                    observed_memory_revision,
                    postflight_memory_revision,
                )
                && structured.get("resolved_model").and_then(Value::as_str) == Some(model),
            "{} adapter smoke returned a noncanonical result: {}",
            host.as_str(),
            result.output
        );
        Ok(())
    })?;
        let report = json!({
        "schema_version": "eliot-external-agent-mcp-smoke-v2",
        "status": "passed",
        "smoke_id": smoke_id,
        "host": host,
        "model": model,
        "project_id": project_id,
        "task_id": task_id,
        "agent_session_id": agent_session_id,
        "zero_model_preflight": {
            "tool_names": preflight.tool_names,
            "raw_database_absent": preflight.raw_database_absent,
            "memory_revision": memory_revision,
        },
        "zero_model_postflight": {
            "tool_names": postflight.tool_names,
            "raw_database_absent": postflight.raw_database_absent,
            "memory_revision": postflight_memory_revision,
        },
        "phase_journal_ref": path_string(trace.path()),
        "authority_open_state_hash": operation_scope.open_receipt.state_hash,
        "adapter_result": result,
        "provider_calls": 1,
        "gui_used": false,
        });
        anyhow::ensure!(
            operation_scope.instance == host_governor_instance(config_path)?,
            "operation scope daemon instance changed during provider smoke"
        );
        Ok(report)
        },
    ))
    .await?;
    atomic_write_json(&report_path, &report)?;
    atomic_write_json(&smoke_report_path, &report)?;
    Ok(report)
}

fn provider_allowed_tools(host: AgentHostId, tool_names: &[String]) -> Vec<String> {
    match host {
        AgentHostId::Claude => tool_names
            .iter()
            .flat_map(|name| {
                [
                    format!("mcp__eliot-governor__{name}"),
                    format!("mcp__eliot_governor__{name}"),
                ]
            })
            .collect(),
        AgentHostId::Antigravity | AgentHostId::OpenCode => tool_names.to_vec(),
        AgentHostId::Codex => Vec::new(),
    }
}

pub(crate) fn provider_mcp_access_profile(
    purpose: ExternalAgentPurpose,
) -> crate::mcp_stdio::McpAccessProfile {
    match purpose {
        ExternalAgentPurpose::CognitiveWorker => crate::mcp_stdio::McpAccessProfile::CognitiveChild,
        ExternalAgentPurpose::UnderstandingReader => {
            crate::mcp_stdio::McpAccessProfile::UnderstandingReader
        }
        ExternalAgentPurpose::MemoryFreeControl => {
            crate::mcp_stdio::McpAccessProfile::CognitiveControl
        }
        _ => crate::mcp_stdio::McpAccessProfile::ExternalAuditor,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded diagnostic keeps command, process, parse, and receipt evidence together"
)]
async fn run_auth_smoke(config_path: &Path, host: AgentHostId, model: &str) -> Result<Value> {
    anyhow::ensure!(
        host != AgentHostId::Codex,
        "Codex is not an external adapter"
    );
    anyhow::ensure!(
        !model.trim().is_empty(),
        "auth-smoke requires an exact non-empty model"
    );
    let governor = std::env::current_exe()?.canonicalize()?;
    let process_runner = super::ProviderRuntime::production(config_path)?.runner();
    let core =
        ExternalAgentAdapterCore::new(host, config_path, &governor, Arc::clone(&process_runner))?;
    let executable = core
        .executable
        .context("headless provider executable is not installed")?;
    let auth_id = format!("external-agent-auth-{}-{}", host.as_str(), Uuid::now_v7());
    let root = runtime_root(config_path)
        .join("external-agent-auth-smokes")
        .join(&auth_id);
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "resolved_model"],
        "properties": {
            "status": {"const": "ready"},
            "resolved_model": {"const": model}
        }
    });
    let prompt = format!(
        "Return only the schema-bound status=ready and resolved_model={model}. Do not use tools, inspect files, or edit anything."
    );
    let mode = ProviderStructuredOutputMode::NativeJsonSchema;
    let plan = match host {
        AgentHostId::Claude => ProviderCommandPlan {
            argv: vec![
                "-p".to_owned(),
                "--model".to_owned(),
                model.to_owned(),
                "--output-format".to_owned(),
                "stream-json".to_owned(),
                "--verbose".to_owned(),
                "--json-schema".to_owned(),
                serde_json::to_string(&schema)?,
                "--disallowedTools".to_owned(),
                "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch".to_owned(),
                "--max-turns".to_owned(),
                "1".to_owned(),
                "--no-session-persistence".to_owned(),
                "--".to_owned(),
                prompt.clone(),
            ],
            nonsecret_environment: BTreeMap::new(),
            structured_output_mode: mode,
            model_selection_mechanism: "cli_flag:--model".to_owned(),
        },
        AgentHostId::Antigravity => build_antigravity_command(&AntigravityCommandInput {
            requested_model: model.to_owned(),
            workspace: path_string(&workspace),
            output_schema: schema.clone(),
            max_runtime_seconds: 120,
            prompt: prompt.clone(),
            native_json_schema: true,
            read_only: true,
        })?,
        AgentHostId::OpenCode => build_opencode_command(&OpenCodeCommandInput {
            requested_model: model.to_owned(),
            workspace: path_string(&workspace),
            prompt: prompt.clone(),
            read_only: true,
        })?,
        AgentHostId::Codex => unreachable!(),
    };
    let mut environment = BTreeMap::new();
    for name in SAFE_INHERITED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            environment.insert((*name).to_owned(), value.to_string_lossy().into_owned());
        }
    }
    environment.extend(plan.nonsecret_environment.clone());
    if host == AgentHostId::OpenCode {
        let config_dir = root.join("opencode-config");
        let xdg = root.join("opencode-xdg");
        std::fs::create_dir_all(&config_dir)?;
        std::fs::create_dir_all(&xdg)?;
        atomic_write_json(
            &config_dir.join("opencode.json"),
            &json!({"$schema": "https://opencode.ai/config.json", "mcp": {}}),
        )?;
        environment.insert("OPENCODE_CONFIG_DIR".to_owned(), path_string(&config_dir));
        environment.insert("XDG_CONFIG_HOME".to_owned(), path_string(&xdg));
    }
    let operation_id = format!("auth-smoke-{auth_id}");
    let route_policy = eliot_types::ProviderRoutePolicy::for_route(
        host,
        "external-agent-auth-smoke",
        eliot_types::ProviderDeclaredBudget::new(120_000, MAX_PROVIDER_OUTPUT_BYTES)
            .with_cleanup_grace_ms(PROVIDER_CLEANUP_GRACE_SECONDS * 1_000),
    );
    let mut on_spawned = |_| Ok(());
    let output = process_runner
        .run(
            ProviderProcessSpec {
                operation_id,
                invocation_id: Some(auth_id.clone()),
                executable,
                args: plan.argv.into_iter().map(OsString::from).collect(),
                cwd: workspace,
                environment: environment
                    .into_iter()
                    .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                    .collect(),
                stdin_payload: None,
                route_policy,
                cancellation: eliot_engine::runtime_supervision::CancellationToken::new(),
                deadline: tokio::time::Instant::now() + Duration::from_secs(120),
                runtime_contract_sha256: None,
                role_lease_id: None,
                role_lease_epoch: None,
            },
            &mut on_spawned,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    anyhow::ensure!(
        output.exit_code == Some(0) && !output.timed_out,
        "{}; login command: {}",
        provider_failure_message(&output),
        provider_login_command(host)
    );
    let parsed = parse_terminal(
        host,
        &output.stdout,
        model,
        &schema,
        plan.structured_output_mode,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let report = json!({
        "schema_version": "eliot-external-agent-auth-smoke-v1",
        "status": "passed",
        "auth_smoke_id": auth_id,
        "host": host,
        "requested_model": model,
        "resolved_model": parsed.resolved_model,
        "provider_session_id": parsed.provider_session_id,
        "provider_authenticated": true,
        "mcp_enabled": false,
        "provider_calls": 1,
        "stdout_sha256": sha256_bytes(&output.stdout),
        "stderr_sha256": sha256_bytes(&output.stderr),
        "process_tree_terminated": output.reap_receipt.proves_complete_reap(),
        "reap_receipt": output.reap_receipt,
        "gui_used": false,
    });
    let report_path = runtime_root(config_path)
        .join("reports")
        .join("external-agent-auth-smokes")
        .join(format!("{}-latest.json", host.as_str()));
    atomic_write_json(&report_path, &report)?;
    Ok(report)
}

fn provider_login_command(host: AgentHostId) -> &'static str {
    match host {
        AgentHostId::Claude => "claude auth login",
        AgentHostId::Antigravity => "agy <official onboarding command shown by local help>",
        AgentHostId::OpenCode => "opencode auth login",
        AgentHostId::Codex => "unsupported",
    }
}

impl ClaudeCodeCliAdapter {
    fn new(
        config_path: &Path,
        governor_executable: &Path,
        process_runner: Arc<dyn ProviderProcessRunner>,
    ) -> Result<Self> {
        Ok(Self {
            core: ExternalAgentAdapterCore::new(
                AgentHostId::Claude,
                config_path,
                governor_executable,
                process_runner,
            )?,
        })
    }
}

impl AntigravityCliAdapter {
    fn new(
        config_path: &Path,
        governor_executable: &Path,
        process_runner: Arc<dyn ProviderProcessRunner>,
    ) -> Result<Self> {
        Ok(Self {
            core: ExternalAgentAdapterCore::new(
                AgentHostId::Antigravity,
                config_path,
                governor_executable,
                process_runner,
            )?,
        })
    }
}

impl OpenCodeCliAdapter {
    fn new(
        config_path: &Path,
        governor_executable: &Path,
        process_runner: Arc<dyn ProviderProcessRunner>,
    ) -> Result<Self> {
        Ok(Self {
            core: ExternalAgentAdapterCore::new(
                AgentHostId::OpenCode,
                config_path,
                governor_executable,
                process_runner,
            )?,
        })
    }
}

macro_rules! impl_external_adapter {
    ($adapter:ty) => {
        impl Adapter for $adapter {
            fn id(&self) -> &str {
                &self.core.adapter_id
            }

            fn manifest(&self) -> &eliot_types::CapabilityManifest {
                &self.core.manifest
            }

            fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
                self.core.health()
            }

            fn execute(
                &self,
                request: AdapterRequest,
                context: AdapterExecutionContext,
            ) -> BoxAdapterFuture<'_, AdapterResult> {
                self.core.execute(request, context)
            }

            fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
                Box::pin(async { Ok(()) })
            }
        }
    };
}

impl_external_adapter!(ClaudeCodeCliAdapter);
impl_external_adapter!(AntigravityCliAdapter);
impl_external_adapter!(OpenCodeCliAdapter);

impl ExternalAgentAdapterCore {
    fn new(
        host: AgentHostId,
        config_path: &Path,
        governor_executable: &Path,
        process_runner: Arc<dyn ProviderProcessRunner>,
    ) -> Result<Self> {
        let executable = discover_provider_binary(host)?;
        let version = executable
            .as_deref()
            .map(sha256_file)
            .transpose()?
            .map(|sha256| format!("executable-sha256:{sha256}"));
        let adapter_id = adapter_id(host).to_owned();
        let manifest = provider_manifest(host, &adapter_id, executable.as_deref());
        Ok(Self {
            host,
            adapter_id,
            executable,
            version,
            governor_executable: governor_executable.to_path_buf(),
            config_path: config_path.to_path_buf(),
            manifest,
            process_runner,
            authority_boundary: Arc::new(ProductionExternalAgentAuthorityBoundary),
        })
    }

    #[cfg(test)]
    fn for_test(
        host: AgentHostId,
        config_path: &Path,
        governor_executable: &Path,
        executable: &Path,
        process_runner: Arc<dyn ProviderProcessRunner>,
        authority_boundary: Arc<dyn ExternalAgentAuthorityBoundary>,
    ) -> Result<Self> {
        let executable = validate_provider_binary(host, executable)?;
        let version = Some(format!("executable-sha256:{}", sha256_file(&executable)?));
        let adapter_id = adapter_id(host).to_owned();
        let manifest = provider_manifest(host, &adapter_id, Some(&executable));
        Ok(Self {
            host,
            adapter_id,
            executable: Some(executable),
            version,
            governor_executable: governor_executable.to_path_buf(),
            config_path: config_path.to_path_buf(),
            manifest,
            process_runner,
            authority_boundary,
        })
    }

    fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
        Box::pin(async move {
            let installed = self.executable.as_deref().is_some_and(Path::is_file)
                && self
                    .version
                    .as_deref()
                    .is_some_and(|value| !value.is_empty());
            Ok(AdapterHealth {
                adapter_id: self.adapter_id.clone(),
                name: self.manifest.name.clone(),
                state: if installed {
                    AdapterState::Healthy
                } else {
                    AdapterState::Unavailable
                },
                healthy: installed,
                message: if installed {
                    format!(
                        "headless executable installed; authentication requires a live smoke ({})",
                        self.version.as_deref().unwrap_or_default()
                    )
                } else {
                    "headless provider executable not found".to_owned()
                },
                consecutive_failures: 0,
                circuit_open: false,
                checked_at: OffsetDateTime::now_utc(),
            })
        })
    }

    fn execute(
        &self,
        request: AdapterRequest,
        context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult> {
        Box::pin(async move {
            let execution: ExternalAgentExecutionRequest =
                serde_json::from_value(request.input.clone())?;
            validate_external_agent_execution_request(&execution)?;
            if request.context.project_id != execution.invocation.project_id
                || request.context.task_id != execution.invocation.task_id
                || request.context.session_id != execution.launch_contract.agent_session_id
            {
                return Err(eliot_engine::EngineError::WriteRejected(
                    "AdapterContext differs from sealed external-agent authority".to_owned(),
                ));
            }
            self.authority_boundary
                .ensure_dispatch_safe(&self.config_path)
                .await?;
            self.execute_governed(request, execution, context).await
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_governed(
        &self,
        request: AdapterRequest,
        execution: ExternalAgentExecutionRequest,
        context: AdapterExecutionContext,
    ) -> Result<AdapterResult, eliot_engine::EngineError> {
        let PreparedExternalAgentExecution {
            executable,
            provider_hash_before,
            schema,
            cwd,
            plan,
            environment,
            runtime_contract,
        } = self.prepare_governed(&execution, RuntimePreparationMode::Dispatch)?;

        let runtime_root = runtime_root(&self.config_path);
        let attempt_id = format!(
            "external-agent-attempt-{}",
            execution.invocation.invocation_id
        );
        let journal = ProviderInvocationJournal::new(&runtime_root);
        let payload_hash = sha256_bytes(&serde_json::to_vec(&execution)?);
        let execution_request_path =
            persist_external_execution_request(&runtime_root, &execution, &payload_hash)?;
        let mut attempt = journal.create(ProviderInvocationAttempt {
            invocation_attempt_id: attempt_id.clone(),
            provider: self.host.as_str().to_owned(),
            campaign_id: execution.campaign_id.clone(),
            preregistration_id: execution.invocation.verifier_ref.clone(),
            reservation_id: "pending".to_owned(),
            idempotency_key: execution.invocation.idempotency_key.clone(),
            external_invocation_ref: None,
            frozen_input_hash: payload_hash.clone(),
            request_payload_hash: payload_hash,
            route_or_model: Some(execution.requested_model.clone()),
            adapter_version: Some(EXTERNAL_ADAPTER_VERSION.to_owned()),
            executable_or_transport: Some(path_string(&executable)),
            cwd: Some(path_string(&cwd)),
            environment_fingerprint: Some(sha256_bytes(&serde_json::to_vec(&environment)?)),
            timeout_profile_id: execution.provider_route_policy.policy_id().to_owned(),
            provider_route_policy: Some(execution.provider_route_policy.binding()),
            state_transitions: Vec::new(),
            dispatch_started_at: None,
            process_started_at: None,
            provider_ack_at: None,
            first_output_at: None,
            last_output_at: None,
            process_exit_at: None,
            cleanup_completed_at: None,
            stdout_blob_or_hash: None,
            stderr_blob_or_hash: None,
            structured_output_blob_or_hash: None,
            exit_code_or_signal: None,
            process_or_job_identity: None,
            timeout_class: None,
            process_reap_receipt: None,
            process_timed_out: None,
            process_cancelled: None,
            process_worker_error: None,
            stdout_total_bytes: None,
            stderr_total_bytes: None,
            stdout_truncated: None,
            stderr_truncated: None,
            quota_or_cost_if_known: None,
            original_closeout_ref: Some(path_string(&execution_request_path)),
        })?;

        let reservation_owner = ProviderCallReservationOwner::new(&runtime_root);
        let reservation = match reservation_owner.reserve(ProviderCallReservationRequest {
            campaign_id: execution.campaign_id.clone(),
            task_id: execution.invocation.task_id,
            provider: self.host.as_str().to_owned(),
            idempotency_key: execution.invocation.idempotency_key.clone(),
            gate_decision_ref: execution.invocation.verifier_ref.clone(),
        })? {
            ProviderCallReservationDecision::Reserved(reservation) => reservation,
            ProviderCallReservationDecision::IdempotentReplay(reservation) => {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::PreDispatchAborted,
                    vec![format!(
                        "idempotent_replay_redispatch_forbidden:{}",
                        reservation.reservation_id
                    )],
                )?;
                return Err(eliot_engine::EngineError::WriteRejected(
                    "idempotent replay requires canonical-result inspection; redispatch is forbidden"
                        .to_owned(),
                ));
            }
            ProviderCallReservationDecision::BudgetExceeded => {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::PreDispatchAborted,
                    vec!["provider_call_budget_exceeded".to_owned()],
                )?;
                return Err(eliot_engine::EngineError::WriteRejected(
                    "provider call budget exceeded".to_owned(),
                ));
            }
            ProviderCallReservationDecision::CampaignClosed => {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::PreDispatchAborted,
                    vec!["provider_campaign_closed".to_owned()],
                )?;
                return Err(eliot_engine::EngineError::WriteRejected(
                    "provider campaign is closed".to_owned(),
                ));
            }
        };
        attempt.reservation_id = reservation.reservation_id.clone();
        journal.persist(&attempt)?;
        journal.transition(
            &mut attempt,
            ProviderInvocationState::Reserved,
            vec![format!(
                "provider-call-reservation:{}",
                reservation.reservation_id
            )],
        )?;

        let broker_job_id = match self
            .authority_boundary
            .enqueue(&self.config_path, self.host, &execution)
            .await
        {
            Ok(job_id) => job_id,
            Err(error) => {
                let _ = reservation_owner.release_pre_dispatch(
                    &reservation.reservation_id,
                    "HostBroker admission failed before provider dispatch",
                );
                let _ = journal.transition(
                    &mut attempt,
                    ProviderInvocationState::PreDispatchAborted,
                    vec![format!("host_broker_admission_failed:{error}")],
                );
                return Err(error);
            }
        };
        if let Err(error) = self
            .authority_boundary
            .start(&self.config_path, &broker_job_id)
            .await
        {
            let _ = reservation_owner.release_pre_dispatch(
                &reservation.reservation_id,
                "HostBroker failed before provider dispatch",
            );
            let _ = journal.transition(
                &mut attempt,
                ProviderInvocationState::PreDispatchAborted,
                vec![format!("host_broker_start_failed:{error}")],
            );
            return Err(error);
        }
        let worktree_before = worktree_snapshot_if_git(&cwd)?;
        reservation_owner.mark_dispatching(&reservation.reservation_id)?;
        journal.transition(
            &mut attempt,
            ProviderInvocationState::DispatchStarting,
            vec![runtime_contract.runtime_contract_sha256.clone()],
        )?;
        let process_spec = ProviderProcessSpec {
            operation_id: context.operation_id.clone(),
            invocation_id: Some(attempt_id.clone()),
            executable: executable.clone(),
            args: plan.argv.iter().map(OsString::from).collect(),
            cwd: cwd.clone(),
            environment: environment
                .iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                .collect(),
            stdin_payload: None,
            route_policy: execution.provider_route_policy.clone(),
            cancellation: context.cancellation.clone(),
            deadline: context.deadline,
            runtime_contract_sha256: context.runtime_contract_sha256.clone(),
            role_lease_id: context.role_lease_id.clone(),
            role_lease_epoch: context.role_lease_epoch,
        };
        let mut on_spawned = |pid| {
            reservation_owner.mark_dispatched(&reservation.reservation_id, &attempt_id)?;
            let now = OffsetDateTime::now_utc();
            attempt.dispatch_started_at = Some(now);
            attempt.process_started_at = Some(now);
            attempt.external_invocation_ref = Some(attempt_id.clone());
            attempt.process_or_job_identity = Some(format!("pid:{pid}"));
            journal.transition(
                &mut attempt,
                ProviderInvocationState::Dispatched,
                vec![format!("pid:{pid}")],
            )?;
            journal.transition(
                &mut attempt,
                ProviderInvocationState::Running,
                vec![format!("pid:{pid}")],
            )
        };
        let process = self.process_runner.run(process_spec, &mut on_spawned).await;
        let process = match process {
            Ok(process) => process,
            Err(error) => {
                let error_text = error.to_string();
                let state = attempt
                    .state_transitions
                    .last()
                    .map(|transition| transition.to);
                if state == Some(ProviderInvocationState::DispatchStarting) {
                    let _ = reservation_owner.release_pre_dispatch(
                        &reservation.reservation_id,
                        "managed process spawn failed before provider dispatch",
                    );
                    let _ = journal.transition(
                        &mut attempt,
                        ProviderInvocationState::PreDispatchAborted,
                        vec![error.to_string()],
                    );
                } else {
                    let _ = reservation_owner.mark_unknown_outcome(
                        &reservation.reservation_id,
                        "managed process failed after dispatch",
                    );
                    if let Err(journal_error) =
                        record_post_dispatch_supervisor_failure(&journal, &mut attempt, &error_text)
                    {
                        return Err(eliot_engine::EngineError::WriteRejected(format!(
                            "managed provider process failed after dispatch and reconciliation journaling failed; provider redispatch is forbidden; supervisor_error={error_text}; journal_error={journal_error}"
                        )));
                    }
                }
                return Err(eliot_engine::EngineError::WriteRejected(format!(
                    "managed provider process failed: {error_text}"
                )));
            }
        };
        if let Err(error) = record_terminal_process(&journal, &mut attempt, &process) {
            let _ = reservation_owner.mark_unknown_outcome(
                &reservation.reservation_id,
                "process reaped but terminal journal persistence requires reconciliation",
            );
            return Err(error);
        }

        let stdout_capture = ProviderOutputSpool.capture(
            &runtime_root,
            &attempt_id,
            "stdout",
            process.stdout.as_slice(),
            MAX_PROVIDER_OUTPUT_BYTES,
        );
        let stdout_capture = match stdout_capture {
            Ok(capture) => capture,
            Err(error) => {
                let _ = journal.transition(
                    &mut attempt,
                    ProviderInvocationState::LocalCaptureFailed,
                    vec![format!("stdout_capture_failed:{error}")],
                );
                let _ = reservation_owner.fail_after_dispatch(
                    &reservation.reservation_id,
                    "provider stdout capture failed after terminal process facts",
                );
                return Err(error);
            }
        };
        let stderr_capture = ProviderOutputSpool.capture(
            &runtime_root,
            &attempt_id,
            "stderr",
            process.stderr.as_slice(),
            MAX_PROVIDER_OUTPUT_BYTES,
        );
        let stderr_capture = match stderr_capture {
            Ok(capture) => capture,
            Err(error) => {
                let _ = journal.transition(
                    &mut attempt,
                    ProviderInvocationState::LocalCaptureFailed,
                    vec![format!("stderr_capture_failed:{error}")],
                );
                let _ = reservation_owner.fail_after_dispatch(
                    &reservation.reservation_id,
                    "provider stderr capture failed after terminal process facts",
                );
                return Err(error);
            }
        };
        if let Err(error) = journal.record_captured_output(
            &mut attempt,
            stdout_capture.blob_ref.clone(),
            stderr_capture.blob_ref.clone(),
        ) {
            let _ = reservation_owner.mark_unknown_outcome(
                &reservation.reservation_id,
                "captured output refs could not be journaled",
            );
            return Err(error);
        }
        if stdout_capture.output_observed {
            journal.transition(
                &mut attempt,
                ProviderInvocationState::OutputObserved,
                vec![stdout_capture.blob_ref.relative_path.clone()],
            )?;
        }
        let worktree_after = worktree_snapshot_if_git(&cwd)?;
        let read_only_mutation = execution.read_only && worktree_before != worktree_after;

        if process.worker_error.is_some() || !process.reap_receipt.proves_complete_reap() {
            journal.transition(
                &mut attempt,
                ProviderInvocationState::CleanupFailedAfterComplete,
                vec![format!("worker_error:{:?}", process.worker_error)],
            )?;
            reservation_owner.mark_unknown_outcome(
                &reservation.reservation_id,
                "provider process cleanup or supervision failed after dispatch",
            )?;
            return self
                .terminal_result(
                    &request,
                    &execution,
                    &runtime_contract,
                    &process,
                    &stdout_capture,
                    &stderr_capture,
                    None,
                    None,
                    AgentResultStatus::UnknownOutcome,
                    AdapterResultStatus::Failed,
                    true,
                    Some(
                        "provider process cleanup was incomplete; reconciliation required"
                            .to_owned(),
                    ),
                )
                .await;
        }
        if process.timed_out {
            journal.transition(
                &mut attempt,
                ProviderInvocationState::TimeoutPendingReconciliation,
                vec![stdout_capture.blob_ref.relative_path.clone()],
            )?;
            reservation_owner.mark_unknown_outcome(
                &reservation.reservation_id,
                &format!(
                    "provider {:?} timeout requires reconciliation",
                    process.timeout_class
                ),
            )?;
            journal.transition(
                &mut attempt,
                ProviderInvocationState::NonReconcilableUnknown,
                vec!["no provider status lookup is admitted".to_owned()],
            )?;
            return self
                .terminal_result(
                    &request,
                    &execution,
                    &runtime_contract,
                    &process,
                    &stdout_capture,
                    &stderr_capture,
                    None,
                    None,
                    AgentResultStatus::UnknownOutcome,
                    AdapterResultStatus::Timeout,
                    true,
                    Some("provider timed out; outcome is fail-closed and non-retryable".to_owned()),
                )
                .await;
        }
        if process.exit_code != Some(0) || read_only_mutation {
            journal.transition(
                &mut attempt,
                ProviderInvocationState::ProcessExitedNonzero,
                vec![format!(
                    "exit={:?};read_only_mutation={read_only_mutation}",
                    process.exit_code
                )],
            )?;
            reservation_owner.fail_after_dispatch(
                &reservation.reservation_id,
                if read_only_mutation {
                    "read-only provider changed the governed workspace"
                } else {
                    "provider process exited nonzero"
                },
            )?;
            return self
                .terminal_result(
                    &request,
                    &execution,
                    &runtime_contract,
                    &process,
                    &stdout_capture,
                    &stderr_capture,
                    None,
                    None,
                    AgentResultStatus::Failed,
                    AdapterResultStatus::Failed,
                    false,
                    Some(if read_only_mutation {
                        "read-only provider changed the governed workspace".to_owned()
                    } else {
                        provider_failure_message(&process)
                    }),
                )
                .await;
        }

        let parsed = parse_terminal(
            self.host,
            &process.stdout,
            &execution.requested_model,
            &schema,
            plan.structured_output_mode,
        );
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::ProtocolParseFailed,
                    vec![stdout_capture.blob_ref.relative_path.clone()],
                )?;
                reservation_owner.fail_after_dispatch(
                    &reservation.reservation_id,
                    "provider terminal output rejected",
                )?;
                return self
                    .terminal_result(
                        &request,
                        &execution,
                        &runtime_contract,
                        &process,
                        &stdout_capture,
                        &stderr_capture,
                        None,
                        None,
                        AgentResultStatus::Failed,
                        AdapterResultStatus::Failed,
                        false,
                        Some(error.to_string()),
                    )
                    .await;
            }
        };
        let structured_bytes = serde_json::to_vec(&parsed.structured_output)?;
        let structured_capture = ProviderOutputSpool.capture(
            &runtime_root,
            &attempt_id,
            "structured",
            structured_bytes.as_slice(),
            MAX_PROVIDER_OUTPUT_BYTES,
        );
        let structured_capture = match structured_capture {
            Ok(capture) => capture,
            Err(error) => {
                let _ = journal.transition(
                    &mut attempt,
                    ProviderInvocationState::LocalCaptureFailed,
                    vec![format!("structured_capture_failed:{error}")],
                );
                let _ = reservation_owner.fail_after_dispatch(
                    &reservation.reservation_id,
                    "provider structured capture failed after terminal process facts",
                );
                return Err(error);
            }
        };
        attempt.structured_output_blob_or_hash = Some(structured_capture.blob_ref.clone());
        attempt
            .quota_or_cost_if_known
            .clone_from(&parsed.token_or_cost_telemetry);
        let completeness = ExternalResultCompletenessService.evaluate(ProviderCompletenessInput {
            receipt_id: format!("provider-completeness:{attempt_id}"),
            invocation_attempt_ref: attempt_id.clone(),
            raw_output_ref: Some(stdout_capture.blob_ref.relative_path.clone()),
            expected_schema: execution.output_schema_sha256.clone(),
            terminal_marker_or_protocol_status: Some(parsed.terminal_status.clone()),
            required_fields_present: true,
            truncation_detected: false,
            stream_closed_cleanly: true,
            process_exit_success: true,
        });
        if !completeness.result_complete {
            let _ = journal.transition(
                &mut attempt,
                ProviderInvocationState::ProtocolParseFailed,
                vec!["provider_completeness_rejected".to_owned()],
            );
            let _ = reservation_owner.fail_after_dispatch(
                &reservation.reservation_id,
                "provider completeness service rejected terminal result",
            );
            return Err(eliot_engine::EngineError::WriteRejected(
                "provider completeness service rejected a parsed terminal result".to_owned(),
            ));
        }
        journal.transition(
            &mut attempt,
            ProviderInvocationState::CompletedCaptured,
            vec![structured_capture.blob_ref.relative_path.clone()],
        )?;
        let provider_hash_after = engine_anyhow(sha256_file(&executable))?;
        if provider_hash_after != provider_hash_before {
            let _ = journal.transition(
                &mut attempt,
                ProviderInvocationState::CleanupFailedAfterComplete,
                vec!["provider_executable_hash_changed".to_owned()],
            );
            let _ = reservation_owner.fail_after_dispatch(
                &reservation.reservation_id,
                "provider executable hash changed during execution",
            );
            return Err(eliot_engine::EngineError::WriteRejected(
                "provider executable hash changed during execution".to_owned(),
            ));
        }
        let mut result = self
            .terminal_result(
                &request,
                &execution,
                &runtime_contract,
                &process,
                &stdout_capture,
                &stderr_capture,
                Some(&structured_capture),
                Some(parsed),
                AgentResultStatus::Succeeded,
                AdapterResultStatus::Succeeded,
                false,
                None,
            )
            .await?;
        let review_ref = format!("provider-result:{}", result.result_id);
        let closeout = reservation_owner
            .complete(&reservation.reservation_id, &review_ref)
            .and_then(|_| {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::ReviewNormalized,
                    vec![review_ref.clone()],
                )
            });
        if let Err(error) = closeout {
            let _ = journal.transition(
                &mut attempt,
                ProviderInvocationState::CleanupFailedAfterComplete,
                vec![format!("post_canonical_closeout_failed:{error}")],
            );
            result.status = AdapterResultStatus::Failed;
            result.error = Some(AdapterError {
                code: "adapter_closeout_failed".to_owned(),
                message: format!(
                    "provider result is canonical, but reservation/journal closeout failed: {error}"
                ),
                retryable: false,
            });
            if let Some(output) = result.output.as_object_mut() {
                output.insert(
                    "adapter_closeout".to_owned(),
                    json!({
                        "status": "cleanup_failed_after_complete",
                        "error": error.to_string(),
                    }),
                );
            }
        }
        Ok(result)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "runtime preview and dispatch must share one exact preparation boundary"
    )]
    fn prepare_governed(
        &self,
        execution: &ExternalAgentExecutionRequest,
        mode: RuntimePreparationMode,
    ) -> Result<PreparedExternalAgentExecution, eliot_engine::EngineError> {
        let catalog_profile = crate::mcp_stdio::catalog::provider_mcp_tool_profile(
            provider_mcp_access_profile(execution.purpose),
        );
        if execution.mcp_tool_profile != catalog_profile {
            return Err(eliot_engine::EngineError::WriteRejected(
                "provider MCP tool profile differs from the canonical catalog".to_owned(),
            ));
        }
        let executable = self.executable.as_deref().ok_or_else(|| {
            eliot_engine::EngineError::ServiceNotReady {
                service: self.adapter_id.clone(),
                reason: "headless provider executable is not installed".to_owned(),
            }
        })?;
        let executable = std::fs::canonicalize(executable)?;
        let provider_hash_before = engine_anyhow(sha256_file(&executable))?;
        let provider_version =
            self.version
                .clone()
                .ok_or_else(|| eliot_engine::EngineError::ServiceNotReady {
                    service: self.adapter_id.clone(),
                    reason: "provider version probe did not complete".to_owned(),
                })?;
        let prompt_path = canonical_bound_file(&execution.prompt_ref, "provider prompt")?;
        let schema_path =
            canonical_bound_file(&execution.output_schema_ref, "provider output schema")?;
        let prompt_bytes = std::fs::read(&prompt_path)?;
        let schema_bytes = std::fs::read(&schema_path)?;
        require_sha256(
            &prompt_bytes,
            &execution.prompt_sha256,
            "provider prompt SHA-256",
        )?;
        require_sha256(
            &schema_bytes,
            &execution.output_schema_sha256,
            "provider output schema SHA-256",
        )?;
        let prompt = String::from_utf8(prompt_bytes).map_err(|_| {
            eliot_engine::EngineError::WriteRejected(
                "provider prompt must be valid UTF-8".to_owned(),
            )
        })?;
        let schema: Value = serde_json::from_slice(&schema_bytes)?;
        if !schema.is_object() && !schema.is_boolean() {
            return Err(eliot_engine::EngineError::WriteRejected(
                "provider output schema root is invalid".to_owned(),
            ));
        }
        let cwd = std::fs::canonicalize(Path::new(&execution.launch_contract.cwd_or_worktree))?;
        let invocation_root = runtime_root(&self.config_path)
            .join("external-agent")
            .join(safe_component(&execution.invocation.invocation_id));
        let mcp = materialize_provider_mcp(
            self.host,
            &self.governor_executable,
            &self.config_path,
            &cwd,
            &invocation_root,
            execution,
            mode,
        )?;
        let plan = provider_command_plan(
            self.host,
            execution,
            &schema,
            &prompt,
            &mcp.provider_config_path,
            &cwd,
        )?;
        let environment = provider_environment(
            self.host,
            &plan,
            &self.config_path,
            &self.governor_executable,
            execution,
            &mcp,
        );
        let mut runtime_contract = ProviderRuntimeContract {
            schema_version: PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION.to_owned(),
            host: self.host,
            purpose: execution.purpose,
            provider_executable: path_string(&executable),
            provider_executable_sha256: provider_hash_before.clone(),
            provider_version,
            requested_model: execution.requested_model.clone(),
            model_selection_mechanism: plan.model_selection_mechanism.clone(),
            provider_cwd: path_string(&cwd),
            provider_argv: plan.argv.clone(),
            nonsecret_environment: environment.clone(),
            mcp_servers: vec![mcp.contract],
            mcp_tool_profile: execution.mcp_tool_profile.clone(),
            expected_mcp_tool_names: execution.expected_mcp_tool_names.clone(),
            forbidden_mcp_server_names: execution.forbidden_mcp_server_names.clone(),
            allowed_provider_tools: execution.allowed_provider_tools.clone(),
            denied_provider_tools: execution.denied_provider_tools.clone(),
            permission_profile: execution.launch_contract.permission_profile.clone(),
            structured_output_mode: plan.structured_output_mode,
            output_schema_sha256: execution.output_schema_sha256.clone(),
            timeout_profile_ref: execution.timeout_profile_ref.clone(),
            provider_route_policy: execution.provider_route_policy.binding(),
            process_containment: "windows-suspended-kill-on-close-job-object-v1".to_owned(),
            candidate_only: true,
            runtime_contract_sha256: String::new(),
        };
        seal_provider_runtime_contract(&mut runtime_contract)?;
        Ok(PreparedExternalAgentExecution {
            executable,
            provider_hash_before,
            schema,
            cwd,
            plan,
            environment,
            runtime_contract,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::too_many_lines,
        reason = "terminal closeout assembles one canonical evidence and journal transaction"
    )]
    async fn terminal_result(
        &self,
        request: &AdapterRequest,
        execution: &ExternalAgentExecutionRequest,
        runtime_contract: &ProviderRuntimeContract,
        process: &ProviderProcessOutcome,
        stdout: &eliot_engine::ProviderOutputCapture,
        stderr: &eliot_engine::ProviderOutputCapture,
        structured: Option<&eliot_engine::ProviderOutputCapture>,
        parsed: Option<ProviderTerminalResult>,
        agent_status: AgentResultStatus,
        adapter_status: AdapterResultStatus,
        unknown_outcome: bool,
        error_message: Option<String>,
    ) -> Result<AdapterResult, eliot_engine::EngineError> {
        let structured_output = parsed
            .as_ref()
            .map(|parsed| parsed.structured_output.clone());
        let evidence = ProviderExecutionEvidence {
            runtime_contract_sha256: runtime_contract.runtime_contract_sha256.clone(),
            provider_route_policy: execution.provider_route_policy.binding(),
            requested_model: execution.requested_model.clone(),
            resolved_model: parsed
                .as_ref()
                .map_or_else(String::new, |parsed| parsed.resolved_model.clone()),
            provider_session_id: parsed
                .as_ref()
                .map_or_else(String::new, |parsed| parsed.provider_session_id.clone()),
            exit_code: process.exit_code,
            terminal_status: parsed.as_ref().map_or_else(
                || {
                    if process.timed_out {
                        "timeout".to_owned()
                    } else {
                        "failed".to_owned()
                    }
                },
                |parsed| parsed.terminal_status.clone(),
            ),
            unknown_outcome,
            structured_output: structured_output.clone(),
            structured_output_ref: structured.map(|capture| capture.blob_ref.relative_path.clone()),
            structured_output_sha256: structured_output
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()?
                .map(|bytes| sha256_bytes(&bytes)),
            stdout_ref: Some(stdout.blob_ref.relative_path.clone()),
            stdout_sha256: Some(sha256_bytes(&process.stdout)),
            stderr_ref: Some(stderr.blob_ref.relative_path.clone()),
            stderr_sha256: Some(sha256_bytes(&process.stderr)),
            observed_mcp_server_names: vec!["eliot-governor".to_owned()],
            observed_mcp_tool_names: parsed
                .as_ref()
                .map_or_else(Vec::new, |parsed| parsed.observed_tool_names.clone()),
            provider_tool_call_refs: parsed.as_ref().map_or_else(Vec::new, |parsed| {
                parsed
                    .observed_tool_names
                    .iter()
                    .map(|name| format!("provider-tool:{name}"))
                    .collect()
            }),
            changed_paths: Vec::new(),
            diff_ref: None,
            token_or_cost_telemetry: parsed
                .as_ref()
                .and_then(|parsed| parsed.token_or_cost_telemetry.clone()),
            duration_ms: process.reap_receipt.elapsed_ms,
        };
        let agent_result = AgentResultEnvelope {
            result_id: deterministic_external_result_id(execution),
            invocation_id: execution.invocation.invocation_id.clone(),
            host_id: self.host,
            host_session_id: parsed
                .as_ref()
                .map(|parsed| parsed.provider_session_id.clone()),
            status: agent_status,
            role_lease_epoch: execution.invocation.role_lease_epoch,
            operation_generation: execution.invocation.operation_generation,
            summary: error_message
                .clone()
                .unwrap_or_else(|| "provider returned a schema-valid candidate result".to_owned()),
            artifact_refs: [
                evidence.stdout_ref.clone(),
                evidence.stderr_ref.clone(),
                evidence.diff_ref.clone(),
            ]
            .into_iter()
            .flatten()
            .collect(),
            evidence_refs: vec![
                format!(
                    "provider-runtime-contract:{}",
                    runtime_contract.runtime_contract_sha256
                ),
                format!("adapter-request:{}", request.request_id),
            ],
            verifier_refs: vec![execution.invocation.verifier_ref.clone()],
            candidate_only: true,
            exit_status: process.exit_code,
            token_or_cost_telemetry: evidence.token_or_cost_telemetry.clone(),
            unknown_outcome_evidence_refs: if unknown_outcome {
                vec![
                    evidence.stdout_ref.clone().unwrap_or_default(),
                    evidence.stderr_ref.clone().unwrap_or_default(),
                ]
            } else {
                Vec::new()
            },
            supersedes_result_id: None,
            provider_output_hash: evidence.structured_output_sha256.clone(),
            canonical_receipt: None,
        };
        let agent_result = self
            .authority_boundary
            .canonicalize(&self.config_path, execution, agent_result)
            .await?;
        let output = json!({
            "agent_result": agent_result,
            "provider_execution_evidence": evidence,
            "provider_runtime_contract": runtime_contract,
        });
        let result_id = output
            .pointer("/agent_result/result_id")
            .and_then(Value::as_str)
            .unwrap_or("external-agent-result")
            .to_owned();
        let observation = AdapterObservation {
            observation_id: format!("external-agent-observation-{}", Uuid::new_v4()),
            adapter_id: self.adapter_id.clone(),
            result_id: result_id.clone(),
            project_id: request.context.project_id,
            task_id: request.context.task_id,
            summary: output
                .pointer("/agent_result/summary")
                .and_then(Value::as_str)
                .unwrap_or("external agent result")
                .to_owned(),
            payload: output.clone(),
            payload_ref: format!("external-agent-result:{result_id}"),
            raw_blob_ref: Some(stdout.blob_ref.clone()),
            taint: TaintClass::ExternalAgent,
            write_receipt: output
                .pointer("/agent_result/canonical_receipt")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            blackboard_item_id: None,
            mailbox_message_id: None,
            controller_review_required: true,
            generated_at: OffsetDateTime::now_utc(),
        };
        Ok(AdapterResult {
            result_id,
            request_id: request.request_id.clone(),
            adapter_id: self.adapter_id.clone(),
            status: adapter_status,
            output,
            output_blob: None,
            observations: vec![observation],
            error: error_message.map(|message| AdapterError {
                code: if unknown_outcome {
                    "provider_unknown_outcome".to_owned()
                } else {
                    "provider_execution_failed".to_owned()
                },
                message,
                retryable: false,
            }),
            duration_ms: process.reap_receipt.elapsed_ms,
            trace_id: request.context.trace_id.clone(),
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

fn deterministic_external_result_id(execution: &ExternalAgentExecutionRequest) -> String {
    deterministic_external_result_id_from_parts(
        &execution.invocation.invocation_id,
        &execution.invocation.idempotency_key,
    )
}

fn deterministic_external_result_id_from_parts(
    invocation_id: impl AsRef<str>,
    idempotency_key: impl AsRef<str>,
) -> String {
    let semantic_key = format!("{}\0{}", invocation_id.as_ref(), idempotency_key.as_ref());
    format!(
        "external-agent-result:{}",
        blake3::hash(semantic_key.as_bytes()).to_hex()
    )
}

fn canonical_agent_result_write(
    result: &AgentResultEnvelope,
) -> Result<CanonicalAgentResultWrite, eliot_engine::EngineError> {
    if result.canonical_receipt.is_some() {
        return Err(eliot_engine::EngineError::WriteRejected(
            "external AgentResultEnvelope must be unreceipted before canonical write".to_owned(),
        ));
    }
    Ok(CanonicalAgentResultWrite {
        key: format!("managed-provider-result:{}", result.result_id),
        receipt_kind: "agent_result",
        body: serde_json::to_value(result)?,
    })
}

fn existing_receipted_external_result(
    existing: Option<&AgentResultEnvelope>,
    unreceipted_result: &AgentResultEnvelope,
) -> Result<Option<AgentResultEnvelope>, eliot_engine::EngineError> {
    let Some(existing) = existing else {
        return Ok(None);
    };
    let mut existing_semantic = existing.clone();
    existing_semantic.canonical_receipt = None;
    if existing_semantic != *unreceipted_result {
        return Err(eliot_engine::EngineError::WriteRejected(
            "external result replay changed the AgentResultEnvelope".to_owned(),
        ));
    }
    Ok(existing
        .canonical_receipt
        .is_some()
        .then(|| existing.clone()))
}

fn persist_external_execution_request(
    root: &Path,
    execution: &ExternalAgentExecutionRequest,
    payload_hash: &str,
) -> Result<PathBuf, eliot_engine::EngineError> {
    let path = root
        .join("external-agent-requests")
        .join(format!("{payload_hash}.json"));
    engine_anyhow(atomic_write_json(&path, execution))?;
    Ok(path)
}

async fn enqueue_external_agent_broker_invocation(
    config_path: &Path,
    host: AgentHostId,
    execution: &ExternalAgentExecutionRequest,
) -> Result<String, eliot_engine::EngineError> {
    let root = runtime_root(config_path);
    let session_id = execution.launch_contract.agent_session_id.ok_or_else(|| {
        eliot_engine::EngineError::WriteRejected(
            "external invocation lacks governed AgentSession".to_owned(),
        )
    })?;
    let mut state = engine_anyhow(delegation_runtime::load_state(&root))?;
    let binding = state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == session_id)
        .cloned()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "external invocation has no exact AgentSessionHostBinding".to_owned(),
            )
        })?;
    if binding.host_identity.host_id != host {
        return Err(eliot_engine::EngineError::WriteRejected(
            "external invocation host differs from its session binding".to_owned(),
        ));
    }
    let profile = HostProfileService.connected(&binding);
    let work_lease_active = if let Some(work_lease_id) = execution.invocation.work_lease_id {
        let work_state = engine_anyhow(delegation_runtime::load_work_state(&root))?;
        work_state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == work_lease_id)
            .is_some_and(work_lease_is_active)
    } else {
        false
    };
    let job = HostBrokerService.enqueue(
        &mut state,
        &execution.invocation,
        &profile,
        work_lease_active,
    )?;
    // The private observation RPC validates managed job authority against the
    // daemon-owned projection. Publish the adopted invocation/job projection
    // before asking WriterActor for canonical receipts; otherwise the daemon
    // can only see the pre-adoption owner shell and correctly rejects the
    // running-job observation as unbound. A later canonical-write failure is
    // still fenced by the operation-scope close path and is never dispatchable.
    engine_anyhow(delegation_runtime::save_host_broker_state(&root, &state))?;
    super::managed::write_canonical_managed_invocation_request(
        config_path,
        &state,
        &execution.invocation,
    )
    .await
    .map_err(anyhow_engine)?;
    super::managed::write_canonical_managed_job(config_path, &state, &job)
        .await
        .map_err(anyhow_engine)?;
    Ok(job.job_id)
}

async fn start_external_agent_broker_job(
    config_path: &Path,
    job_id: &str,
) -> Result<(), eliot_engine::EngineError> {
    let root = runtime_root(config_path);
    let mut state = engine_anyhow(delegation_runtime::load_state(&root))?;
    let job = state
        .operation_jobs
        .iter_mut()
        .find(|job| job.job_id == job_id)
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "external invocation OperationJob disappeared before dispatch".to_owned(),
            )
        })?;
    if job.state == OperationJobState::Queued {
        HostBrokerService.transition(job, OperationJobState::Running, None)?;
    } else if job.state != OperationJobState::Running {
        return Err(eliot_engine::EngineError::WriteRejected(
            "external invocation OperationJob is not dispatchable".to_owned(),
        ));
    }
    let job = job.clone();
    super::managed::write_canonical_managed_job(config_path, &state, &job)
        .await
        .map_err(anyhow_engine)?;
    engine_anyhow(delegation_runtime::save_host_broker_state(&root, &state))
}

async fn canonicalize_external_agent_broker_result(
    config_path: &Path,
    execution: &ExternalAgentExecutionRequest,
    unreceipted_result: AgentResultEnvelope,
) -> Result<AgentResultEnvelope, eliot_engine::EngineError> {
    let root = runtime_root(config_path);
    let mut state = engine_anyhow(delegation_runtime::load_state(&root))?;
    let existing = state
        .agent_results
        .iter()
        .find(|result| result.result_id == unreceipted_result.result_id);
    if let Some(existing) = existing_receipted_external_result(existing, &unreceipted_result)? {
        return Ok(existing);
    }
    let admission = HostBrokerService.record_result(&mut state, unreceipted_result)?;
    let mut receipted_result = match admission {
        eliot_engine::AgentResultAdmission::Accepted(result) => result,
        eliot_engine::AgentResultAdmission::StaleEvidencePreserved(_) => {
            engine_anyhow(crate::delegation_runtime::save_host_broker_state(
                &root, &state,
            ))?;
            return Err(eliot_engine::EngineError::WriteRejected(
                "stale role epoch or operation generation result preserved as evidence but rejected as current"
                    .to_owned(),
            ));
        }
    };
    let session_id = execution.launch_contract.agent_session_id.ok_or_else(|| {
        eliot_engine::EngineError::WriteRejected(
            "external result lacks governed AgentSession".to_owned(),
        )
    })?;
    let canonical_write = canonical_agent_result_write(&receipted_result)?;
    let (canonical_receipt, _) = write_canonical_host_observation(
        config_path,
        execution.invocation.project_id,
        execution.invocation.task_id,
        session_id,
        &canonical_write.key,
        canonical_write.receipt_kind,
        &canonical_write.body,
    )
    .await
    .map_err(|error| {
        eliot_engine::EngineError::WriteRejected(format!(
            "canonical external-agent observation failed: {error}"
        ))
    })?;
    receipted_result.canonical_receipt = Some(canonical_receipt);
    let stored = state
        .agent_results
        .iter_mut()
        .find(|result| result.result_id == receipted_result.result_id)
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "external AgentResultEnvelope disappeared before receipt binding".to_owned(),
            )
        })?;
    *stored = receipted_result.clone();
    let job = state
        .operation_jobs
        .iter()
        .find(|job| job.invocation_id == receipted_result.invocation_id)
        .cloned()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "external AgentResultEnvelope has no matching OperationJob".to_owned(),
            )
        })?;
    super::managed::write_canonical_managed_job(config_path, &state, &job)
        .await
        .map_err(anyhow_engine)?;
    engine_anyhow(delegation_runtime::save_host_broker_state(&root, &state))?;
    Ok(receipted_result)
}

struct MaterializedMcp {
    contract: ProviderMcpServerContract,
    provider_config_path: PathBuf,
    extra_environment: BTreeMap<String, String>,
}

#[allow(
    clippy::too_many_lines,
    reason = "provider-specific MCP materialization is one fail-closed contract boundary"
)]
fn materialize_provider_mcp(
    host: AgentHostId,
    governor: &Path,
    config_path: &Path,
    cwd: &Path,
    invocation_root: &Path,
    execution: &ExternalAgentExecutionRequest,
    mode: RuntimePreparationMode,
) -> Result<MaterializedMcp, eliot_engine::EngineError> {
    let governor = std::fs::canonicalize(governor)?;
    let governor_sha256 = engine_anyhow(sha256_file(&governor))?;
    let profile = execution.mcp_tool_profile.profile_id.as_str();
    let args = vec![
        "mcp".to_owned(),
        "stdio".to_owned(),
        "--host".to_owned(),
        host.as_str().to_owned(),
        "--profile".to_owned(),
        profile.to_owned(),
        "--instance".to_owned(),
        "default".to_owned(),
    ];
    let scope_environment = scoped_environment(execution);
    let server = json!({
        "command": path_string(&governor),
        "args": args,
        "env": scope_environment,
    });
    let mut extra_environment = BTreeMap::new();
    let provider_config_path = match host {
        AgentHostId::Claude => {
            let path = invocation_root.join("claude-mcp.json");
            if mode == RuntimePreparationMode::Dispatch {
                atomic_write_json(&path, &json!({"mcpServers": {"eliot-governor": server}}))
                    .map_err(anyhow_engine)?;
            }
            path
        }
        AgentHostId::Antigravity => {
            let agents = cwd.join(".agents");
            let path = agents.join("mcp_config.json");
            if path.exists() {
                let current: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                let servers = current
                    .get("mcpServers")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        eliot_engine::EngineError::WriteRejected(
                            "existing Antigravity workspace MCP config is not governed".to_owned(),
                        )
                    })?;
                if servers.len() != 1 || !servers.contains_key("eliot-governor") {
                    return Err(eliot_engine::EngineError::WriteRejected(
                        "Antigravity workspace must expose exactly one Governor MCP server"
                            .to_owned(),
                    ));
                }
            }
            if mode == RuntimePreparationMode::Dispatch {
                ensure_antigravity_permissions(invocation_root)?;
                std::fs::create_dir_all(&agents)?;
                atomic_write_json(&path, &json!({"mcpServers": {"eliot-governor": server}}))
                    .map_err(anyhow_engine)?;
            }
            path
        }
        AgentHostId::OpenCode => {
            let config_dir = invocation_root.join("opencode-config");
            let path = config_dir.join("opencode.json");
            let command = std::iter::once(path_string(&governor))
                .chain(args.iter().cloned())
                .collect::<Vec<_>>();
            if mode == RuntimePreparationMode::Dispatch {
                std::fs::create_dir_all(&config_dir)?;
                atomic_write_json(
                    &path,
                    &json!({
                        "$schema": "https://opencode.ai/config.json",
                        "mcp": {
                            "eliot-governor": {
                                "type": "local",
                                "command": command,
                                "enabled": true,
                                "timeout": 30000,
                                "environment": scope_environment
                            }
                        }
                    }),
                )
                .map_err(anyhow_engine)?;
            }
            extra_environment.insert("OPENCODE_CONFIG_DIR".to_owned(), path_string(&config_dir));
            let xdg = invocation_root.join("opencode-xdg");
            if mode == RuntimePreparationMode::Dispatch {
                std::fs::create_dir_all(&xdg)?;
            }
            extra_environment.insert("XDG_CONFIG_HOME".to_owned(), path_string(&xdg));
            path
        }
        AgentHostId::Codex => {
            return Err(eliot_engine::EngineError::WriteRejected(
                "Codex is not an external provider adapter".to_owned(),
            ));
        }
    };
    let contract = ProviderMcpServerContract {
        name: "eliot-governor".to_owned(),
        command: path_string(&governor),
        args,
        cwd: path_string(cwd),
        required: true,
        enabled: true,
        executable_sha256: governor_sha256,
        build_source_commit: source_commit(cwd),
    };
    let _ = config_path;
    Ok(MaterializedMcp {
        contract,
        provider_config_path,
        extra_environment,
    })
}

fn ensure_antigravity_permissions(invocation_root: &Path) -> Result<(), eliot_engine::EngineError> {
    let profile = std::env::var_os("USERPROFILE").ok_or_else(|| {
        eliot_engine::EngineError::WriteRejected(
            "Antigravity permission merge requires the real USERPROFILE".to_owned(),
        )
    })?;
    let settings = PathBuf::from(profile)
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json");
    let existing_bytes = if settings.is_file() {
        std::fs::read(&settings)?
    } else {
        b"{}\n".to_vec()
    };
    let mut value: Value = serde_json::from_slice(&existing_bytes)?;
    let root = value.as_object_mut().ok_or_else(|| {
        eliot_engine::EngineError::WriteRejected(
            "Antigravity CLI settings root is not an object".to_owned(),
        )
    })?;
    let permissions = root
        .entry("permissions")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "Antigravity CLI permissions field is not an object".to_owned(),
            )
        })?;
    let allow = permissions
        .entry("allow")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "Antigravity CLI permissions.allow is not an array".to_owned(),
            )
        })?;
    let mut added = Vec::new();
    for tool in crate::mcp_stdio::EXTERNAL_AUDITOR_TOOLS {
        let rule = format!("mcp(eliot-governor/{tool})");
        if !allow.iter().any(|value| value.as_str() == Some(&rule)) {
            allow.push(Value::String(rule.clone()));
            added.push(rule);
        }
    }
    let deny = permissions
        .entry("deny")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "Antigravity CLI permissions.deny is not an array".to_owned(),
            )
        })?;
    for rule in [
        "mcp(eliot_surrealdb/*)",
        "mcp(surrealdb/*)",
        "read_file(.git/)",
    ] {
        if !deny.iter().any(|value| value.as_str() == Some(rule)) {
            deny.push(Value::String(rule.to_owned()));
            added.push(rule.to_owned());
        }
    }
    let merged = serde_json::to_vec_pretty(&value)?;
    let before_hash = sha256_bytes(&existing_bytes);
    let after_hash = sha256_bytes(&merged);
    if before_hash != after_hash {
        std::fs::create_dir_all(invocation_root)?;
        atomic_write_bytes(
            &invocation_root.join("antigravity-settings-before.json"),
            &existing_bytes,
        )
        .map_err(anyhow_engine)?;
        atomic_write_bytes(&settings, &merged).map_err(anyhow_engine)?;
    }
    atomic_write_json(
        &invocation_root.join("antigravity-permission-install-receipt.json"),
        &json!({
            "schema_version": "eliot-antigravity-permission-install-v1",
            "settings_path": path_string(&settings),
            "before_sha256": before_hash,
            "after_sha256": after_hash,
            "added_rules": added,
            "wildcard_mcp_allow_added": false,
            "credentials_read_or_copied": false,
            "rollback_source": path_string(&invocation_root.join("antigravity-settings-before.json")),
        }),
    )
    .map_err(anyhow_engine)?;
    Ok(())
}

fn provider_command_plan(
    host: AgentHostId,
    execution: &ExternalAgentExecutionRequest,
    schema: &Value,
    prompt: &str,
    mcp_config: &Path,
    cwd: &Path,
) -> Result<ProviderCommandPlan, eliot_engine::EngineError> {
    match host {
        AgentHostId::Claude => build_claude_code_command(&ClaudeCodeCommandInput {
            requested_model: execution.requested_model.clone(),
            output_schema: schema.clone(),
            mcp_config_path: path_string(mcp_config),
            allowed_tools: execution.allowed_provider_tools.clone(),
            denied_tools: execution.denied_provider_tools.clone(),
            max_turns: execution.max_turns_or_steps,
            prompt: prompt.to_owned(),
        }),
        AgentHostId::Antigravity => build_antigravity_command(&AntigravityCommandInput {
            requested_model: execution.requested_model.clone(),
            workspace: path_string(cwd),
            output_schema: schema.clone(),
            max_runtime_seconds: execution.launch_contract.wall_clock_budget_seconds,
            prompt: prompt.to_owned(),
            native_json_schema: true,
            read_only: execution.read_only,
        }),
        AgentHostId::OpenCode => build_opencode_command(&OpenCodeCommandInput {
            requested_model: execution.requested_model.clone(),
            workspace: path_string(cwd),
            prompt: prompt.to_owned(),
            read_only: execution.read_only,
        }),
        AgentHostId::Codex => Err(eliot_engine::EngineError::WriteRejected(
            "Codex is not an external provider adapter".to_owned(),
        )),
    }
}

fn parse_terminal(
    host: AgentHostId,
    stdout: &[u8],
    requested_model: &str,
    schema: &Value,
    mode: ProviderStructuredOutputMode,
) -> Result<ProviderTerminalResult, eliot_engine::EngineError> {
    match host {
        AgentHostId::Claude => parse_claude_code_stream(stdout, requested_model, schema),
        AgentHostId::Antigravity => parse_antigravity_output(stdout, requested_model, schema, mode),
        AgentHostId::OpenCode => parse_opencode_stream(stdout, requested_model, schema),
        AgentHostId::Codex => Err(eliot_engine::EngineError::WriteRejected(
            "Codex is not an external provider adapter".to_owned(),
        )),
    }
}

fn provider_environment(
    host: AgentHostId,
    plan: &ProviderCommandPlan,
    config_path: &Path,
    governor: &Path,
    execution: &ExternalAgentExecutionRequest,
    mcp: &MaterializedMcp,
) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::new();
    for name in SAFE_INHERITED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            environment.insert((*name).to_owned(), value.to_string_lossy().into_owned());
        }
    }
    environment.extend(plan.nonsecret_environment.clone());
    environment.extend(mcp.extra_environment.clone());
    environment.extend(scoped_environment(execution));
    environment.insert("ELIOT_GOVERNOR_EXE".to_owned(), path_string(governor));
    environment.insert("ELIOT_GOVERNOR_CONFIG".to_owned(), path_string(config_path));
    if host == AgentHostId::Antigravity
        && execution.purpose != ExternalAgentPurpose::CognitiveWorker
    {
        environment.insert(
            "ELIOT_MCP_ACCESS_PROFILE".to_owned(),
            execution.mcp_tool_profile.profile_id.clone(),
        );
    }
    environment
}

fn scoped_environment(execution: &ExternalAgentExecutionRequest) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::new();
    if let Some(session) = execution.launch_contract.agent_session_id {
        environment.insert("ELIOT_AGENT_SESSION_ID".to_owned(), session.to_string());
    }
    environment.insert(
        "ELIOT_PROJECT_ID".to_owned(),
        execution.invocation.project_id.to_string(),
    );
    environment.insert(
        "ELIOT_TASK_ID".to_owned(),
        execution.invocation.task_id.to_string(),
    );
    environment.insert(
        "ELIOT_WORK_ITEM_ID".to_owned(),
        execution.invocation.work_item_id.to_string(),
    );
    environment.insert(
        "ELIOT_ROLE_LEASE_ID".to_owned(),
        execution.invocation.role_lease_id.clone(),
    );
    if let Some(lease) = execution.invocation.work_lease_id {
        environment.insert("ELIOT_WORK_LEASE_ID".to_owned(), lease.to_string());
    }
    if execution.purpose == ExternalAgentPurpose::MemoryFreeControl {
        environment.insert("ELIOT_COGNITIVE_CONTROL".to_owned(), "1".to_owned());
    }
    environment
}

fn provider_manifest(
    host: AgentHostId,
    adapter_id: &str,
    executable: Option<&Path>,
) -> eliot_types::CapabilityManifest {
    eliot_types::CapabilityManifest {
        adapter_id: adapter_id.to_owned(),
        name: format!("{} headless CLI adapter", host.as_str()),
        version: EXTERNAL_ADAPTER_VERSION.to_owned(),
        description: "governed candidate-only external provider runtime".to_owned(),
        adapter_class: AdapterClass::ExternalCandidate,
        capabilities: vec![
            AdapterCapability::HealthCheck,
            AdapterCapability::EmitCandidateObservation,
            AdapterCapability::EmitArtifactHandle,
            AdapterCapability::RequestControllerReview,
        ],
        authority_profile: AdapterAuthorityProfile {
            allowed_projects: Vec::new(),
            allowed_roles: vec![
                AgentRole::Implementer,
                AgentRole::Reviewer,
                AgentRole::Auditor,
            ],
            allowed_capabilities: vec![
                AdapterCapability::HealthCheck,
                AdapterCapability::EmitCandidateObservation,
                AdapterCapability::EmitArtifactHandle,
                AdapterCapability::RequestControllerReview,
            ],
            can_write_truth: false,
            can_request_patch: false,
            can_finish_task: false,
        },
        limits: AdapterLimits {
            timeout_ms: 915_000,
            max_payload_bytes: 262_144,
            max_output_bytes: 1_048_576,
            max_concurrent_requests: 1,
            circuit_breaker_failures: 2,
        },
        enabled_by_default: true,
        process_policy: ProcessExecutionPolicy {
            process_spawn_allowed: true,
            allowed_executables: executable.map(path_string).into_iter().collect::<Vec<_>>(),
            inherit_environment: false,
            network_allowed: true,
        },
    }
}

fn discover_provider_binary(host: AgentHostId) -> Result<Option<PathBuf>> {
    let explicit = match host {
        AgentHostId::Claude => "ELIOT_CLAUDE_CODE_EXE",
        AgentHostId::Antigravity => "ELIOT_ANTIGRAVITY_EXE",
        AgentHostId::OpenCode => "ELIOT_OPENCODE_EXE",
        AgentHostId::Codex => return Ok(None),
    };
    if let Some(path) = std::env::var_os(explicit).map(PathBuf::from) {
        return validate_provider_binary(host, &path).map(Some);
    }
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let candidates = match (host, local.as_deref()) {
        (AgentHostId::Claude, Some(local)) => discover_winget_claude(local),
        (AgentHostId::Antigravity, Some(local)) => {
            vec![local.join("agy").join("bin").join("agy.exe")]
        }
        (AgentHostId::OpenCode, Some(local)) => {
            vec![local.join("OpenCode").join("opencode-cli.exe")]
        }
        _ => Vec::new(),
    };
    for candidate in candidates {
        if candidate.is_file() {
            return validate_provider_binary(host, &candidate).map(Some);
        }
    }
    let names: &[&str] = match host {
        AgentHostId::Claude => &["claude"],
        AgentHostId::Antigravity => &["agy", "antigravity"],
        AgentHostId::OpenCode => &["opencode-cli", "opencode"],
        AgentHostId::Codex => &[],
    };
    for name in names {
        if let Some(path) = where_executable(name)? {
            return validate_provider_binary(host, &path).map(Some);
        }
    }
    Ok(None)
}

fn discover_winget_claude(local: &Path) -> Vec<PathBuf> {
    let root = local.join("Microsoft").join("WinGet").join("Packages");
    std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("Anthropic.ClaudeCode_")
        })
        .map(|entry| entry.path().join("claude.exe"))
        .collect()
}

fn where_executable(name: &str) -> Result<Option<PathBuf>> {
    let output = Command::new("where.exe").arg(name).output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(PathBuf::from))
}

fn validate_provider_binary(host: AgentHostId, path: &Path) -> Result<PathBuf> {
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("canonicalize provider executable {}", path.display()))?;
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rejected = match host {
        AgentHostId::Claude => {
            lower.contains(r"\windowsapps\")
                || lower.contains(r"\program files\claude\")
                || name == "claude desktop.exe"
        }
        AgentHostId::Antigravity => name != "agy.exe",
        AgentHostId::OpenCode => name == "opencode.exe" || name == "opencode",
        AgentHostId::Codex => true,
    };
    anyhow::ensure!(
        !rejected,
        "{} is not an admitted headless {} executable",
        path.display(),
        host.as_str()
    );
    Ok(path)
}

fn canonical_bound_file(value: &str, label: &str) -> Result<PathBuf, eliot_engine::EngineError> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(eliot_engine::EngineError::WriteRejected(format!(
            "{label} path is not absolute"
        )));
    }
    std::fs::canonicalize(path).map_err(eliot_engine::EngineError::from)
}

fn require_sha256(
    bytes: &[u8],
    expected: &str,
    label: &str,
) -> Result<(), eliot_engine::EngineError> {
    let actual = sha256_bytes(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(eliot_engine::EngineError::WriteRejected(format!(
            "{label} differs: expected={expected} actual={actual}"
        )))
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn adapter_id(host: AgentHostId) -> &'static str {
    match host {
        AgentHostId::Claude => "external-agent:claude",
        AgentHostId::Antigravity => "external-agent:antigravity",
        AgentHostId::OpenCode => "external-agent:opencode",
        AgentHostId::Codex => "external-agent:codex-forbidden",
    }
}

fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn engine_anyhow<T>(result: Result<T>) -> Result<T, eliot_engine::EngineError> {
    result.map_err(anyhow_engine)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the signature is used directly as an anyhow Result::map_err callback"
)]
fn anyhow_engine(error: anyhow::Error) -> eliot_engine::EngineError {
    eliot_engine::EngineError::WriteRejected(error.to_string())
}

fn source_commit(cwd: &Path) -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(cwd)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn worktree_snapshot_if_git(
    cwd: &Path,
) -> Result<Option<(String, String)>, eliot_engine::EngineError> {
    if !cwd.join(".git").exists() {
        return Ok(None);
    }
    let status = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_dir(cwd)
        .output()?;
    let diff = Command::new("git")
        .args(["diff", "--binary", "--no-ext-diff"])
        .current_dir(cwd)
        .output()?;
    if !status.status.success() || !diff.status.success() {
        return Err(eliot_engine::EngineError::WriteRejected(
            "failed to snapshot governed provider worktree".to_owned(),
        ));
    }
    Ok(Some((
        sha256_bytes(&status.stdout),
        sha256_bytes(&diff.stdout),
    )))
}

fn provider_failure_message(process: &ProviderProcessOutcome) -> String {
    let stderr = String::from_utf8_lossy(&process.stderr);
    if stderr
        .to_ascii_lowercase()
        .contains("not logged into antigravity")
        || stderr
            .to_ascii_lowercase()
            .contains("not logged in to antigravity")
    {
        "BLOCKED_PROVIDER_AUTH_ANTIGRAVITY".to_owned()
    } else if stderr.to_ascii_lowercase().contains("not logged in")
        || stderr.to_ascii_lowercase().contains("authentication")
    {
        "provider CLI is unauthenticated".to_owned()
    } else {
        format!("provider process exited {:?}", process.exit_code)
    }
}

#[cfg(test)]
pub(super) fn external_adapter_manifest_fixture(
    host: AgentHostId,
) -> eliot_types::CapabilityManifest {
    provider_manifest(host, adapter_id(host), None)
}

#[cfg(test)]
pub(super) fn canonical_external_result_contract_fixture() -> Result<Value> {
    let result = AgentResultEnvelope {
        result_id: deterministic_external_result_id_from_parts(
            "fixture-invocation",
            "fixture-idempotency",
        ),
        invocation_id: "fixture-invocation".to_owned(),
        host_id: AgentHostId::Claude,
        host_session_id: Some("fixture-provider-session".to_owned()),
        status: AgentResultStatus::Succeeded,
        role_lease_epoch: 1,
        operation_generation: 1,
        summary: "fixture candidate result".to_owned(),
        artifact_refs: Vec::new(),
        evidence_refs: vec!["fixture-evidence".to_owned()],
        verifier_refs: vec!["fixture-verifier".to_owned()],
        candidate_only: true,
        exit_status: Some(0),
        token_or_cost_telemetry: None,
        unknown_outcome_evidence_refs: Vec::new(),
        supersedes_result_id: None,
        provider_output_hash: Some("a".repeat(64)),
        canonical_receipt: None,
    };
    let write = canonical_agent_result_write(&result)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut receipted = result.clone();
    receipted.canonical_receipt = Some(eliot_types::WriteReceiptRef {
        receipt_id: eliot_types::ReceiptId::new_v7(),
        write_id: eliot_types::WriteId::new_v7(),
    });
    let accepted_replay = existing_receipted_external_result(Some(&receipted), &result)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut changed = result.clone();
    changed.summary.push_str(" changed");
    let changed_replay_rejected =
        existing_receipted_external_result(Some(&receipted), &changed).is_err();
    Ok(json!({
        "first_result_id": result.result_id,
        "same_result_id": deterministic_external_result_id_from_parts(
            "fixture-invocation",
            "fixture-idempotency",
        ),
        "different_result_id": deterministic_external_result_id_from_parts(
            "fixture-invocation",
            "different-idempotency",
        ),
        "key": write.key,
        "receipt_kind": write.receipt_kind,
        "body": write.body,
        "receipted_replay_accepted": accepted_replay
            .as_ref()
            .and_then(|result| result.canonical_receipt.as_ref())
            .is_some(),
        "changed_replay_rejected": changed_replay_rejected,
    }))
}

#[cfg(test)]
mod mcp_smoke_tests {
    use super::*;

    #[test]
    fn smoke_prompt_requires_the_bound_scope_only() {
        let prompt = mcp_smoke_prompt("opencode/mimo-v2.5-free");
        assert!(
            prompt.contains(
                "exactly once with the sole argument {\"scope\":\"memory_free_control\"}"
            )
        );
        assert!(!prompt.contains("{\"project_id\""));
        assert!(!prompt.contains("{\"task_id\""));
        assert!(prompt.contains("without Markdown fences or prose"));
        assert!(prompt.contains("resolved_model=opencode/mimo-v2.5-free"));
    }

    #[test]
    fn provider_revision_may_advance_inside_the_execution_window() {
        assert!(memory_revision_within_execution_window(3, 6, 8));
        assert!(memory_revision_within_execution_window(3, 3, 3));
        assert!(!memory_revision_within_execution_window(3, 2, 8));
        assert!(!memory_revision_within_execution_window(3, 9, 8));
    }

    #[test]
    fn phase_trace_attributes_an_aborted_phase() -> Result<()> {
        let root = std::env::temp_dir().join(format!("eliot-smoke-phase-test-{}", Uuid::now_v7()));
        let trace = SmokePhaseTrace::new(&root, "phase-test")?;
        trace.start("current_state_preflight")?;
        trace.abort_active("test deadline")?;
        let entries = std::fs::read_to_string(trace.path())?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["status"], "started");
        assert_eq!(entries[1]["status"], "aborted");
        assert_eq!(entries[1]["phase"], "current_state_preflight");
        assert_eq!(entries[1]["detail"], "test deadline");
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }
}

#[cfg(test)]
mod provider_runtime_tests {
    use super::*;
    use crate::host_runtime::supervised_process::ScriptedProviderProcessRunner;
    use eliot_types::{
        AdapterContext, AgentSessionId, HostLaunchContract, ProcessReapReceipt,
        ProviderDeclaredBudget, ProviderRoutePolicy, ReceiptId, WorkItemId, WorkLeaseId, WriteId,
    };

    #[derive(Default)]
    struct RecordingAuthorityBoundary {
        phases: Mutex<Vec<&'static str>>,
    }

    impl RecordingAuthorityBoundary {
        fn phases(&self) -> Vec<&'static str> {
            self.phases
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn record(&self, phase: &'static str) {
            self.phases
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(phase);
        }
    }

    impl ExternalAgentAuthorityBoundary for RecordingAuthorityBoundary {
        fn ensure_dispatch_safe<'a>(&'a self, _config_path: &'a Path) -> BoxAdapterFuture<'a, ()> {
            Box::pin(async move {
                self.record("integrity");
                Ok(())
            })
        }

        fn enqueue<'a>(
            &'a self,
            _config_path: &'a Path,
            _host: AgentHostId,
            execution: &'a ExternalAgentExecutionRequest,
        ) -> BoxAdapterFuture<'a, String> {
            Box::pin(async move {
                self.record("enqueue");
                Ok(execution.invocation.invocation_id.clone())
            })
        }

        fn start<'a>(
            &'a self,
            _config_path: &'a Path,
            _job_id: &'a str,
        ) -> BoxAdapterFuture<'a, ()> {
            Box::pin(async move {
                self.record("start");
                Ok(())
            })
        }

        fn canonicalize<'a>(
            &'a self,
            _config_path: &'a Path,
            _execution: &'a ExternalAgentExecutionRequest,
            mut result: AgentResultEnvelope,
        ) -> BoxAdapterFuture<'a, AgentResultEnvelope> {
            Box::pin(async move {
                self.record("canonicalize");
                result.canonical_receipt = Some(eliot_types::WriteReceiptRef {
                    receipt_id: ReceiptId::new_v7(),
                    write_id: WriteId::new_v7(),
                });
                Ok(result)
            })
        }
    }

    struct RouteFixture {
        root: PathBuf,
        supervisor: AdapterSupervisor,
        runner: Arc<ScriptedProviderProcessRunner>,
        provider_runtime: super::super::ProviderRuntime,
        authority: Arc<RecordingAuthorityBoundary>,
        request: AdapterRequest,
        attempt_id: String,
    }

    fn antigravity_native_output() -> Vec<u8> {
        concat!(
            "{\"event\":\"init\",\"conversation_id\":\"agy-route-test\",",
            "\"init\":{\"model\":\"gemini-3.6-flash-high\"}}\n",
            "{\"event\":\"step_update\",\"step_update\":{\"step_type\":\"tool\",",
            "\"tool_name\":\"call_mcp_tool\",\"tool_info\":{\"parameters\":{",
            "\"ServerName\":\"eliot-governor\",\"ToolName\":\"eliot_current_state\"}}}}\n",
            "{\"event\":\"result\",\"result\":{\"conversation_id\":\"agy-route-test\",",
            "\"status\":\"SUCCESS\",\"structured_output\":{\"status\":\"ready\",",
            "\"resolved_model\":\"gemini-3.6-flash-high\"}}}\n"
        )
        .as_bytes()
        .to_vec()
    }

    fn provider_model(host: AgentHostId) -> &'static str {
        match host {
            AgentHostId::Claude => "claude-opus-5",
            AgentHostId::Antigravity => "gemini-3.6-flash-high",
            AgentHostId::OpenCode => "opencode/mimo-v2.5-free",
            AgentHostId::Codex => unreachable!("Codex has no external provider route"),
        }
    }

    fn provider_executable_name(host: AgentHostId) -> &'static str {
        match host {
            AgentHostId::Claude => "claude.exe",
            AgentHostId::Antigravity => "agy.exe",
            AgentHostId::OpenCode => "opencode-headless.cmd",
            AgentHostId::Codex => unreachable!("Codex has no external provider route"),
        }
    }

    fn provider_native_output(host: AgentHostId) -> Vec<u8> {
        match host {
            AgentHostId::Claude => concat!(
                "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"tool_use\",",
                "\"name\":\"mcp__eliot-governor__eliot_current_state\"}]}}\n",
                "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,",
                "\"session_id\":\"claude-route-test\",\"model\":\"claude-opus-5\",",
                "\"structured_output\":{\"status\":\"ready\",",
                "\"resolved_model\":\"claude-opus-5\"}}\n"
            )
            .as_bytes()
            .to_vec(),
            AgentHostId::Antigravity => antigravity_native_output(),
            AgentHostId::OpenCode => concat!(
                "{\"type\":\"step_start\",\"sessionID\":\"opencode-route-test\",",
                "\"part\":{\"type\":\"step-start\"}}\n",
                "{\"type\":\"tool_use\",\"sessionID\":\"opencode-route-test\",",
                "\"part\":{\"type\":\"tool\",\"tool\":\"eliot_current_state\",",
                "\"state\":{\"status\":\"completed\"}}}\n",
                "{\"type\":\"text\",\"sessionID\":\"opencode-route-test\",",
                "\"part\":{\"type\":\"text\",\"text\":",
                "\"{\\\"status\\\":\\\"ready\\\",\\\"resolved_model\\\":",
                "\\\"opencode/mimo-v2.5-free\\\"}\"}}\n",
                "{\"type\":\"step_finish\",\"sessionID\":\"opencode-route-test\",",
                "\"part\":{\"type\":\"step-finish\",\"reason\":\"stop\"}}\n"
            )
            .as_bytes()
            .to_vec(),
            AgentHostId::Codex => unreachable!("Codex has no external provider route"),
        }
    }

    fn scripted_outcome(
        stdout: Vec<u8>,
        timed_out: bool,
        forced_termination: bool,
    ) -> ProviderProcessOutcome {
        let now = OffsetDateTime::now_utc();
        let stdout_len = u64::try_from(stdout.len()).unwrap_or(u64::MAX);
        ProviderProcessOutcome {
            exit_code: (!timed_out).then_some(0),
            stdout,
            stderr: Vec::new(),
            stdout_total_bytes: stdout_len,
            stderr_total_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out,
            timeout_class: timed_out.then_some(ProviderTimeoutClass::FirstOutputTimeout),
            cancelled: timed_out,
            worker_error: None,
            observed_processes: Vec::new(),
            process_started_at: now,
            first_output_at: (!timed_out).then_some(now),
            last_output_at: (!timed_out).then_some(now),
            process_exit_at: Some(now),
            cleanup_completed_at: now,
            reap_receipt: ProcessReapReceipt {
                operation_id: "scripted-provider-route".to_owned(),
                generation: 1,
                job_object_name: "scripted-job".to_owned(),
                root_pid: Some(42_424),
                process_count_before: 1,
                process_count_after: 0,
                graceful_attempted: true,
                forced_termination,
                stdout_closed: true,
                stderr_closed: true,
                all_tasks_joined: true,
                elapsed_ms: 20,
                terminal_error_codes: Vec::new(),
            },
        }
    }

    fn route_fixture(
        outcomes: Vec<ProviderProcessOutcome>,
        completion_delay: Duration,
    ) -> Result<RouteFixture> {
        route_fixture_for(
            AgentHostId::Antigravity,
            ExternalAgentPurpose::UnderstandingReader,
            outcomes,
            completion_delay,
            true,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn route_fixture_for(
        host: AgentHostId,
        purpose: ExternalAgentPurpose,
        outcomes: Vec<ProviderProcessOutcome>,
        completion_delay: Duration,
        open_campaign: bool,
    ) -> Result<RouteFixture> {
        let root = std::env::temp_dir().join(format!("eliot-provider-route-{}", Uuid::now_v7()));
        let config_path = root.join("config/governor.toml");
        let cwd = root.join("workspace");
        std::fs::create_dir_all(config_path.parent().context("config parent")?)?;
        std::fs::create_dir_all(&cwd)?;
        std::fs::write(&config_path, b"# provider route fixture\n")?;
        let executable = root.join(provider_executable_name(host));
        let governor = root.join("eliot-governor.exe");
        std::fs::write(
            &executable,
            format!("scripted {} executable", host.as_str()),
        )?;
        std::fs::write(&governor, b"scripted governor executable")?;
        let executable = std::fs::canonicalize(executable)?;
        let governor = std::fs::canonicalize(governor)?;
        let cwd = std::fs::canonicalize(cwd)?;
        let prompt_path = root.join("prompt.txt");
        let schema_path = root.join("schema.json");
        let prompt = "Return the exact schema-valid result.";
        let model = provider_model(host);
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["status", "resolved_model"],
            "properties": {
                "status": {"const": "ready"},
                "resolved_model": {"const": model}
            }
        });
        std::fs::write(&prompt_path, prompt)?;
        std::fs::write(&schema_path, serde_json::to_vec(&schema)?)?;
        let prompt_path = std::fs::canonicalize(prompt_path)?;
        let schema_path = std::fs::canonicalize(schema_path)?;
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let agent_session_id = AgentSessionId::new_v7();
        let work_item_id = WorkItemId::new_v7();
        let invocation_id = format!("provider-route-{}", Uuid::now_v7());
        let route_policy = ProviderRoutePolicy::for_route(
            host,
            "provider-runtime-test",
            ProviderDeclaredBudget::new(10_000, MAX_PROVIDER_OUTPUT_BYTES)
                .with_first_output_deadline_ms(Some(8_000))
                .with_cancellation_grace_ms(10)
                .with_cleanup_grace_ms(10),
        );
        let mcp_access_profile = provider_mcp_access_profile(purpose);
        let mcp_tool_profile =
            crate::mcp_stdio::catalog::provider_mcp_tool_profile(mcp_access_profile);
        let worker = purpose == ExternalAgentPurpose::CognitiveWorker;
        let work_lease_id = worker.then(WorkLeaseId::new_v7);
        let launch_contract = HostLaunchContract {
            invocation_id: invocation_id.clone(),
            host_profile_ref: format!("test:{}", host.as_str()),
            mode: HostMode::Supervised,
            project_id: Some(project_id),
            agent_session_id: Some(agent_session_id),
            task_id: Some(task_id),
            work_item_id: Some(work_item_id),
            role_lease_id: Some("provider-route-role".to_owned()),
            role_lease_epoch: 1,
            operation_generation: 1,
            work_lease_id,
            worktree_lease_id: None,
            planned_verifier_ref: Some("provider-route-verifier".to_owned()),
            cwd_or_worktree: path_string(&cwd),
            baseline_commit: None,
            allowed_paths: worker.then(|| path_string(&cwd)).into_iter().collect(),
            forbidden_paths: vec!["raw-database".to_owned()],
            integration_bundle_ref: path_string(&root),
            mcp_config_ref: path_string(&root.join("provider-mcp.json")),
            skill_bundle_ref: path_string(&root.join("skills")),
            lifecycle_bridge_ref: "external-agent-adapter".to_owned(),
            environment_allowlist: SAFE_INHERITED_ENVIRONMENT
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            permission_profile: if worker {
                "cognitive_child"
            } else {
                "external_auditor"
            }
            .to_owned(),
            model_route_if_selected: Some(model.to_owned()),
            max_turns_or_steps: Some(4),
            wall_clock_budget_seconds: 1,
            cost_budget_if_supported: None,
            session_id: None,
            resume_policy: "fresh_only".to_owned(),
            structured_output_schema_ref: Some(path_string(&schema_path)),
            stdout_stderr_spool: path_string(&root.join("spool")),
            artifact_manifest_ref: path_string(&root.join("artifacts.json")),
            idempotency_key: invocation_id.clone(),
            expected_result_kind: "provider_execution_evidence".to_owned(),
            contract_hash: "a".repeat(64),
        };
        let execution = ExternalAgentExecutionRequest {
            invocation: eliot_types::AgentInvocationRequest {
                invocation_id: invocation_id.clone(),
                project_id,
                task_id,
                work_item_id,
                requested_capabilities: vec!["emit_candidate_observation".to_owned()],
                role_lease_id: "provider-route-role".to_owned(),
                role_lease_epoch: 1,
                operation_generation: 1,
                runtime_contract_sha256: Some("a".repeat(64)),
                work_lease_id,
                packet_refs: Vec::new(),
                expected_result_kind: "provider_execution_evidence".to_owned(),
                verifier_ref: "provider-route-verifier".to_owned(),
                idempotency_key: invocation_id.clone(),
            },
            launch_contract,
            campaign_id: format!("campaign:{invocation_id}"),
            purpose,
            mcp_tool_profile: mcp_tool_profile.clone(),
            prompt_ref: path_string(&prompt_path),
            prompt_sha256: sha256_bytes(prompt.as_bytes()),
            output_schema_ref: path_string(&schema_path),
            output_schema_sha256: sha256_bytes(&std::fs::read(&schema_path)?),
            requested_model: model.to_owned(),
            max_turns_or_steps: 4,
            timeout_profile_ref: route_policy.policy_id().to_owned(),
            provider_route_policy: route_policy,
            allowed_provider_tools: provider_allowed_tools(host, &mcp_tool_profile.tool_names),
            denied_provider_tools: vec!["raw_shell".to_owned()],
            expected_mcp_tool_names: mcp_tool_profile.tool_names,
            forbidden_mcp_server_names: vec!["eliot_surrealdb".to_owned()],
            read_only: !worker,
            candidate_only: true,
        };
        if open_campaign {
            ProviderCallReservationOwner::new(&root).open_campaign(
                ProviderCallCampaignRequest {
                    campaign_id: execution.campaign_id.clone(),
                    max_calls: 1,
                    closed: false,
                },
            )?;
        }
        let request = AdapterRequest {
            request_id: format!("adapter-request:{invocation_id}"),
            adapter_id: adapter_id(host).to_owned(),
            requested_capability: AdapterCapability::EmitCandidateObservation,
            context: AdapterContext {
                project_id,
                task_id,
                session_id: Some(agent_session_id),
                trace_id: format!("trace:{invocation_id}"),
                created_at: OffsetDateTime::now_utc(),
                role_lease_id: Some("provider-route-role".to_owned()),
                role_lease_epoch: Some(1),
                operation_generation: Some(1),
                runtime_contract_sha256: Some("a".repeat(64)),
            },
            input: serde_json::to_value(&execution)?,
        };
        let runner = Arc::new(ScriptedProviderProcessRunner::with_delay(
            outcomes,
            completion_delay,
        ));
        let authority = Arc::new(RecordingAuthorityBoundary::default());
        let provider_runtime = super::super::ProviderRuntime::scripted(runner.clone());
        let core = ExternalAgentAdapterCore::for_test(
            host,
            &config_path,
            &governor,
            &executable,
            runner.clone(),
            authority.clone(),
        )?;
        let mut registry = AdapterRegistry::new();
        match host {
            AgentHostId::Claude => registry.register(ClaudeCodeCliAdapter { core })?,
            AgentHostId::Antigravity => registry.register(AntigravityCliAdapter { core })?,
            AgentHostId::OpenCode => registry.register(OpenCodeCliAdapter { core })?,
            AgentHostId::Codex => unreachable!("Codex has no external provider route"),
        }
        let supervisor =
            AdapterSupervisor::with_runtime(registry, provider_runtime.operation_runtime());
        Ok(RouteFixture {
            root,
            supervisor,
            runner,
            provider_runtime,
            authority,
            request,
            attempt_id: format!("external-agent-attempt-{invocation_id}"),
        })
    }

    fn final_attempt_state(root: &Path, attempt_id: &str) -> Result<ProviderInvocationAttempt> {
        Ok(ProviderInvocationJournal::new(root).load(attempt_id)?)
    }

    #[test]
    fn provider_runtime_preview_does_not_materialize_antigravity_workspace_config() -> Result<()> {
        let fixture = route_fixture_for(
            AgentHostId::Antigravity,
            ExternalAgentPurpose::UnderstandingReader,
            Vec::new(),
            Duration::ZERO,
            false,
        )?;
        let execution: ExternalAgentExecutionRequest =
            serde_json::from_value(fixture.request.input.clone())?;
        let cwd = PathBuf::from(&execution.launch_contract.cwd_or_worktree);
        let agents = cwd.join(".agents");
        std::fs::create_dir_all(&agents)?;
        let config = agents.join("mcp_config.json");
        let sentinel = b"{\"mcpServers\":{\"eliot-governor\":{\"sentinel\":true}}}\n";
        std::fs::write(&config, sentinel)?;
        let invocation_root = fixture.root.join("preview-runtime");
        let governor = fixture.root.join("eliot-governor.exe").canonicalize()?;

        let preview = materialize_provider_mcp(
            AgentHostId::Antigravity,
            &governor,
            &fixture.root.join("config/governor.toml"),
            &cwd,
            &invocation_root,
            &execution,
            RuntimePreparationMode::Preview,
        )?;

        assert_eq!(preview.provider_config_path, config);
        assert_eq!(std::fs::read(&config)?, sentinel);
        assert!(!invocation_root.exists());
        std::fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn provider_runtime_b1_delayed_output_survives_scaled_former_boundary() -> Result<()> {
        let fixture = route_fixture(
            vec![scripted_outcome(antigravity_native_output(), false, false)],
            Duration::from_secs(6),
        )?;
        let result = fixture
            .supervisor
            .execute(&fixture.request.adapter_id, fixture.request.clone(), None)
            .await?;
        assert_eq!(
            result.status,
            AdapterResultStatus::Succeeded,
            "{:?}",
            result.error
        );
        assert_eq!(fixture.runner.call_count(), 1);
        assert_eq!(
            fixture.authority.phases(),
            ["integrity", "enqueue", "start", "canonicalize"]
        );
        let attempt = final_attempt_state(&fixture.root, &fixture.attempt_id)?;
        assert_eq!(
            attempt
                .state_transitions
                .last()
                .map(|transition| transition.to),
            Some(ProviderInvocationState::ReviewNormalized)
        );
        std::fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[tokio::test]
    async fn provider_runtime_b2_managed_and_external_share_runner_and_policy_owner() -> Result<()>
    {
        let fixture = route_fixture(
            vec![
                scripted_outcome(antigravity_native_output(), false, false),
                scripted_outcome(Vec::new(), false, false),
            ],
            Duration::ZERO,
        )?;
        let external = fixture
            .supervisor
            .execute(&fixture.request.adapter_id, fixture.request.clone(), None)
            .await?;
        assert_eq!(external.status, AdapterResultStatus::Succeeded);
        let execution: ExternalAgentExecutionRequest =
            serde_json::from_value(fixture.request.input.clone())?;
        let mut command =
            tokio::process::Command::new(fixture.root.join("agy.exe").canonicalize()?);
        command.current_dir(&execution.launch_contract.cwd_or_worktree);
        let managed_spec = super::super::managed::managed_provider_process_spec(
            &command,
            &execution.launch_contract,
        )?;
        super::super::managed::dispatch_managed_provider(&fixture.provider_runtime, managed_spec)
            .await?;
        assert_eq!(fixture.runner.call_count(), 2);
        let specs = fixture.runner.specs()?;
        assert_eq!(specs.len(), 2);
        assert_eq!(
            specs[0].route_policy, execution.provider_route_policy,
            "external adapter changed the request-owned policy"
        );
        let expected_managed = ProviderRoutePolicy::for_route(
            AgentHostId::Antigravity,
            "managed-provider",
            ProviderDeclaredBudget::new(
                1_000,
                u64::try_from(eliot_types::MAX_SECRET_BOUNDARY_BYTES)?,
            )
            .with_first_output_deadline_ms(None),
        );
        assert_eq!(specs[1].route_policy, expected_managed);
        std::fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[tokio::test]
    async fn provider_runtime_b3_first_output_timeout_reaps_and_never_replays() -> Result<()> {
        let fixture = route_fixture(
            vec![scripted_outcome(Vec::new(), true, true)],
            Duration::ZERO,
        )?;
        let first = fixture
            .supervisor
            .execute(&fixture.request.adapter_id, fixture.request.clone(), None)
            .await?;
        assert_eq!(
            first.status,
            AdapterResultStatus::Timeout,
            "{:?}",
            first.error
        );
        let _second = fixture
            .supervisor
            .execute(&fixture.request.adapter_id, fixture.request.clone(), None)
            .await?;
        assert_eq!(fixture.runner.call_count(), 1);
        let attempt = final_attempt_state(&fixture.root, &fixture.attempt_id)?;
        assert_eq!(
            attempt
                .state_transitions
                .last()
                .map(|transition| transition.to),
            Some(ProviderInvocationState::NonReconcilableUnknown)
        );
        assert!(
            attempt
                .process_reap_receipt
                .as_ref()
                .is_some_and(ProcessReapReceipt::proves_complete_reap)
        );
        std::fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[tokio::test]
    async fn provider_runtime_b4_invalid_json_is_terminal_rejected() -> Result<()> {
        let fixture = route_fixture(
            vec![scripted_outcome(b"not-json".to_vec(), false, false)],
            Duration::ZERO,
        )?;
        let result = fixture
            .supervisor
            .execute(&fixture.request.adapter_id, fixture.request.clone(), None)
            .await?;
        assert_eq!(
            result.status,
            AdapterResultStatus::Failed,
            "{:?}",
            result.error
        );
        let attempt = final_attempt_state(&fixture.root, &fixture.attempt_id)?;
        assert_eq!(
            attempt
                .state_transitions
                .last()
                .map(|transition| transition.to),
            Some(ProviderInvocationState::ProtocolParseFailed)
        );
        assert_ne!(
            attempt
                .state_transitions
                .last()
                .map(|transition| transition.to),
            Some(ProviderInvocationState::Running)
        );
        std::fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[tokio::test]
    async fn provider_runtime_b5_terminal_output_then_hang_yields_one_forced_reap_result()
    -> Result<()> {
        let fixture = route_fixture(
            vec![scripted_outcome(antigravity_native_output(), false, true)],
            Duration::ZERO,
        )?;
        let result = fixture
            .supervisor
            .execute(&fixture.request.adapter_id, fixture.request.clone(), None)
            .await?;
        assert_eq!(
            result.status,
            AdapterResultStatus::Succeeded,
            "{:?}",
            result.error
        );
        assert_eq!(fixture.runner.call_count(), 1);
        let attempt = final_attempt_state(&fixture.root, &fixture.attempt_id)?;
        assert!(
            attempt
                .process_reap_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.forced_termination && receipt.proves_complete_reap())
        );
        std::fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[tokio::test]
    async fn provider_runtime_b6_all_hosts_and_cognitive_purposes_bind_exact_hashes() -> Result<()>
    {
        let hosts = [
            AgentHostId::Claude,
            AgentHostId::Antigravity,
            AgentHostId::OpenCode,
        ];
        let purposes = [
            ExternalAgentPurpose::CognitiveWorker,
            ExternalAgentPurpose::UnderstandingReader,
            ExternalAgentPurpose::MemoryFreeControl,
            ExternalAgentPurpose::CognitiveJudge,
        ];
        for host in hosts {
            for purpose in purposes {
                let fixture = route_fixture_for(
                    host,
                    purpose,
                    vec![scripted_outcome(provider_native_output(host), false, false)],
                    Duration::ZERO,
                    true,
                )?;
                let execution: ExternalAgentExecutionRequest =
                    serde_json::from_value(fixture.request.input.clone())?;
                let expected_profile = crate::mcp_stdio::catalog::provider_mcp_tool_profile(
                    provider_mcp_access_profile(purpose),
                );
                let expected_profile_id = match purpose {
                    ExternalAgentPurpose::CognitiveWorker => "cognitive_child",
                    ExternalAgentPurpose::UnderstandingReader => "understanding_reader",
                    ExternalAgentPurpose::MemoryFreeControl => "cognitive_control",
                    _ => "external_auditor",
                };
                assert_eq!(expected_profile.profile_id, expected_profile_id);
                assert!(expected_profile.hash_is_valid());
                assert_eq!(execution.mcp_tool_profile, expected_profile);
                assert_eq!(
                    execution.allowed_provider_tools,
                    provider_allowed_tools(host, &expected_profile.tool_names)
                );

                let result = fixture
                    .supervisor
                    .execute(&fixture.request.adapter_id, fixture.request.clone(), None)
                    .await?;
                assert_eq!(
                    result.status,
                    AdapterResultStatus::Succeeded,
                    "route {host:?}/{purpose:?} failed: {:?}",
                    result.error
                );
                assert_eq!(
                    result.output.pointer("/provider_runtime_contract/host"),
                    Some(&json!(host))
                );
                assert_eq!(
                    result.output.pointer("/provider_runtime_contract/purpose"),
                    Some(&json!(purpose))
                );
                assert_eq!(
                    result
                        .output
                        .pointer("/provider_runtime_contract/provider_route_policy/policy_id"),
                    Some(&json!(execution.provider_route_policy.policy_id()))
                );
                assert_eq!(
                    result.output.pointer(
                        "/provider_runtime_contract/provider_route_policy/policy_hash_blake3"
                    ),
                    Some(&json!(execution.provider_route_policy.policy_hash_blake3()))
                );
                assert_eq!(
                    result.output.pointer(
                        "/provider_execution_evidence/provider_route_policy/policy_hash_blake3"
                    ),
                    Some(&json!(execution.provider_route_policy.policy_hash_blake3()))
                );
                assert_eq!(
                    result
                        .output
                        .pointer("/provider_runtime_contract/mcp_tool_profile/profile_hash_blake3"),
                    Some(&json!(&expected_profile.profile_hash_blake3))
                );
                let mut normalized_allowed_tools = execution.allowed_provider_tools.clone();
                normalized_allowed_tools.sort();
                normalized_allowed_tools.dedup();
                assert_eq!(
                    result
                        .output
                        .pointer("/provider_runtime_contract/allowed_provider_tools"),
                    Some(&json!(normalized_allowed_tools))
                );
                let specs = fixture.runner.specs()?;
                assert_eq!(specs.len(), 1);
                assert_eq!(specs[0].route_policy, execution.provider_route_policy);
                assert_eq!(fixture.runner.call_count(), 1);
                std::fs::remove_dir_all(fixture.root)?;
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn provider_runtime_b7_adapter_cannot_create_or_size_campaign() -> Result<()> {
        let fixture = route_fixture_for(
            AgentHostId::Antigravity,
            ExternalAgentPurpose::UnderstandingReader,
            vec![scripted_outcome(antigravity_native_output(), false, false)],
            Duration::ZERO,
            false,
        )?;
        assert!(fixture.request.input.get("max_calls").is_none());
        let result = fixture
            .supervisor
            .execute(&fixture.request.adapter_id, fixture.request.clone(), None)
            .await?;
        assert_eq!(result.status, AdapterResultStatus::Failed);
        assert!(
            result
                .error
                .as_ref()
                .is_some_and(|error| error.message.contains("provider campaign is closed"))
        );
        assert_eq!(fixture.runner.call_count(), 0);
        assert_eq!(fixture.authority.phases(), ["integrity"]);
        let attempt = final_attempt_state(&fixture.root, &fixture.attempt_id)?;
        assert_eq!(
            attempt
                .state_transitions
                .last()
                .map(|transition| transition.to),
            Some(ProviderInvocationState::PreDispatchAborted)
        );
        std::fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn provider_runtime_b8_source_gate_has_one_owner_and_no_compatibility_path() -> Result<()> {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let read = |relative: &str| -> Result<String> {
            Ok(std::fs::read_to_string(workspace.join(relative))?)
        };
        let provider_owner = read("crates/eliot-app/src/host_runtime/provider_runtime.rs")?;
        assert_eq!(
            provider_owner
                .matches("SupervisedWindowsProcessRunner::from_runtime_store")
                .count(),
            1
        );
        let external_agent = read("crates/eliot-app/src/host_runtime/external_agent.rs")?;
        let test_boundary = external_agent
            .find("mod provider_runtime_tests")
            .context("provider runtime test-module source anchor")?;
        let mut route_sources = external_agent[..test_boundary].to_owned();
        for relative in [
            "crates/eliot-app/src/host_runtime/managed.rs",
            "crates/eliot-app/src/cognitive_runner.rs",
            "crates/eliot-app/src/delegation_runtime.rs",
            "crates/eliot-app/src/commands/antigravity.rs",
        ] {
            route_sources.push('\n');
            route_sources.push_str(&read(relative)?);
        }
        for forbidden in [
            "SupervisedWindowsProcessRunner::from_runtime_store",
            "SupervisedWindowsProcessRunner::new",
            "ProviderTimeoutProfile {",
            "AntigravityProcessExecutor",
            "SharedAntigravityProcessExecutor",
            "run_external_agent_process",
            ".spawn(",
        ] {
            assert!(
                !route_sources.contains(forbidden),
                "provider route still contains forbidden source fragment {forbidden}"
            );
        }
        let timeout_owner = read("crates/eliot-types/src/provider_invocation.rs")?;
        assert_eq!(
            timeout_owner
                .matches("let timeout_profile = ProviderTimeoutProfile {")
                .count(),
            1
        );
        let external_types = read("crates/eliot-types/src/external_agent.rs")?;
        assert_eq!(
            external_types
                .lines()
                .filter(|line| line.contains("CognitiveProviderRuntimeContract {"))
                .map(str::trim)
                .collect::<Vec<_>>(),
            ["pub struct CognitiveProviderRuntimeContract {"]
        );
        let cargo = read("crates/eliot-app/Cargo.toml")?;
        assert!(!cargo.contains("[[test]]"));
        assert!(!cargo.contains("cognitive_field_runner"));
        let managed = read("crates/eliot-app/src/host_runtime/managed.rs")?;
        let attempt_write = managed
            .find("atomic_write_json(&attempt_path, &attempt)")
            .context("managed attempt write source anchor")?;
        let dispatch = managed
            .find("dispatch_managed_provider(provider_runtime, provider_spec)")
            .context("managed provider dispatch source anchor")?;
        assert!(attempt_write < dispatch);
        Ok(())
    }
}
