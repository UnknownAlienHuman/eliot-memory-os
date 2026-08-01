fn dispatch_runtime_status(state: &McpState) -> Value {
    serde_json::json!({
        "component": "runtime_status",
        "mode": RuntimeMode::Daemon,
        "active_profile": "daemon",
        "canonical_state_owner": "daemon",
        "runtime_id": state.runtime_id,
        "auth_generation": state.auth_generation,
        "identity_semantics": {
            "runtime_id": "daemon runtime generation; never an AgentSessionId",
            "auth_generation": "IPC auth generation; never a role or role status"
        },
        "ipc_enabled": true,
        "ipc_transport": "windows-named-pipe",
        "ipc_name": state.pipe_name,
        "services": runtime_service_statuses(),
        "report_ref": state.root.join("reports").join("runtime").join("latest.json")
    })
}

fn dispatch_runtime_health(state: &McpState) -> Result<Value> {
    let health = HealthService::report(RuntimeMode::Daemon, runtime_service_statuses());
    write_json_report(
        &state
            .root
            .join("reports")
            .join("runtime-health")
            .join("latest.json"),
        &health,
    )?;
    serde_json::to_value(health).map_err(Into::into)
}

fn dispatch_module_list() -> Result<Value> {
    let registry = ModuleRegistryService::new(builtin_manifests())?;
    serde_json::to_value(registry.report()).map_err(Into::into)
}

fn dispatch_module_health() -> Result<Value> {
    dispatch_module_list()
}

fn dispatch_logs_query(state: &McpState, arguments: Value) -> Result<Value> {
    let input: LogsQueryInput = serde_json::from_value(arguments)?;
    let limit = input.limit.unwrap_or(20).clamp(1, 100);
    let mut events = LogService::new(state.root.join("logs")).tail(limit)?;
    if let Some(trace_id) = input.trace_id.as_deref() {
        events.retain(|event| event.trace_id.as_deref() == Some(trace_id));
    }
    Ok(json!({
        "component": "logs_query",
        "bounded": true,
        "limit": limit,
        "returned": events.len(),
        "events": events
    }))
}

fn dispatch_service_status(state: &McpState) -> Result<Value> {
    let manager = mcp_service_manager(state)?;
    let report = manager.status();
    let report_ref = state
        .root
        .join("reports")
        .join("service")
        .join("latest.json");
    write_json_report(&report_ref, &report)?;
    Ok(json!({
        "component": "service_status",
        "service_name": report.config.service_name,
        "installed": report.installed,
        "running": report.running,
        "install_status": report.install_receipt.status,
        "config_ref": report.install_receipt.config_ref,
        "warnings": report.install_receipt.warnings,
        "report_ref": report_ref
    }))
}

fn dispatch_ipc_status(state: &McpState) -> Result<Value> {
    let report_ref = state.root.join("reports").join("ipc").join("latest.json");
    let report = json!({
        "component": "ipc_status",
        "transport": "windows-named-pipe",
        "listening": true,
        "bind_local_only": true,
        "pipe_name": state.pipe_name,
        "max_frame_bytes": named_pipe_ipc::MAX_FRAME_BYTES,
        "max_connections": named_pipe_ipc::MAX_CONNECTIONS,
        "handshake_required": true,
        "warnings": [],
        "report_ref": report_ref
    });
    write_json_report(&report_ref, &report)?;
    Ok(report)
}

fn dispatch_readiness_report(state: &McpState) -> Result<Value> {
    let report_ref = state
        .root
        .join("reports")
        .join("readiness")
        .join("latest.json");
    let report: Value = if report_ref.is_file() {
        serde_json::from_reader(std::fs::File::open(&report_ref)?)?
    } else {
        let data_root =
            DataRootService::new(&state.root).validate(DataRootMode::DevProjectLocal)?;
        let probe = ProductionReadinessService::probe(
            "EliotGovernor",
            &ReadinessFixture {
                data_root_validated: ProductionReadinessService::data_root_validation_passed(
                    data_root.status,
                ),
                credential_refs_resolved: true,
                db_reachable: true,
                writer_self_check: true,
                read_self_check: true,
                ipc_listening: true,
                fast_deterministic_eval_gate_passed: true,
                blocking_incident: IncidentService::new(&state.root).lockdown_active()?,
            },
        );
        write_json_report(&report_ref, &probe)?;
        serde_json::to_value(probe)?
    };
    Ok(json!({
        "component": "readiness_report",
        "status": report.get("status").cloned().unwrap_or(Value::Null),
        "checks_count": report
            .get("checks")
            .and_then(Value::as_array)
            .map_or(0, std::vec::Vec::len),
        "report_ref": report_ref
    }))
}

fn dispatch_startup_recovery_report(state: &McpState) -> Result<Value> {
    let report_ref = state
        .root
        .join("reports")
        .join("startup-recovery")
        .join("latest.json");
    if !report_ref.is_file() {
        return Ok(json!({
            "component": "startup_recovery_report",
            "status": "unavailable",
            "report_available": false,
            "reason": "startup recovery scan is admin CLI only in H1"
        }));
    }
    let report: Value = serde_json::from_reader(std::fs::File::open(&report_ref)?)?;
    Ok(json!({
        "component": "startup_recovery_report",
        "status": report.get("status").cloned().unwrap_or(Value::Null),
        "unclean_shutdown_detected": report
            .get("unclean_shutdown_detected")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "report_available": true,
        "report_ref": report_ref
    }))
}

fn dispatch_credentials_report(state: &McpState) -> Result<Value> {
    let mut provider = CredentialProviderService::new();
    let _ = provider.put_test_secret(
        "credential:ipc-handshake-token",
        CredentialPurpose::IpcHandshakeToken,
        "mcp-status-token",
    );
    let _ = provider.put_test_secret(
        "credential:surreal-runtime",
        CredentialPurpose::SurrealDbRuntime,
        "mcp-db-secret-fixture",
    );
    let report = provider.report("", &["eliot-app".to_owned(), "mcp".to_owned()]);
    let report_ref = state
        .root
        .join("reports")
        .join("credentials")
        .join("latest.json");
    write_json_report(&report_ref, &report)?;
    Ok(json!({
        "component": "credentials_report",
        "refs_count": report.refs.len(),
        "resolved_count": report.resolved_count,
        "secret_values_redacted": report.secret_values_redacted,
        "toml_contains_secret_values": report.toml_contains_secret_values,
        "command_line_contains_secret_values": report.command_line_contains_secret_values,
        "warnings": report.warnings,
        "report_ref": report_ref
    }))
}

fn mcp_service_manager(state: &McpState) -> Result<WindowsServiceManager> {
    let executable_path = std::env::current_exe().context("resolve current executable")?;
    Ok(WindowsServiceManager::new(
        WindowsServiceManager::default_config(&state.root, &executable_path),
    ))
}

async fn dispatch_adapter_list() -> Result<Value> {
    let registry = AdapterRegistry::builtin()?;
    serde_json::to_value(registry.report().await).map_err(Into::into)
}

async fn dispatch_adapter_health() -> Result<Value> {
    let supervisor = AdapterSupervisor::builtin()?;
    let health = supervisor.health_all().await;
    Ok(json!({
        "component": "adapter_health",
        "health": health,
        "bounded": true
    }))
}

fn dispatch_adapter_inspect(arguments: Value) -> Result<Value> {
    let input: AdapterInspectInput = serde_json::from_value(arguments)?;
    let registry = AdapterRegistry::builtin()?;
    serde_json::to_value(registry.inspect(&input.adapter)?).map_err(Into::into)
}

fn dispatch_doctor_report(state: &McpState) -> Result<Value> {
    let report = DoctorService::new(&state.root, std::env::current_dir()?).report()?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("doctor")
            .join("latest.json"),
        &report,
    )?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_data_root_status(state: &McpState) -> Result<Value> {
    let validation = DataRootService::new(&state.root).validate(DataRootMode::DevProjectLocal)?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("data-root")
            .join("latest.json"),
        &validation,
    )?;
    serde_json::to_value(validation).map_err(Into::into)
}

fn dispatch_blob_report(state: &McpState) -> Result<Value> {
    let report = BlobGcService::new(state.root.join("blobs")).report(true)?;
    write_json_report(
        &state.root.join("reports").join("blob").join("latest.json"),
        &report,
    )?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_incident_list(state: &McpState) -> Result<Value> {
    let report = IncidentService::new(&state.root).report()?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("incidents")
            .join("latest.json"),
        &report,
    )?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_latest_report_or_value<T: serde::Serialize>(
    state: &McpState,
    report_name: &str,
    fallback: T,
) -> Result<Value> {
    let path = state
        .root
        .join("reports")
        .join(report_name)
        .join("latest.json");
    if path.is_file() {
        return Ok(serde_json::from_reader(std::fs::File::open(path)?)?);
    }
    write_json_report(&path, &fallback)?;
    serde_json::to_value(fallback).map_err(Into::into)
}

async fn dispatch_adapter_execute_test(state: &McpState, arguments: Value) -> Result<Value> {
    let input: AdapterInspectInput = serde_json::from_value(arguments)?;
    let blob_store = BlobStore::open(&state.blob_store)?;
    let supervisor = AdapterSupervisor::builtin()?;
    let request = test_request(&input.adapter, AdapterCapability::ExecuteTest);
    let mut result = supervisor
        .execute(&input.adapter, request, Some(&blob_store))
        .await?;
    let writer = state.writer.clone();
    let admission = WriteAdmissionService;
    let mut work_state = load_work_state(&state.root)?;
    let session_id = AgentSessionId::new_v7();
    let mut observations = Vec::new();
    let mut blackboard_items = Vec::new();
    let mut mailbox_messages = Vec::new();
    for observation in &mut result.observations {
        AdapterMemoryWriter::write_observation(&writer, &admission, observation).await?;
        let item = AdapterObservationBridge::to_blackboard_candidate(
            &mut work_state,
            session_id,
            observation,
        );
        let message = AdapterObservationBridge::to_mailbox_notification(
            &mut work_state,
            session_id,
            observation,
        );
        observations.push(observation.clone());
        blackboard_items.push(item);
        mailbox_messages.push(message);
    }
    let project_label = result
        .observations
        .first()
        .map_or_else(ProjectId::new_v7, |observation| observation.project_id)
        .to_string();
    let task_label = result
        .observations
        .first()
        .map_or_else(TaskId::new_v7, |observation| observation.task_id)
        .to_string();
    let report = WorkQueueService.status_report(&work_state, &project_label, &task_label);
    save_work_state_and_report(&state.root, &work_state, &report)?;
    let observation_report = AdapterObservationReport {
        component: "adapter_observations".to_owned(),
        observations,
        blackboard_items,
        mailbox_messages,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_json_report(
        &state
            .root
            .join("reports")
            .join("adapter-observations")
            .join("latest.json"),
        &observation_report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("adapter-observations")
            .join("latest.md"),
        "# Adapter Observations\n",
    )?;
    Ok(json!({
        "component": "adapter_execute_test",
        "adapter": input.adapter,
        "result": result,
        "bounded": true
    }))
}

fn runtime_service_statuses() -> Vec<ServiceRuntimeStatus> {
    [
        "lifecycle",
        "memory",
        "coordination",
        "module_registry",
        "adapter_supervisor",
        "mailbox_blackboard",
        "logs",
        "reports",
    ]
    .into_iter()
    .map(|service_name| ServiceRuntimeStatus {
        service_name: service_name.to_owned(),
        health: ServiceHealthState::Healthy,
        started: true,
        restart_budget_remaining: 3,
        message: "dev-single-process service ready".to_owned(),
    })
    .collect()
}

async fn dispatch_task_contract_create(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: TaskContractCreateToolInput = serde_json::from_value(arguments)?;
    if input.acceptance_items.len() != 2 {
        anyhow::bail!("First Working Loop TaskContract requires exactly two acceptance items");
    }
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse write id")?;
    if state.store.task_contract_by_id(task_id).await?.is_some()
        && state.store.write_receipt_by_id(&write_id).await?.is_none()
    {
        anyhow::bail!("TaskContract already exists");
    }
    let mut ids = std::collections::BTreeSet::new();
    let acceptance_items = input
        .acceptance_items
        .into_iter()
        .map(|item| {
            if item.item_id.trim().is_empty()
                || item.description.trim().is_empty()
                || !ids.insert(item.item_id.clone())
            {
                anyhow::bail!("acceptance items require unique non-empty ids and descriptions");
            }
            Ok(TaskAcceptanceItem {
                item_id: item.item_id,
                description: item.description,
                required_evidence: item.required_evidence,
                satisfied: false,
                observation_id: None,
                verification_id: None,
                verification_scope_hash: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let observation_requirements = acceptance_items
        .iter()
        .filter(|item| item.required_evidence == TaskAcceptanceEvidenceKind::Observation)
        .count();
    let verification_requirements = acceptance_items
        .iter()
        .filter(|item| item.required_evidence == TaskAcceptanceEvidenceKind::Verification)
        .count();
    if observation_requirements != 1 || verification_requirements != 1 {
        anyhow::bail!(
            "First Working Loop TaskContract requires one observation and one verification item"
        );
    }
    let contract = TaskContractInput {
        task_id,
        title: input.title,
        status: TaskContractStatus::Open,
        acceptance_items,
        expected_revision: None,
        action_lease_id: None,
        understanding_proof_hash: None,
        action_provenance: None,
        observation_ids: Vec::new(),
        verification_ids: Vec::new(),
        verification_scopes: Vec::new(),
        completion_proof: None,
        completion_write_id: None,
    };
    let (receipt, contract) = submit_task_transition(
        state,
        context,
        project_id,
        write_id,
        contract,
        "controller-task-contract",
        TaintClass::LocalTool,
        TaskTransitionEvidence::default(),
    )
    .await?;
    Ok(json!({ "status": "created", "task_contract": contract, "write_receipt": receipt }))
}

async fn dispatch_task_state(state: &McpState, arguments: Value) -> Result<Value> {
    let input: TaskStateToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let contract = require_task(state, project_id, task_id).await?;
    Ok(json!({
        "status": "current",
        "current_vs_recalled": "current_canonical_task_state",
        "revision_fence": contract.memory_revision,
        "task_contract": contract
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegisteredTaskVerifier {
    ReceiptResolution,
    DogfoodBlobIntegrity,
    CargoWorkspaceCheck,
}

impl RegisteredTaskVerifier {
    const ALL: [Self; 3] = [
        Self::ReceiptResolution,
        Self::DogfoodBlobIntegrity,
        Self::CargoWorkspaceCheck,
    ];

    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::ReceiptResolution => RECEIPT_VERIFIER_ID,
            Self::DogfoodBlobIntegrity => DOGFOOD_BLOB_VERIFIER_ID,
            Self::CargoWorkspaceCheck => CARGO_WORKSPACE_CHECK_VERIFIER_ID,
        }
    }

    const fn source_kind(self) -> &'static str {
        match self {
            Self::ReceiptResolution => "canonical_task",
            Self::DogfoodBlobIntegrity | Self::CargoWorkspaceCheck => "git_worktree",
        }
    }

    const fn command_display(self) -> &'static str {
        match self {
            Self::ReceiptResolution => "resolve canonical observation receipt",
            Self::DogfoodBlobIntegrity => {
                "cargo test --offline -p eliot-store blob_store::tests::rejects_corrupt_existing_content_addressed_blob -- --exact --test-threads=1"
            }
            Self::CargoWorkspaceCheck => {
                "cargo check --workspace --all-targets --all-features --offline"
            }
        }
    }

    fn profile_ref(self) -> String {
        format!("eliot/verifier-profile/{}@{VERIFIER_VERSION}", self.id())
    }

    pub(crate) fn config_hash(self) -> String {
        let material = match self {
            Self::ReceiptResolution => json!({
                "id": self.id(),
                "version": VERIFIER_VERSION,
                "operation": "resolve_observation_write_receipt_in_exact_task_scope"
            }),
            Self::DogfoodBlobIntegrity => json!({
                "id": self.id(),
                "version": VERIFIER_VERSION,
                "program": "cargo",
                "args": [
                    "test", "--offline", "-p", "eliot-store", DOGFOOD_BLOB_TEST,
                    "--", "--exact", "--test-threads=1"
                ],
                "artifact_paths": [DOGFOOD_BLOB_ARTIFACT],
                "timeout_seconds": 120,
                "provider_kill_switch": true
            }),
            Self::CargoWorkspaceCheck => json!({
                "id": self.id(),
                "version": VERIFIER_VERSION,
                "program": "cargo",
                "args": [
                    "check", "--workspace", "--all-targets", "--all-features", "--offline"
                ],
                "artifact_scope": "action_leased_exact_changed_paths",
                "timeout_seconds": 300,
                "provider_kill_switch": true
            }),
        };
        let bytes =
            serde_json::to_vec(&material).unwrap_or_else(|_| material.to_string().into_bytes());
        blake3::hash(&bytes).to_hex().to_string()
    }

    pub(crate) fn reference(self) -> String {
        format!(
            "eliot/verifier/{}@{}#blake3:{}",
            self.id(),
            VERIFIER_VERSION,
            self.config_hash()
        )
    }

    pub(crate) fn from_reference(reference: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.reference() == reference)
    }

    fn descriptor(self) -> Value {
        json!({
            "verifier_id": self.id(),
            "verifier_version": VERIFIER_VERSION,
            "config_hash": self.config_hash(),
            "verifier_ref": self.reference(),
            "source_kind": self.source_kind(),
            "profile_ref": self.profile_ref(),
            "command": self.command_display()
        })
    }
}

struct CanonicalPacketRefs {
    packet_id: String,
    packet_revision_fence: MemoryRevision,
    task_contract_ref: String,
    negative_memory_check_ref: String,
}

async fn canonical_packet_refs(
    state: &McpState,
    task: &TaskContract,
) -> Result<CanonicalPacketRefs> {
    let current = state
        .store
        .current_state(&CurrentStateRequest {
            project_id: task.project_id,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?;
    let task_contract_ref = format!(
        "eliot/task/{}@{}",
        task.task_id,
        task.memory_revision.value()
    );
    let material = json!({
        "project_id": task.project_id,
        "task_id": task.task_id,
        "task_revision": task.memory_revision,
        "task_write_id": task.write_id,
        "task_status": task.status,
        "acceptance_items": task.acceptance_items,
        "task_contract_ref": task_contract_ref,
        "project_memory_revision": current.memory_revision,
        "project_sequence": current.project_sequence,
        "weak_or_candidate": current.weak_or_candidate,
        "contested_now": current.contested_now,
        "do_not_use": current.do_not_use,
        "recent_failures": current.recent_failures
    });
    let packet_id = format!(
        "eliot/packet/{}",
        blake3::hash(&serde_json::to_vec(&material)?).to_hex()
    );
    let negative_memory_check_ref = format!("eliot/negative-memory/{packet_id}");
    Ok(CanonicalPacketRefs {
        packet_id,
        packet_revision_fence: current.memory_revision,
        task_contract_ref,
        negative_memory_check_ref,
    })
}

struct GitArtifactSnapshot {
    root: PathBuf,
    branch: String,
    commit: String,
    dirty_state_hash: String,
    clean: bool,
    artifact_refs: Vec<VerifierArtifactRef>,
}

async fn run_git(worktree: &Path, args: &[&str]) -> Result<std::process::Output> {
    let output = tokio::process::Command::new("git")
        .args(args)
        .current_dir(worktree)
        .env_remove("SURREAL_USER")
        .env_remove("SURREAL_PASS")
        .env_remove("ELIOT_TEST_SURREAL_ENDPOINT")
        .output()
        .await
        .with_context(|| format!("run git {} in {}", args.join(" "), worktree.display()))?;
    Ok(output)
}

fn checked_command_text(output: std::process::Output, operation: &str) -> Result<String> {
    if !output.status.success() {
        anyhow::bail!("{operation} failed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

async fn resolve_git_artifact_snapshot(
    worktree_ref: &str,
    artifact_paths: &[String],
) -> Result<GitArtifactSnapshot> {
    if worktree_ref.trim().is_empty() || artifact_paths.is_empty() {
        anyhow::bail!("git verifier requires a worktree and artifact paths");
    }
    let root = tokio::fs::canonicalize(worktree_ref)
        .await
        .with_context(|| "canonicalize verifier worktree")?;
    let lower = root.to_string_lossy().to_ascii_lowercase();
    if lower.contains("onedrive")
        || lower.contains("dropbox")
        || lower.contains("google drive")
        || root.components().any(|component| {
            component
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(".git")
        })
    {
        anyhow::bail!("verifier worktree must be outside sync roots and .git");
    }
    let top_level = checked_command_text(
        run_git(&root, &["rev-parse", "--show-toplevel"]).await?,
        "resolve git worktree root",
    )?;
    let top_level = tokio::fs::canonicalize(top_level).await?;
    if top_level != root {
        anyhow::bail!("worktree_ref must name the exact Git worktree root");
    }
    let branch = checked_command_text(
        run_git(&root, &["symbolic-ref", "--quiet", "--short", "HEAD"]).await?,
        "resolve verifier branch",
    )?;
    let commit = checked_command_text(
        run_git(&root, &["rev-parse", "HEAD"]).await?,
        "resolve verifier commit",
    )?;
    let status = run_git(
        &root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    .await?;
    if !status.status.success() {
        anyhow::bail!("resolve verifier dirty state failed");
    }
    let dirty_state_hash = blake3::hash(&status.stdout).to_hex().to_string();
    let clean = status.stdout.is_empty();

    let mut canonical_paths = artifact_paths.to_vec();
    canonical_paths.sort();
    canonical_paths.dedup();
    if canonical_paths.len() != artifact_paths.len() {
        anyhow::bail!("artifact paths must be unique");
    }
    let mut artifact_refs = Vec::with_capacity(canonical_paths.len());
    for relative in canonical_paths {
        let relative_path = Path::new(&relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            anyhow::bail!("artifact path must be a normalized relative path");
        }
        let resolved = tokio::fs::canonicalize(root.join(relative_path))
            .await
            .with_context(|| format!("resolve verifier artifact {relative}"))?;
        if !resolved.starts_with(&root) || !resolved.is_file() {
            anyhow::bail!("verifier artifact escapes the worktree or is not a file");
        }
        let bytes = tokio::fs::read(&resolved).await?;
        artifact_refs.push(VerifierArtifactRef {
            resource_ref: relative.replace('\\', "/"),
            content_hash: blake3::hash(&bytes).to_hex().to_string(),
        });
    }
    Ok(GitArtifactSnapshot {
        root,
        branch,
        commit,
        dirty_state_hash,
        clean,
        artifact_refs,
    })
}

async fn resolve_packet_git_scope(
    worktree: &Path,
    project_id: ProjectId,
) -> Result<eliot_types::memory::GovernedGitScope> {
    let root = tokio::fs::canonicalize(worktree)
        .await
        .context("canonicalize packet Git worktree")?;
    let top_level = checked_command_text(
        run_git(&root, &["rev-parse", "--show-toplevel"]).await?,
        "resolve packet Git worktree root",
    )?;
    if tokio::fs::canonicalize(top_level).await? != root {
        anyhow::bail!("packet runtime root must name the exact Git worktree root");
    }
    let branch = checked_command_text(
        run_git(&root, &["symbolic-ref", "--quiet", "--short", "HEAD"]).await?,
        "resolve packet Git branch",
    )?;
    let commit = checked_command_text(
        run_git(&root, &["rev-parse", "HEAD"]).await?,
        "resolve packet Git commit",
    )?;
    let status = run_git(
        &root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    .await?;
    if !status.status.success() {
        anyhow::bail!("resolve packet Git dirty state failed");
    }
    let ancestors = checked_command_text(
        run_git(&root, &["rev-list", "HEAD"]).await?,
        "resolve packet Git ancestry",
    )?;
    let ancestor_commits = ancestors
        .lines()
        .filter(|candidate| *candidate != commit)
        .map(str::to_owned)
        .collect();
    let tracked = run_git(&root, &["ls-files", "-z"]).await?;
    if !tracked.status.success() {
        anyhow::bail!("resolve packet tracked files failed");
    }
    let mut artifact_refs = Vec::new();
    for relative in String::from_utf8(tracked.stdout)?.split('\0') {
        if relative.is_empty() {
            continue;
        }
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            anyhow::bail!("tracked packet artifact path is not normalized");
        }
        let candidate = root.join(relative_path);
        let Ok(resolved) = tokio::fs::canonicalize(&candidate).await else {
            continue;
        };
        if !resolved.starts_with(&root) || !resolved.is_file() {
            continue;
        }
        let bytes = tokio::fs::read(resolved).await?;
        artifact_refs.push(VerifierArtifactRef {
            resource_ref: relative.replace('\\', "/"),
            content_hash: blake3::hash(&bytes).to_hex().to_string(),
        });
    }
    artifact_refs.sort_by(|left, right| left.resource_ref.cmp(&right.resource_ref));
    Ok(eliot_types::memory::GovernedGitScope {
        project_id,
        branch,
        commit,
        clean: status.stdout.is_empty(),
        ancestor_commits,
        artifact_refs,
    })
}

async fn resolve_action_source_scope(
    verifier: RegisteredTaskVerifier,
    input: &TaskActionToolInput,
) -> Result<ActionSourceScope> {
    match verifier {
        RegisteredTaskVerifier::ReceiptResolution => {
            if input.worktree_ref.is_some() || !input.artifact_paths.is_empty() {
                anyhow::bail!("receipt verifier does not accept caller artifact scope");
            }
            Ok(ActionSourceScope {
                kind: verifier.source_kind().to_owned(),
                worktree_ref: None,
                branch: None,
                baseline_commit: None,
                baseline_dirty_state_hash: None,
                artifact_paths: Vec::new(),
            })
        }
        RegisteredTaskVerifier::DogfoodBlobIntegrity
        | RegisteredTaskVerifier::CargoWorkspaceCheck => {
            if verifier == RegisteredTaskVerifier::DogfoodBlobIntegrity
                && input.artifact_paths != [DOGFOOD_BLOB_ARTIFACT]
            {
                anyhow::bail!("dogfood verifier artifact scope does not match its registry entry");
            }
            let worktree_ref = input
                .worktree_ref
                .as_deref()
                .context("git verifier requires worktree_ref")?;
            let snapshot =
                resolve_git_artifact_snapshot(worktree_ref, &input.artifact_paths).await?;
            if !snapshot.clean {
                anyhow::bail!("action source worktree must be clean at lease issuance");
            }
            Ok(ActionSourceScope {
                kind: verifier.source_kind().to_owned(),
                worktree_ref: Some(snapshot.root.display().to_string()),
                branch: Some(snapshot.branch),
                baseline_commit: Some(snapshot.commit),
                baseline_dirty_state_hash: Some(snapshot.dirty_state_hash),
                artifact_paths: input.artifact_paths.clone(),
            })
        }
    }
}

async fn resolve_action_provenance(
    state: &McpState,
    project_id: ProjectId,
    task: &TaskContract,
    action_write_id: WriteId,
    input: &TaskActionToolInput,
) -> Result<(ActionProvenanceSet, RegisteredTaskVerifier)> {
    let packet = canonical_packet_refs(state, task).await?;
    if input.packet_id != packet.packet_id
        || input.packet_revision_fence != packet.packet_revision_fence.value()
        || input.task_contract_ref != packet.task_contract_ref
        || input.current_truth_refs != [packet.task_contract_ref.clone()]
        || input.negative_memory_check_ref != packet.negative_memory_check_ref
    {
        anyhow::bail!("packet or current-truth reference is missing, stale, or fabricated");
    }
    let verifier = RegisteredTaskVerifier::from_reference(&input.planned_verifier_ref)
        .context("planned verifier reference is not registered or has a stale config hash")?;
    let source_scope = resolve_action_source_scope(verifier, input).await?;

    let mut exact_evidence_refs = Vec::new();
    let mut resolves_current_task_write = false;
    for handle in &input.provenance_handles {
        let write_id = WriteId::from_str(handle)
            .context("provenance handle is not a WriteReceipt reference")?;
        let receipt = state
            .store
            .write_receipt_by_id(&write_id)
            .await?
            .context("provenance WriteReceipt does not resolve")?;
        if receipt.project_id != project_id
            || receipt.task_id != Some(task.task_id)
            || !matches!(
                receipt.status,
                WriteStatus::Committed | WriteStatus::IdempotentReplay
            )
            || receipt
                .memory_revision
                .is_none_or(|revision| revision > task.memory_revision)
        {
            anyhow::bail!("provenance WriteReceipt has wrong task, project, state, or revision");
        }
        resolves_current_task_write |= receipt.write_id == task.write_id;
        exact_evidence_refs.push(receipt.receipt_id.to_string());
    }
    exact_evidence_refs.sort();
    exact_evidence_refs.dedup();
    if exact_evidence_refs.is_empty() || !resolves_current_task_write {
        anyhow::bail!("provenance must resolve the current TaskContract write");
    }

    let mut provenance = ActionProvenanceSet {
        provenance_set_id: format!("eliot/provenance-set/{action_write_id}"),
        task_id: task.task_id,
        packet_id: packet.packet_id,
        packet_revision_fence: packet.packet_revision_fence,
        task_contract_ref: packet.task_contract_ref.clone(),
        current_truth_refs: vec![packet.task_contract_ref],
        exact_evidence_refs,
        negative_memory_check_ref: packet.negative_memory_check_ref,
        planned_verifier_ref: verifier.reference(),
        source_scope,
        resolved_at: time::OffsetDateTime::now_utc(),
        resolver_version: ACTION_PROVENANCE_RESOLVER_VERSION.to_owned(),
        hash: String::new(),
    };
    provenance.hash = canonical_struct_hash(&provenance)?;
    Ok((provenance, verifier))
}
