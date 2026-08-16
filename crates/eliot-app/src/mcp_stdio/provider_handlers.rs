async fn dispatch_understanding_proof(state: &McpState, arguments: Value) -> Result<Value> {
    let proof: UnderstandingProof = serde_json::from_value(arguments)?;
    let codecortex_reports = latest_codecortex_report(&state.root)?
        .into_iter()
        .collect::<Vec<_>>();
    let receipt = UnderstandingProofValidator::new(ReadService::new(state.store.clone()))
        .validate_with_codecortex(&proof, &codecortex_reports)
        .await?;
    serde_json::to_value(receipt).map_err(Into::into)
}

async fn dispatch_codecortex_scan(state: &McpState, arguments: Value) -> Result<Value> {
    let input: CodeCortexScanToolInput = serde_json::from_value(arguments)?;
    let request = CodeCortexRequest {
        project: input.project,
        task: input.task,
        goal: input.goal,
        exact_patterns: input.exact_patterns.unwrap_or_default(),
        max_files: input.max_files.unwrap_or(160),
        max_matches_per_pattern: input.max_matches_per_pattern.unwrap_or(24),
        include_diagnostics: input.include_diagnostics.unwrap_or(true),
    };
    let project_root = resolve_codecortex_repo_root(
        &state.root,
        None,
    )?;
    let mut report = CodeCortexService::new(project_root).scan(&request)?;
    write_codecortex_report_to_memory(state, &mut report).await?;
    write_json_report(&codecortex_latest_path(&state.root), &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

const GOVERNOR_REPO_ROOT_ENV: &str = "ELIOT_GOVERNOR_REPO_ROOT";

/// Resolve the physical source checkout for `CodeCortex`. Runtime data, the
/// process working directory, and installed plugin/cache paths are not source
/// authority. Existing governed scopes win; the environment contract is only
/// a fallback and is validated against the live Git checkout.
fn resolve_codecortex_repo_root(
    _runtime_root: &Path,
    task_contract: Option<&TaskContract>,
) -> Result<PathBuf> {
    let explicit_scope = task_contract.and_then(|task_contract| {
        if !matches!(
            task_contract.status,
            TaskContractStatus::Active | TaskContractStatus::DoneVerified
        ) {
            return None;
        }
        let provenance = task_contract.action_provenance.as_ref()?;
        if provenance.task_id != task_contract.task_id {
            return None;
        }
        Some(provenance)
    })
    .and_then(|provenance| {
            if provenance.source_scope.kind != "git_worktree" {
                return None;
            }
            let mut material = provenance.clone();
            let expected_hash = material.hash.clone();
            material.hash.clear();
            if canonical_struct_hash(&material).ok().as_deref() != Some(expected_hash.as_str()) {
                return None;
            }
            provenance.source_scope.worktree_ref.as_deref()
        })
        .map(PathBuf::from);
    let configured_root = std::env::var_os(GOVERNOR_REPO_ROOT_ENV).map(PathBuf::from);
    resolve_codecortex_repo_root_from_sources(
        explicit_scope.as_deref(),
        configured_root.as_deref(),
    )
}

fn resolve_codecortex_repo_root_from_sources(
    explicit_scope: Option<&Path>,
    configured_root: Option<&Path>,
) -> Result<PathBuf> {
    let candidate = explicit_scope
        .or(configured_root)
        .context("CodeCortex requires a governed scope or ELIOT_GOVERNOR_REPO_ROOT")?;
    let canonical = std::fs::canonicalize(candidate).with_context(|| {
        format!(
            "CodeCortex trusted repo root does not resolve: {}",
            candidate.display()
        )
    })?;
    anyhow::ensure!(
        canonical.is_dir() && canonical.join("Cargo.toml").is_file(),
        "CodeCortex trusted repo root must be a Cargo checkout: {}",
        canonical.display()
    );
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&canonical)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("validate CodeCortex trusted repo root with git")?;
    anyhow::ensure!(
        output.status.success(),
        "CodeCortex trusted repo root is not a Git checkout: {}",
        canonical.display()
    );
    let git_root = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let canonical_git_root = std::fs::canonicalize(&git_root).with_context(|| {
        format!("canonicalize Git root returned for {}", canonical.display())
    })?;
    anyhow::ensure!(
        canonical_git_root == canonical,
        "CodeCortex trusted repo root differs from Git root: {}",
        canonical.display()
    );
    Ok(canonical)
}

fn dispatch_codecortex_latest(state: &McpState) -> Result<Value> {
    let report = latest_codecortex_report(&state.root)?
        .context("no latest CodeCortex report found; call eliot_codecortex_scan first")?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_external_review_providers(state: &McpState) -> Result<Value> {
    let report = ExternalProviderRegistryService.report();
    write_external_review_mcp_report(state, "external-providers", "External Providers", &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

async fn dispatch_external_review_request(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExternalReviewRequestToolInput = serde_json::from_value(arguments)?;
    let provider = ExternalProviderRegistryService.inspect(&input.provider)?;
    let mut request = external_review_request(
        &input.project,
        &input.task,
        &input.provider,
        parse_external_review_role(input.role.as_deref().unwrap_or("auditor"))?,
        &input.question,
    );
    request.project_id = project_id_from_label(&input.project);
    request.task_id = task_id_from_label(&input.task);
    request.output_schema = external_output_schema_for(&request, &provider);
    request.budget = ExternalReviewBudget {
        max_packet_bytes: provider.limits.max_packet_bytes,
        max_output_bytes: provider.limits.max_raw_output_bytes,
        max_findings: provider.limits.max_findings,
    };
    let (mut work_state, work_lease) = ensure_external_review_work_lease(state, &mut request)?;
    let packet = ExternalReviewPacketBuilder.build(
        &request,
        "context_packet_l3:mcp-external-review",
        json!({
            "project": input.project,
            "task": input.task,
            "question": input.question,
            "allowed_paths": &request.allowed_paths,
            "evidence_refs": &request.evidence_refs,
            "credential": "redacted"
        }),
    )?;
    let gate = ExternalReviewGate.decide(
        &request,
        &provider,
        ExternalReviewGateContext {
            work_lease: work_lease.as_ref(),
            worktree_lease: None,
            provider_integration_eval_gate_passed: true,
            incident_lockdown: IncidentService::new(&state.root).lockdown_active()?,
        },
    );
    let job = ExternalReviewJobService.create_job(&request);
    let work_report = WorkQueueService.status_report(&work_state, &request.project, &request.task);
    save_work_state_and_report(&state.root, &work_state, &work_report)?;
    write_work_entities(
        state,
        &mut work_state,
        work_lease.as_ref().map(|lease| lease.agent_session_id),
        work_lease.as_ref().map(|lease| lease.work_item_id),
        work_lease.as_ref().map(|lease| lease.work_lease_id),
        &[],
    )
    .await?;
    write_external_review_mcp_report(
        state,
        "external-review-requests",
        "External Review Request",
        &request,
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-packets",
        "External Review Packet",
        &packet,
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-gates",
        "External Review Gates",
        &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-jobs",
        "External Review Jobs",
        &ExternalReviewReportService.jobs_report(std::slice::from_ref(&job)),
    )?;
    serde_json::to_value(json!({
        "component": "external_review_request",
        "request": request,
        "packet": packet,
        "gate": gate,
        "job": job
    }))
    .map_err(Into::into)
}

fn dispatch_external_review_job_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExternalReviewJobStatusToolInput = serde_json::from_value(arguments)?;
    let report = latest_json_report(&external_review_latest_path(
        &state.root,
        "external-review-jobs",
    ))?
    .context("no external review jobs report found")?;
    Ok(filter_report_item(&report, "jobs", "job_id", &input.job))
}

fn dispatch_external_review_result(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExternalReviewResultToolInput = serde_json::from_value(arguments)?;
    let report = latest_json_report(&external_review_latest_path(
        &state.root,
        "external-review-results",
    ))?
    .context("no external review results report found")?;
    Ok(filter_report_item(
        &report,
        "results",
        "result_id",
        &input.result,
    ))
}

fn dispatch_external_review_report(state: &McpState) -> Result<Value> {
    let report = json!({
        "component": "external_review_report",
        "providers": external_review_report_status(&state.root, "external-providers"),
        "jobs": external_review_report_status(&state.root, "external-review-jobs"),
        "results": external_review_report_status(&state.root, "external-review-results"),
        "gates": external_review_report_status(&state.root, "external-review-gates"),
        "normalization": external_review_report_status(&state.root, "external-review-normalization"),
        "doctor": ExternalReviewReportService.doctor_status(external_review_tools_governed_only()),
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_external_review_mcp_report(state, "external-review", "External Review", &report)?;
    Ok(report)
}

fn dispatch_antigravity_status(state: &McpState) -> Result<Value> {
    let (resolution, probe, contract) = mcp_antigravity_resolution_probe_contract();
    let (official_plugin_ready, mcp_registered) = mcp_antigravity_installation_readiness();
    let doctor = AntigravityDoctorIntegration.status(
        &resolution,
        &probe,
        &contract,
        official_plugin_ready,
        mcp_registered,
        mcp_antigravity_tools_governed_only(),
    );
    write_antigravity_mcp_report(
        state,
        "antigravity-detection",
        "Antigravity Detection",
        &probe,
    )?;
    write_antigravity_mcp_report(state, "antigravity-doctor", "Antigravity Doctor", &doctor)?;
    serde_json::to_value(doctor).map_err(Into::into)
}

fn dispatch_antigravity_doctor(state: &McpState) -> Result<Value> {
    dispatch_antigravity_status(state)
}

fn dispatch_antigravity_request(arguments: Value) -> Result<Value> {
    let input: AntigravityRequestToolInput = serde_json::from_value(arguments)?;
    let request = antigravity_review_request(
        &input.project,
        &input.task,
        parse_antigravity_mode(input.mode.as_deref().unwrap_or("audit-plan"))?,
        &input.question,
    );
    serde_json::to_value(request).map_err(Into::into)
}

fn dispatch_antigravity_job_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: AntigravityRunRefToolInput = serde_json::from_value(arguments)?;
    let run = latest_antigravity_mcp_run(state)?;
    if let Some(run) = run {
        if input
            .run
            .as_deref()
            .is_some_and(|run_id| run_id != run.run_id)
        {
            return Ok(json!({ "status": "not_found", "run": input.run }));
        }
        Ok(json!({
            "component": "antigravity_job_status",
            "run_id": run.run_id,
            "state": run.state,
            "dry_run": run.dry_run,
            "fixture_runner": run.fixture_runner,
            "message": run.message
        }))
    } else {
        Ok(json!({ "component": "antigravity_job_status", "status": "not_found" }))
    }
}

fn dispatch_antigravity_result(state: &McpState, arguments: Value) -> Result<Value> {
    let input: AntigravityRunRefToolInput = serde_json::from_value(arguments)?;
    let run = latest_antigravity_mcp_run(state)?;
    if let Some(run) = run {
        if input
            .run
            .as_deref()
            .is_some_and(|run_id| run_id != run.run_id)
        {
            return Ok(json!({ "status": "not_found", "run": input.run }));
        }
        serde_json::to_value(run.normalized_result).map_err(Into::into)
    } else {
        Ok(json!({ "component": "antigravity_result", "status": "not_found" }))
    }
}

fn dispatch_antigravity_report(state: &McpState) -> Result<Value> {
    let (resolution, probe, contract) = mcp_antigravity_resolution_probe_contract();
    let latest_run = latest_antigravity_mcp_run(state)?;
    let runs = latest_run.iter().cloned().collect::<Vec<_>>();
    let telemetry = AntigravityTelemetryService.report(&probe, &runs);
    let (official_plugin_ready, mcp_registered) = mcp_antigravity_installation_readiness();
    let doctor = AntigravityDoctorIntegration.status(
        &resolution,
        &probe,
        &contract,
        official_plugin_ready,
        mcp_registered,
        mcp_antigravity_tools_governed_only(),
    );
    let report = antigravity_report(
        resolution, probe, contract, None, latest_run, doctor, telemetry,
    );
    write_antigravity_mcp_report(state, "antigravity-report", "Antigravity Report", &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_antigravity_skills(state: &McpState) -> Result<Value> {
    let status = AntigravityOfficialPluginService.status(&mcp_antigravity_home());
    write_antigravity_mcp_report(state, "antigravity-skills", "Antigravity Skills", &status)?;
    serde_json::to_value(status).map_err(Into::into)
}

fn dispatch_antigravity_plugin(state: &McpState) -> Result<Value> {
    let status = AntigravityOfficialPluginService.status(&mcp_antigravity_home());
    write_antigravity_mcp_report(state, "antigravity-plugin", "Antigravity Plugin", &status)?;
    serde_json::to_value(status).map_err(Into::into)
}

fn dispatch_antigravity_auth_status(state: &McpState) -> Result<Value> {
    let (_resolution, probe, _contract) = mcp_antigravity_resolution_probe_contract();
    let auth = AntigravityAuthCheckService.help_only(
        &probe,
        vec!["reports/antigravity-detection/latest.json".to_owned()],
    );
    write_antigravity_mcp_report(state, "antigravity-auth", "Antigravity Auth", &auth)?;
    serde_json::to_value(auth).map_err(Into::into)
}

fn dispatch_antigravity_enablement_status(state: &McpState) -> Result<Value> {
    if let Some(value) = latest_json_report(&antigravity_latest_path(
        &state.root,
        "antigravity-enablement",
    ))? {
        Ok(value)
    } else {
        let (_resolution, probe, _contract) = mcp_antigravity_resolution_probe_contract();
        let auth = AntigravityAuthCheckService.help_only(
            &probe,
            vec!["reports/antigravity-detection/latest.json".to_owned()],
        );
        let state_value = AntigravityEnablementService.state_from_probe(&probe, Some(&auth));
        Ok(json!({
            "component": "antigravity_enablement_status",
            "status": "not_enabled",
            "state": state_value,
            "authority": "status-only; MCP cannot enable real Antigravity"
        }))
    }
}

fn dispatch_antigravity_visibility(state: &McpState) -> Result<Value> {
    let mut visibility = latest_json_report(&antigravity_latest_path(
        &state.root,
        "antigravity-visibility",
    ))?
    .unwrap_or_else(|| {
        json!({
            "component": "antigravity_visibility",
            "status": "not_reported",
            "authority": "status-only; MCP cannot install, configure, enable, or invoke Antigravity"
        })
    });
    if let Some(object) = visibility.as_object_mut() {
        object.insert(
            "current_role_authority".to_owned(),
            Value::String(
                "not_a_role_source; use eliot_host_session_status for the authenticated caller"
                    .to_owned(),
            ),
        );
    }
    Ok(visibility)
}

fn dispatch_antigravity_mcp_status(state: &McpState) -> Result<Value> {
    let home = antigravity_user_home()?;
    let previous_invocation = latest_antigravity_mcp_typed::<AntigravityMcpInvocationReceipt>(
        state,
        "antigravity-mcp-invocations",
    )?;
    Ok(antigravity_mcp_live_status(
        &home,
        previous_invocation.as_ref(),
    ))
}

fn dispatch_antigravity_plugin_status(state: &McpState) -> Result<Value> {
    let _ = state;
    Ok(antigravity_plugin_live_status(&antigravity_user_home()?))
}

fn antigravity_user_home() -> Result<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .context("USERPROFILE/HOME is unavailable for Antigravity config discovery")
}

fn antigravity_mcp_live_status(
    home: &Path,
    previous_invocation: Option<&AntigravityMcpInvocationReceipt>,
) -> Value {
    let configs = AntigravityMcpConfigService.status(home);
    let registered = configs.iter().any(|status| status.registered);
    let invocation_succeeded = previous_invocation
        .is_some_and(|receipt| receipt.succeeded && receipt.matching_audit_event);
    json!({
        "component": "antigravity_mcp_status",
        "registered": registered,
        "invocation_succeeded": invocation_succeeded,
        "configs": configs,
        "source": "live-user-config",
        "authority": "status-only; MCP cannot mutate Antigravity configuration"
    })
}

fn antigravity_plugin_live_status(home: &Path) -> Value {
    let status = AntigravityOfficialPluginService.status(home);
    let installed = status.gui_installed || status.cli_installed;
    let Value::Object(mut fields) = json!(status) else {
        return json!({
            "component": "antigravity_plugin_status",
            "installed": false,
            "source": "live-user-config",
            "authority": "status-only; MCP cannot install plugins",
            "error": "Antigravity plugin status serialization did not produce an object"
        });
    };
    fields.insert("component".to_owned(), json!("antigravity_plugin_status"));
    fields.insert("installed".to_owned(), json!(installed));
    fields.insert("source".to_owned(), json!("live-user-config"));
    fields.insert(
        "authority".to_owned(),
        json!("status-only; MCP cannot install plugins"),
    );
    Value::Object(fields)
}

fn dispatch_antigravity_live_smoke_status(state: &McpState) -> Result<Value> {
    latest_json_report(&antigravity_latest_path(
        &state.root,
        "antigravity-live-smoke",
    ))?
    .map_or_else(
        || {
            Ok(json!({
                "component": "antigravity_live_smoke_status",
                "status": "not_attempted",
                "authority": "status-only; MCP cannot run real Antigravity"
            }))
        },
        Ok,
    )
}

fn dispatch_antigravity_real_report(state: &McpState) -> Result<Value> {
    let (resolution, probe, contract) = mcp_antigravity_resolution_probe_contract();
    let auth = latest_antigravity_mcp_typed::<AntigravityAuthCheck>(state, "antigravity-auth")?
        .unwrap_or_else(|| {
            AntigravityAuthCheckService.help_only(
                &probe,
                vec!["reports/antigravity-detection/latest.json".to_owned()],
            )
        });
    let enablement = latest_antigravity_mcp_typed::<AntigravityEnablementReceipt>(
        state,
        "antigravity-enablement",
    )?;
    let live_smoke = latest_antigravity_mcp_typed::<AntigravityLiveSmokeResult>(
        state,
        "antigravity-live-smoke",
    )?;
    let disable =
        latest_antigravity_mcp_typed::<AntigravityDisableReceipt>(state, "antigravity-disable")?;
    let latest_run = latest_antigravity_mcp_run(state)?;
    let runs = latest_run.iter().cloned().collect::<Vec<_>>();
    let telemetry = AntigravityTelemetryService.report(&probe, &runs);
    let current_state = enablement.as_ref().map_or_else(
        || AntigravityEnablementService.state_from_probe(&probe, Some(&auth)),
        |receipt| receipt.requested_state,
    );
    let doctor = AntigravityRealExecutionDoctor.status(
        &resolution,
        &probe,
        &contract,
        &auth,
        current_state,
        live_smoke.as_ref(),
        disable.as_ref(),
        !runs.is_empty() || live_smoke.is_some(),
    );
    let report = antigravity_real_report(
        resolution, probe, contract, auth, enablement, live_smoke, disable, doctor, telemetry,
    );
    write_antigravity_mcp_report(state, "antigravity-real", "Antigravity Real", &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

#[allow(clippy::too_many_lines)]
async fn dispatch_external_review_run_mock(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExternalReviewRunMockToolInput = serde_json::from_value(arguments)?;
    let request: ExternalReviewRequest = read_json_file(&external_review_latest_path(
        &state.root,
        "external-review-requests",
    ))?;
    if request.request_id != input.request {
        return Ok(json!({
            "status": "not_found",
            "request": input.request
        }));
    }
    let provider = ExternalProviderRegistryService.inspect(&request.provider_id)?;
    let packet: ExternalReviewPacket = read_json_file(&external_review_latest_path(
        &state.root,
        "external-review-packets",
    ))?;
    let mut work_state = load_work_state(&state.root)?;
    let work_lease = request.work_lease_id.and_then(|lease_id| {
        work_state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == lease_id)
            .cloned()
    });
    let gate = ExternalReviewGate.decide(
        &request,
        &provider,
        ExternalReviewGateContext {
            work_lease: work_lease.as_ref(),
            worktree_lease: None,
            provider_integration_eval_gate_passed: true,
            incident_lockdown: IncidentService::new(&state.root).lockdown_active()?,
        },
    );
    if gate.decision != ExternalReviewGateDecisionKind::AllowMockRun {
        write_external_review_mcp_report(
            state,
            "external-review-gates",
            "External Review Gates",
            &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
        )?;
        return Ok(json!({ "status": "blocked", "gate": gate }));
    }
    let blob_store = BlobStore::open(&state.blob_store)?;
    let supervisor = AdapterSupervisor::builtin()?;
    let (mut job, raw_output) = ExternalReviewJobService
        .run_mock(&request, &provider, &packet, &supervisor, &blob_store)
        .await?;
    let normalization = ExternalReviewNormalizer.normalize(&request, &job, &raw_output);
    let mut results = Vec::new();
    if let Some(mut result) = normalization.result.clone() {
        job.result_id = Some(result.result_id.clone());
        let writer = state.writer.clone();
        let bridge = ExternalReviewBridgeService
            .write_and_route(
                &writer,
                &WriteAdmissionService,
                &mut work_state,
                AgentSessionId::new_v7(),
                &mut result,
            )
            .await?;
        write_external_review_mcp_report(
            state,
            "external-review-bridge",
            "External Review Bridge",
            &bridge,
        )?;
        results.push(result);
    }
    let work_report = WorkQueueService.status_report(&work_state, &request.project, &request.task);
    save_work_state_and_report(&state.root, &work_state, &work_report)?;
    write_external_review_mcp_report(
        state,
        "external-review-jobs",
        "External Review Jobs",
        &ExternalReviewReportService.jobs_report(std::slice::from_ref(&job)),
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-results",
        "External Review Results",
        &ExternalReviewReportService.results_report(&results),
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-normalization",
        "External Review Normalization",
        &ExternalReviewReportService
            .normalization_report(std::slice::from_ref(&normalization.receipt)),
    )?;
    serde_json::to_value(json!({
        "component": "external_review_run_mock",
        "job": job,
        "normalization": normalization.receipt,
        "results": results
    }))
    .map_err(Into::into)
}

fn canonical_idempotency_key(base: &str, suffix: &str) -> Result<String> {
    let base = base.trim();
    if base.is_empty() {
        anyhow::bail!("canonical idempotency_key must not be empty");
    }
    Ok(format!("canonical:{base}:{suffix}"))
}

fn canonical_fingerprint_marker(fingerprint: &str) -> String {
    format!("mcp_input_fingerprint={fingerprint}")
}

fn trace_ref_value<'a>(value: &'a str, category: &str) -> Result<&'a str> {
    let value = value.trim();
    let reference = value
        .strip_prefix(category)
        .and_then(|suffix| {
            suffix
                .strip_prefix(':')
                .or_else(|| suffix.strip_prefix('='))
        })
        .filter(|reference| !reference.trim().is_empty())
        .with_context(|| format!("{category} must use {category}:<canonical-ref>"))?;
    Ok(reference)
}

async fn require_canonical_task(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    expected_revision: u64,
) -> Result<TaskContract> {
    let task = require_task(state, project_id, task_id).await?;
    if task.memory_revision != MemoryRevision::new(expected_revision) {
        anyhow::bail!(
            "stale canonical task revision: expected {expected_revision}, current {}",
            task.memory_revision.value()
        );
    }
    Ok(task)
}

async fn canonical_trace_records(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<Vec<CanonicalRecord<CanonicalTraceCompletenessContract>>> {
    Ok(state
        .store
        .replay_view(project_id, Some(task_id), 128)
        .await?
        .trace_contracts)
}

async fn require_registered_trace(
    state: &McpState,
    task: &TaskContract,
    trace_ref: &str,
) -> Result<CanonicalRecord<CanonicalTraceCompletenessContract>> {
    let record = state
        .store
        .canonical_trace_by_trace_ref(task.project_id, task.task_id, trace_ref)
        .await?
        .with_context(|| format!("canonical complete trace is not registered: {trace_ref}"))?;
    revalidate_canonical_trace(state, task, &record.receipt_body).await?;
    Ok(record)
}

async fn canonical_source_binding(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    write_id: WriteId,
    source_content_hash: String,
    label: &str,
) -> Result<CanonicalTraceReceiptBinding> {
    let receipt = state
        .store
        .write_receipt_by_id(&write_id)
        .await?
        .with_context(|| format!("{label} has no canonical write receipt"))?;
    if receipt.project_id != project_id
        || receipt.task_id != Some(task_id)
        || !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
        || !is_canonical_hash(&receipt.input_hash)
        || !is_canonical_hash(&source_content_hash)
    {
        anyhow::bail!("{label} canonical receipt scope, status, or hash is invalid");
    }
    Ok(CanonicalTraceReceiptBinding {
        receipt: WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        },
        command_kind: receipt.command_kind,
        input_hash: receipt.input_hash,
        source_content_hash,
    })
}

async fn resolve_canonical_trace_evidence(
    state: &McpState,
    input: &TraceCompletenessToolInput,
    task: &TaskContract,
) -> Result<Vec<CanonicalTraceEvidence>> {
    let (observation_id, verification_id, artifact) = validate_trace_source_refs(input, task)?;
    let observation_write_id = WriteId::from_str(&observation_id)
        .context("actual observation id must be its canonical write id")?;
    let verifier_write_id = WriteId::from_uuid(verification_id.as_uuid());
    let observation = state
        .store
        .tool_observation_by_id(&observation_id)
        .await?
        .context("actual observation record is not canonical")?;
    let verification = state
        .store
        .verification_run_by_id(verification_id)
        .await?
        .context("registered verifier run is not canonical")?;
    if verification.result != VerificationResult::Passed {
        anyhow::bail!("trace registration requires a passed canonical verifier run");
    }
    let task_binding = canonical_source_binding(
        state,
        task.project_id,
        task.task_id,
        task.write_id,
        canonical_struct_hash(task)?,
        "task contract",
    )
    .await?;
    let observation_binding = canonical_source_binding(
        state,
        task.project_id,
        task.task_id,
        observation_write_id,
        canonical_struct_hash(&observation)?,
        "actual observation",
    )
    .await?;
    let verifier_binding = canonical_source_binding(
        state,
        task.project_id,
        task.task_id,
        verifier_write_id,
        canonical_struct_hash(&verification)?,
        "verifier run",
    )
    .await?;
    let task_ref = format!("task_contract:{}", task.task_id);
    let actual_ref = format!("actual_observation:{observation_id}");
    let verifier_ref = format!("verifier_run:{verification_id}");
    let receipt_sources = [
        (
            CanonicalTraceEvidenceKind::TaskContract,
            task_ref.clone(),
            task_binding.clone(),
        ),
        (
            CanonicalTraceEvidenceKind::ActualObservation,
            actual_ref.clone(),
            observation_binding.clone(),
        ),
        (
            CanonicalTraceEvidenceKind::VerifierRun,
            verifier_ref.clone(),
            verifier_binding.clone(),
        ),
    ];
    let mut evidence = canonical_receipt_trace_evidence(task, &receipt_sources)?;
    let input_refs = vec![task_ref, actual_ref, verifier_ref];
    let input_hashes = vec![
        task_binding.input_hash,
        observation_binding.input_hash,
        verifier_binding.input_hash,
    ];
    for (kind, reference) in canonical_derived_trace_references(
        task,
        &observation_id,
        verification_id,
        &artifact,
        state.profile.as_str(),
    ) {
        evidence.push(TraceCompletenessService::derivation_evidence(
            kind,
            task.project_id,
            task.task_id,
            task.memory_revision,
            reference,
            "eliot-canonical-resolution-v1".to_owned(),
            input_refs.clone(),
            input_hashes.clone(),
            TaintClass::LocalVerified,
        )?);
    }
    Ok(evidence)
}

fn canonical_receipt_trace_evidence(
    task: &TaskContract,
    sources: &[(
        CanonicalTraceEvidenceKind,
        String,
        CanonicalTraceReceiptBinding,
    )],
) -> Result<Vec<CanonicalTraceEvidence>> {
    sources
        .iter()
        .map(|(kind, reference, binding)| {
            TraceCompletenessService::receipt_evidence(
                *kind,
                task.project_id,
                task.task_id,
                task.memory_revision,
                reference.clone(),
                binding.clone(),
                TaintClass::LocalVerified,
            )
            .map_err(Into::into)
        })
        .collect()
}

async fn revalidate_canonical_trace(
    state: &McpState,
    task: &TaskContract,
    contract: &CanonicalTraceCompletenessContract,
) -> Result<()> {
    if contract.project_id != task.project_id
        || contract.task_id != task.task_id
        || contract.source_task_revision != task.memory_revision
    {
        anyhow::bail!("canonical trace is stale or outside the current task scope");
    }
    TraceCompletenessService::validate_canonical_contract(contract)?;
    for evidence in &contract.evidence {
        let CanonicalTraceEvidenceSource::CanonicalReceipt { binding } = &evidence.source else {
            continue;
        };
        let current = current_trace_receipt_binding(state, task, evidence).await?;
        if *binding != current {
            anyhow::bail!("canonical trace receipt binding changed or was fabricated");
        }
    }
    Ok(())
}

async fn current_trace_receipt_binding(
    state: &McpState,
    task: &TaskContract,
    evidence: &CanonicalTraceEvidence,
) -> Result<CanonicalTraceReceiptBinding> {
    match evidence.kind {
        CanonicalTraceEvidenceKind::TaskContract => {
            if evidence.reference != format!("task_contract:{}", task.task_id) {
                anyhow::bail!("task contract evidence reference is not canonical");
            }
            canonical_source_binding(
                state,
                task.project_id,
                task.task_id,
                task.write_id,
                canonical_struct_hash(task)?,
                "task contract",
            )
            .await
        }
        CanonicalTraceEvidenceKind::ActualObservation => {
            let observation_id = trace_ref_value(&evidence.reference, "actual_observation")?;
            if !task
                .observation_ids
                .iter()
                .any(|value| value == observation_id)
            {
                anyhow::bail!("actual observation evidence is no longer attached to the task");
            }
            let observation = state
                .store
                .tool_observation_by_id(observation_id)
                .await?
                .context("actual observation evidence no longer resolves")?;
            canonical_source_binding(
                state,
                task.project_id,
                task.task_id,
                WriteId::from_str(observation_id)?,
                canonical_struct_hash(&observation)?,
                "actual observation",
            )
            .await
        }
        CanonicalTraceEvidenceKind::VerifierRun => {
            let verification_id =
                VerificationId::from_str(trace_ref_value(&evidence.reference, "verifier_run")?)?;
            if !task.verification_ids.contains(&verification_id) {
                anyhow::bail!("verifier evidence is no longer attached to the task");
            }
            let verification = state
                .store
                .verification_run_by_id(verification_id)
                .await?
                .context("verifier evidence no longer resolves")?;
            if verification.result != VerificationResult::Passed {
                anyhow::bail!("canonical verifier evidence is no longer passed");
            }
            canonical_source_binding(
                state,
                task.project_id,
                task.task_id,
                WriteId::from_uuid(verification_id.as_uuid()),
                canonical_struct_hash(&verification)?,
                "verifier run",
            )
            .await
        }
        _ => anyhow::bail!("derived trace evidence cannot carry a canonical receipt binding"),
    }
}

fn is_canonical_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_trace_source_refs(
    input: &TraceCompletenessToolInput,
    task: &TaskContract,
) -> Result<(String, VerificationId, String)> {
    let observation_id =
        trace_ref_value(&input.actual_observation_ref, "actual_observation")?.to_owned();
    if !task
        .observation_ids
        .iter()
        .any(|candidate| candidate == &observation_id)
    {
        anyhow::bail!("actual_observation_ref is not attached to the canonical task");
    }
    let verification_id =
        VerificationId::from_str(trace_ref_value(&input.verifier_run_ref, "verifier_run")?)
            .context("parse verifier_run verification id")?;
    if !task.verification_ids.contains(&verification_id) {
        anyhow::bail!("verifier_run_ref is not attached to the canonical task");
    }
    let artifact = trace_ref_value(&input.artifact_ref, "artifact_ref")?.to_owned();
    let artifact_is_scoped = task.verification_scopes.iter().any(|scope| {
        scope.verification_id == verification_id
            && scope.artifact_refs.iter().any(|candidate| {
                candidate.resource_ref == artifact || candidate.content_hash == artifact
            })
    });
    if !artifact_is_scoped {
        anyhow::bail!("artifact_ref is not covered by the canonical verifier scope");
    }
    if input.source_route.trim().is_empty()
        || input.source_tool.trim().is_empty()
        || input.source_verifier.trim().is_empty()
        || input.outcome.trim().is_empty()
    {
        anyhow::bail!("trace source route, tool, verifier, and outcome must be explicit");
    }
    Ok((observation_id, verification_id, artifact))
}

fn canonical_derived_trace_references(
    task: &TaskContract,
    observation_id: &str,
    verification_id: VerificationId,
    artifact: &str,
    profile: &str,
) -> [(CanonicalTraceEvidenceKind, String); 10] {
    [
        (
            CanonicalTraceEvidenceKind::ContextPacket,
            format!(
                "context_packet:{}:{}",
                task.task_id,
                task.memory_revision.value()
            ),
        ),
        (
            CanonicalTraceEvidenceKind::CurrentTruthRevision,
            format!("current_truth_revision:{}", task.memory_revision.value()),
        ),
        (
            CanonicalTraceEvidenceKind::MemoryExposureSet,
            format!(
                "memory_exposure_set:{}:{}",
                task.task_id,
                task.project_sequence.value()
            ),
        ),
        (
            CanonicalTraceEvidenceKind::AgentToolEvents,
            format!("agent_tool_events:{observation_id}"),
        ),
        (
            CanonicalTraceEvidenceKind::ExpectedObservation,
            format!("expected_observation:verification:{verification_id}:passed"),
        ),
        (
            CanonicalTraceEvidenceKind::ArtifactRef,
            format!("artifact_ref:{artifact}"),
        ),
        (
            CanonicalTraceEvidenceKind::FinishDecision,
            format!("finish_decision:{}:{:?}", task.write_id, task.status),
        ),
        (
            CanonicalTraceEvidenceKind::PolicySnapshot,
            "policy_snapshot:eliot-canonical-v1".to_owned(),
        ),
        (
            CanonicalTraceEvidenceKind::ModelRoute,
            format!("model_route:{profile}"),
        ),
        (
            CanonicalTraceEvidenceKind::OutcomeAndCost,
            format!("outcome_and_cost:{observation_id}:{verification_id}"),
        ),
    ]
}
