use std::os::windows::process::ExitStatusExt as _;

#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch(config_path: &Path, command: HostCommand) -> Result<()> {
    match command {
        HostCommand::CognitiveSeal { request, instance } => {
            crate::cognitive_runner::seal(config_path, &request, &instance).await
        }
        HostCommand::CognitiveRun { request, instance } => {
            crate::cognitive_runner::run(config_path, &request, &instance).await
        }
        HostCommand::CognitiveStatus {
            run,
            project,
            task,
            instance,
        } => crate::cognitive_runner::status(config_path, &run, &project, &task, &instance).await,
        HostCommand::Inspect { host } => {
            if is_claude_desktop_host(&host) {
                write_json(&claude_desktop_doctor(config_path)?)
            } else {
                write_json(&inspect(parse_host(&host)?)?)
            }
        }
        HostCommand::Activate {
            host,
            surface,
            dry_run,
        } => {
            let family = parse_host(&host)?;
            anyhow::ensure!(
                family == AgentHostId::Claude,
                "only the Claude host family has selectable surfaces"
            );
            let surface = ClaudeSurface::parse(&surface).with_context(|| {
                format!("unknown Claude surface {surface}; expected `code` or `desktop`")
            })?;
            write_json(&activate_claude_surface(config_path, surface, dry_run)?)
        }
        HostCommand::Doctor { host } => {
            // A surface selector reports that surface; the bare family selector
            // reports both, because whether two are active at once is a fact
            // only the family view can see.
            match claude_surface_selector(&host) {
                Some(ClaudeSurface::ClaudeDesktopMcpb) => {
                    write_json(&claude_desktop_doctor(config_path)?)
                }
                Some(ClaudeSurface::ClaudeCodePlugin) => {
                    write_json(&doctor(config_path, AgentHostId::Claude)?)
                }
                None if parse_host(&host)? == AgentHostId::Claude => {
                    write_json(&claude_family_doctor(config_path)?)
                }
                None => write_json(&doctor(config_path, parse_host(&host)?)?),
            }
        }
        HostCommand::Render {
            host,
            mode,
            cwd,
            model,
            session,
            project,
            agent_session,
            task,
            work_item,
            role_lease,
            work_lease,
            worktree_lease,
            planned_verifier_ref,
            baseline,
            write_path,
        } => {
            let host = parse_host(&host)?;
            let mut scope = parse_launch_scope(
                project,
                agent_session,
                task,
                work_item,
                role_lease,
                work_lease,
                worktree_lease,
                planned_verifier_ref,
                baseline,
                write_path,
            )?;
            let _ = bind_launch_scope(config_path, host, cwd.as_deref(), &mut scope, false).await?;
            let contract = render_contract(
                config_path,
                host,
                parse_mode(&mode)?,
                cwd,
                model,
                session,
                &scope,
            )?;
            write_json(&contract)
        }
        HostCommand::Launch {
            host,
            mode,
            cwd,
            model,
            session,
            project,
            agent_session,
            task,
            work_item,
            role_lease,
            work_lease,
            worktree_lease,
            planned_verifier_ref,
            baseline,
            write_path,
            prompt,
            idempotency_key,
            timeout_seconds,
            dry_run,
        } => {
            Box::pin(launch(
                config_path,
                parse_host(&host)?,
                parse_mode(&mode)?,
                cwd,
                model,
                session,
                parse_launch_scope(
                    project,
                    agent_session,
                    task,
                    work_item,
                    role_lease,
                    work_lease,
                    worktree_lease,
                    planned_verifier_ref,
                    baseline,
                    write_path,
                )?,
                prompt,
                idempotency_key,
                timeout_seconds,
                dry_run,
                None,
                None,
            ))
            .await
        }
        HostCommand::InvocationStatus { idempotency_key } => {
            write_json(&invocation_status(config_path, &idempotency_key).await?)
        }
        HostCommand::Install {
            host,
            dry_run,
            wait_seconds,
        } => {
            if is_claude_desktop_host(&host) {
                write_json(&install_claude_desktop(config_path, dry_run, wait_seconds)?)
            } else {
                write_json(&install(config_path, parse_host(&host)?, dry_run)?)
            }
        }
        HostCommand::Uninstall {
            host,
            dry_run,
            wait_seconds,
        } => {
            if is_claude_desktop_host(&host) {
                write_json(&uninstall_claude_desktop(
                    config_path,
                    dry_run,
                    wait_seconds,
                )?)
            } else {
                write_json(&uninstall(config_path, parse_host(&host)?, dry_run)?)
            }
        }
        HostCommand::Event { host, event } => {
            write_json(&record_event(config_path, parse_host(&host)?, &event)?)
        }
        HostCommand::SessionRegister {
            host,
            session,
            client_instance,
        } => write_json(&register_session(
            config_path,
            parse_host(&host)?,
            session,
            client_instance,
        )?),
        HostCommand::RoleGrant {
            task,
            session,
            role,
            capability,
            ttl_minutes,
        } => write_json(
            &grant_role(config_path, &task, &session, &role, capability, ttl_minutes).await?,
        ),
        HostCommand::BrokerStatus => write_json(&broker_status(config_path)?),
        HostCommand::SkillLint => {
            let report = SkillPackService.lint(&repo_root(config_path))?;
            if !report.valid {
                write_json(&report)?;
                bail!("ELIOT skill pack lint failed: {}", report.errors.join("; "));
            }
            write_json(&report)
        }
        HostCommand::SkillSync => {
            let root = repo_root(config_path);
            let sync = SkillPackService.sync(&root)?;
            let report = SkillPackService.lint(&root)?;
            if !report.valid {
                write_json(&report)?;
                bail!(
                    "ELIOT skill pack is invalid after sync: {}",
                    report.errors.join("; ")
                );
            }
            write_json(&sync)
        }
    }
}

fn inspect(host: AgentHostId) -> Result<Value> {
    let profile = HostProfileService.probe(host)?;
    Ok(json!({
        "schema_version": "eliot-host-inspection-v1",
        "host_identity_is_not_a_role": true,
        "runtime_profile": profile,
    }))
}

fn doctor(config_path: &Path, host: AgentHostId) -> Result<Value> {
    let root = repo_root(config_path);
    let profile = HostProfileService.probe(host)?;
    let skills = SkillPackService.lint(&root)?;
    let bundle = bundle_root(&root, host);
    let (config_ref, lifecycle_ref) = integration_refs(&bundle, host);
    let config_valid =
        serde_json::from_reader::<_, Value>(std::fs::File::open(&config_ref)?).is_ok();
    let lifecycle_valid = lifecycle_ref.is_file();
    let ready = profile.status == HostProfileStatus::Current
        && skills.valid
        && config_valid
        && lifecycle_valid;
    Ok(json!({
        "schema_version": "eliot-host-doctor-v1",
        "ready": ready,
        "host_identity_is_not_a_role": true,
        "profile": profile,
        "skill_pack": skills,
        "bundle": {
            "path": bundle,
            "hash": bundle_hash(&bundle, host)?,
            "config_ref": config_ref,
            "config_valid": config_valid,
            "lifecycle_ref": lifecycle_ref,
            "lifecycle_valid": lifecycle_valid
        }
    }))
}

fn open_claude_desktop_package(target: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let executable = claude_desktop_executable()?;
        StdCommand::new(&executable)
            .arg(target)
            .spawn()
            .with_context(|| {
                format!(
                    "open Claude Desktop package {} through {}",
                    target.display(),
                    executable.display()
                )
            })?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        bail!("Claude Desktop MCPB installation is supported only on Windows")
    }
}

fn open_claude_desktop() -> Result<()> {
    #[cfg(windows)]
    {
        let executable = claude_desktop_executable()?;
        StdCommand::new(&executable)
            .spawn()
            .with_context(|| format!("open Claude Desktop through {}", executable.display()))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        bail!("Claude Desktop is supported only on Windows")
    }
}

fn wait_for_claude_desktop_install(
    manifest_name: &str,
    manifest_version: &str,
    running_governor_hash: &str,
    wait_seconds: u64,
) -> Result<ClaudeDesktopExtensionState> {
    let deadline = Instant::now() + Duration::from_secs(wait_seconds);
    loop {
        if let Some(state) = claude_desktop_extension_state(manifest_name)?
            && claude_desktop_state_is_current(&state, manifest_version, running_governor_hash)
        {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            bail!(
                "Claude Desktop did not finish installing {manifest_name} {manifest_version} within {wait_seconds} seconds"
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn wait_for_claude_desktop_uninstall(manifest_name: &str, wait_seconds: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(wait_seconds);
    loop {
        if claude_desktop_extension_state(manifest_name)?.is_none() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "Claude Desktop did not finish uninstalling {manifest_name} within {wait_seconds} seconds"
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn render_contract(
    config_path: &Path,
    host: AgentHostId,
    mode: HostMode,
    cwd: Option<PathBuf>,
    model: Option<String>,
    session: Option<String>,
    scope: &HostLaunchScope,
) -> Result<eliot_types::HostLaunchContract> {
    let root = repo_root(config_path);
    let profile = HostProfileService.probe(host)?;
    let cwd = cwd.unwrap_or_else(|| root.clone());
    Ok(HostLaunchContractService.render(&root, &profile, mode, &cwd, model, session, scope)?)
}

fn uses_managed_antigravity_launch(host: AgentHostId, structured_capture_requested: bool) -> bool {
    host == AgentHostId::Antigravity && !structured_capture_requested
}

fn uses_managed_antigravity_containment(host: AgentHostId) -> bool {
    host == AgentHostId::Antigravity
}

fn antigravity_permission_profile(bounded_auditor: bool) -> &'static str {
    if bounded_auditor {
        "ul_structured_auditor"
    } else {
        "canonical_readonly_candidate_plan"
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn launch(
    config_path: &Path,
    host: AgentHostId,
    mode: HostMode,
    cwd: Option<PathBuf>,
    model: Option<String>,
    session: Option<String>,
    mut scope: HostLaunchScope,
    prompt: Option<String>,
    idempotency_key: Option<String>,
    timeout_seconds: Option<u64>,
    dry_run: bool,
    structured_output_schema: Option<Value>,
    structured_capture: Option<&mut Value>,
) -> Result<()> {
    let bounded_auditor = structured_capture.is_some()
        && scope.project_id.is_some()
        && scope.task_id.is_some()
        && scope.role_lease_id.is_some();
    let managed_antigravity = uses_managed_antigravity_launch(host, structured_capture.is_some());
    let antigravity_containment = uses_managed_antigravity_containment(host);
    let canonical_authority = bind_launch_scope(
        config_path,
        host,
        cwd.as_deref(),
        &mut scope,
        bounded_auditor,
    )
    .await?;
    let mut contract = render_contract(config_path, host, mode, cwd, model, session, &scope)?;
    if host == AgentHostId::Antigravity {
        finalize_antigravity_contract(&mut contract, idempotency_key.as_deref(), timeout_seconds)?;
        antigravity_permission_profile(bounded_auditor)
            .clone_into(&mut contract.permission_profile);
    } else {
        if idempotency_key.is_some() {
            bail!("--idempotency-key is currently managed for Antigravity only");
        }
        if timeout_seconds.is_some() && !bounded_auditor {
            bail!("--timeout-seconds requires Antigravity or a bounded structured launch");
        }
        if bounded_auditor {
            "ul_structured_auditor".clone_into(&mut contract.permission_profile);
        }
    }
    if bounded_auditor && let Some(timeout_seconds) = timeout_seconds {
        contract.wall_clock_budget_seconds = timeout_seconds.clamp(1, MAX_MANAGED_LAUNCH_SECONDS);
    }
    contract.contract_hash.clear();
    contract.contract_hash = blake3::hash(&serde_json::to_vec(&contract)?)
        .to_hex()
        .to_string();
    let profile = HostProfileService.probe(host)?;
    let root = repo_root(config_path);
    let source_bundle = bundle_root(&root, host);
    let governor = std::env::current_exe().context("resolve running eliot-governor executable")?;
    let governor_env = governor.to_string_lossy().replace('\\', "/");
    let discovered_claude_bundle = if host == AgentHostId::Claude {
        matching_installed_claude_bundle(&source_bundle, &governor)?
    } else {
        None
    };
    let (bundle, attach_session_plugin) = if let Some(installed) = discovered_claude_bundle {
        (installed, false)
    } else if dry_run {
        (source_bundle, host == AgentHostId::Claude)
    } else {
        (
            prepare_launch_bundle(config_path, host, &source_bundle, &governor)?,
            host == AgentHostId::Claude,
        )
    };
    let prompt_hash = format!(
        "blake3:{}",
        blake3::hash(prompt.as_deref().unwrap_or_default().as_bytes()).to_hex()
    );
    let prompt_present = prompt.is_some();
    let (mut program, args) = launch_argv(
        host,
        &profile.executable_path,
        &bundle,
        attach_session_plugin,
        &contract,
        structured_output_schema.as_ref(),
        prompt,
    )?;
    let invocation_root = invocation_root(config_path, &contract.invocation_id);
    let receipt_args = if prompt_present {
        &args[..args.len().saturating_sub(1)]
    } else {
        args.as_slice()
    };
    let rendered = json!({
        "schema_version": "eliot-host-launch-plan-v1",
        "contract": &contract,
        "program": &program,
        "argv_without_prompt": receipt_args,
        "prompt_hash": &prompt_hash,
        "resolved_integration_bundle_ref": &bundle,
        "session_plugin_override": attach_session_plugin,
        "environment_names": launch_environment_names(host, mode, &contract),
        "daemon_start_policy": {
            "instance": DEFAULT_INSTANCE_NAME,
            "reuse_ready": true,
            "start_if_absent": true,
            "hidden_user_process": true,
            "service_registry_or_admin_mutation": false
        },
        "dry_run": dry_run,
    });
    if dry_run {
        return write_json(&rendered);
    }

    let _managed_guard = if antigravity_containment {
        Some(managed_launch_mutex().lock().await)
    } else {
        None
    };
    if antigravity_containment {
        program = prepare_antigravity_executable_snapshot(&profile, &contract)?
            .to_string_lossy()
            .into_owned();
    }
    let request_hash = managed_request_hash(&contract, &program, &args)?;
    let mut invocation_lock = None;
    if antigravity_containment {
        match reconcile_existing_managed_invocation(config_path, &invocation_root, &request_hash)
            .await?
        {
            ExistingManagedInvocation::New => {}
            ExistingManagedInvocation::Reuse(receipt) => {
                if structured_capture.is_some() {
                    bail!(
                        "provider dispatched: contained Antigravity invocation already completed; its structured output was intentionally not retained and redispatch is forbidden"
                    );
                }
                return write_json(&receipt);
            }
            ExistingManagedInvocation::UnknownOutcome => {
                bail!(
                    "provider dispatched: Antigravity invocation has an unknown outcome; inspect `host invocation-status --idempotency-key {}` and do not redispatch",
                    contract.idempotency_key
                );
            }
            ExistingManagedInvocation::InProgress => {
                bail!(
                    "provider dispatched: Antigravity invocation with this idempotency key is already in progress"
                );
            }
        }
        invocation_lock = Some(ManagedInvocationLock::acquire(&invocation_root)?);
    }

    let daemon_readiness = runtime_bootstrap::ensure_default_daemon_ready(
        config_path,
        &governor,
        named_pipe_ipc::IPC_PROTOCOL_VERSION,
        "host_launch",
    )
    .await?;

    let mut command = Command::new(&program);
    command
        .args(&args)
        .current_dir(&contract.cwd_or_worktree)
        .kill_on_drop(true);
    let managed_environment = if antigravity_containment {
        Some(configure_antigravity_environment(
            &mut command,
            config_path,
            &contract,
            &governor_env,
        )?)
    } else {
        configure_standard_managed_environment(&mut command, &governor_env);
        None
    };
    command.env("ELIOT_GOVERNOR_CONFIG", config_path);
    if host == AgentHostId::Antigravity && bounded_auditor {
        command.env("ELIOT_MCP_ACCESS_PROFILE", "external_auditor");
    }
    if let Some(agent_session_id) = contract.agent_session_id {
        command.env("ELIOT_AGENT_SESSION_ID", agent_session_id.to_string());
    }
    if let Some(project_id) = contract.project_id {
        command.env("ELIOT_PROJECT_ID", project_id.to_string());
    }
    if let Some(task_id) = contract.task_id {
        command.env("ELIOT_TASK_ID", task_id.to_string());
    }
    if let Some(work_item_id) = contract.work_item_id {
        command.env("ELIOT_WORK_ITEM_ID", work_item_id.to_string());
    }
    if let Some(role_lease_id) = &contract.role_lease_id {
        command.env("ELIOT_ROLE_LEASE_ID", role_lease_id);
    }
    if let Some(work_lease_id) = contract.work_lease_id {
        command.env("ELIOT_WORK_LEASE_ID", work_lease_id.to_string());
    }
    if let Some(worktree_lease_id) = contract.worktree_lease_id {
        command.env("ELIOT_WORKTREE_LEASE_ID", worktree_lease_id.to_string());
    }
    if antigravity_containment {
        command.stdin(Stdio::null());
    }
    if host == AgentHostId::OpenCode {
        command.env("OPENCODE_CONFIG_DIR", &bundle);
        if mode == HostMode::Supervised {
            let isolated_config = runtime_root(config_path)
                .join("host-sandboxes")
                .join("opencode-xdg");
            std::fs::create_dir_all(&isolated_config)?;
            command.env("XDG_CONFIG_HOME", isolated_config);
        }
    }
    if mode == HostMode::Interactive {
        let status = command.status().await?;
        if !status.success() {
            bail!("{} interactive launch exited with {status}", host.as_str());
        }
        return Ok(());
    }

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let daemon_readiness = serde_json::to_value(daemon_readiness)?;
    let launch_boundary = if antigravity_containment {
        Some(managed_launch_boundary_attestation(
            &profile,
            &program,
            &bundle,
            &invocation_root,
            managed_environment.context("managed Antigravity environment was not prepared")?,
        )?)
    } else {
        None
    };
    let _antigravity_executable_guard = if antigravity_containment {
        Some(lock_antigravity_executable_snapshot(Path::new(&program))?)
    } else {
        None
    };
    let provider_runtime = ProviderRuntime::production(config_path)?;
    if managed_antigravity {
        let authority = canonical_authority
            .managed
            .as_ref()
            .context("managed Antigravity launch lost canonical authority")?;
        return run_managed_antigravity(
            config_path,
            &provider_runtime,
            command,
            &contract,
            &profile,
            &program,
            &args,
            &invocation_root,
            &request_hash,
            &prompt_hash,
            &daemon_readiness,
            authority,
            launch_boundary.context("managed Antigravity launch boundary disappeared")?,
            invocation_lock.context("managed invocation lock was not acquired")?,
        )
        .await;
    }
    if antigravity_containment {
        let mut attempt = ContainedAntigravityAttemptJournal {
            schema_version: CONTAINED_ANTIGRAVITY_ATTEMPT_SCHEMA_V1.to_owned(),
            invocation_id: contract.invocation_id.clone(),
            idempotency_key: contract.idempotency_key.clone(),
            request_hash: request_hash.clone(),
            contract_hash: contract.contract_hash.clone(),
            host: AgentHostId::Antigravity,
            project_id: contract.project_id,
            task_id: contract.task_id,
            agent_session_id: contract.agent_session_id,
            role_lease_id: contract.role_lease_id.clone(),
            permission_profile: contract.permission_profile.clone(),
            prompt_hash: prompt_hash.clone(),
            owner_pid: std::process::id(),
            bounded_auditor_authority_hash: canonical_authority
                .bounded_auditor
                .as_ref()
                .map(|authority| authority.authority_hash.clone()),
            launch_boundary: launch_boundary
                .clone()
                .context("contained Antigravity launch boundary disappeared")?,
            attempt_hash: String::new(),
            attempt_recorded_before_provider_call: true,
            provider_call_budget_consumed: true,
            redispatch_allowed: false,
            started_at: OffsetDateTime::now_utc(),
        };
        attempt.attempt_hash = contained_antigravity_attempt_hash(&attempt)?;
        std::fs::create_dir_all(&invocation_root)?;
        if invocation_root.join("attempt.json").exists() {
            bail!("contained Antigravity attempt-before-call CAS already exists");
        }
        atomic_write_json(&invocation_root.join("attempt.json"), &attempt)?;
        write_provider_start_marker(&invocation_root, &attempt.attempt_hash)?;
    }
    let wall_clock = Duration::from_secs(contract.wall_clock_budget_seconds);
    let raw_command = command.as_std();
    let provider_route_policy = eliot_types::ProviderRoutePolicy::for_route(
        host,
        "host-launch",
        eliot_types::ProviderDeclaredBudget::new(
            u64::try_from(wall_clock.as_millis()).unwrap_or(u64::MAX),
            u64::try_from(MAX_SECRET_BOUNDARY_BYTES).unwrap_or(u64::MAX),
        )
        .with_first_output_deadline_ms(None),
    );
    let provider_spec = eliot_engine::ProviderProcessSpec {
        operation_id: format!("host-provider-{}", contract.invocation_id),
        invocation_id: Some(contract.invocation_id.clone()),
        executable: raw_command.get_program().into(),
        args: raw_command
            .get_args()
            .map(std::ffi::OsString::from)
            .collect(),
        cwd: raw_command
            .get_current_dir()
            .map(ToOwned::to_owned)
            .map_or_else(std::env::current_dir, Ok)?,
        environment: raw_command
            .get_envs()
            .filter_map(|(name, value)| {
                value.map(|value| {
                    (
                        std::ffi::OsString::from(name),
                        std::ffi::OsString::from(value),
                    )
                })
            })
            .collect(),
        stdin_payload: None,
        route_policy: provider_route_policy,
        cancellation: eliot_engine::runtime_supervision::CancellationToken::new(),
        deadline: tokio::time::Instant::now() + wall_clock,
        runtime_contract_sha256: Some(contract.contract_hash.clone()),
        role_lease_id: contract.role_lease_id.clone(),
        role_lease_epoch: Some(contract.role_lease_epoch),
    };
    let spawned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spawned_in_hook = std::sync::Arc::clone(&spawned);
    let invocation_root_for_hook = invocation_root.clone();
    let provider_runner = provider_runtime.runner();
    let mut on_spawned = move |_| {
        spawned_in_hook.store(true, std::sync::atomic::Ordering::Release);
        if antigravity_containment {
            let validation = (|| -> Result<()> {
                validate_contained_antigravity_attempt(
                    &read_contained_antigravity_attempt(
                        &invocation_root_for_hook.join("attempt.json"),
                    )?
                        .context(
                            "contained Antigravity attempt journal disappeared after dispatch",
                        )?,
                )
                .context(
                    "provider dispatched: contained Antigravity attempt journal became invalid; outcome is unknown",
                )?;
                Ok(())
            })();
            validation.map_err(|error| {
                eliot_engine::EngineError::RuntimeSupervision(format!(
                    "contained Antigravity post-spawn validation failed: {error:#}"
                ))
            })?;
        }
        Ok(())
    };
    let process = match eliot_engine::ProviderProcessRunner::run(
        provider_runner.as_ref(),
        provider_spec,
        &mut on_spawned,
    ).await {
        Ok(process) => process,
        Err(error) => {
            if antigravity_containment
                && !spawned.load(std::sync::atomic::Ordering::Acquire)
            {
                clear_contained_antigravity_pre_dispatch(&invocation_root).with_context(|| {
                    format!(
                        "{} provider launch failed before dispatch and its pre-dispatch journal could not be cleared",
                        host.as_str()
                    )
                })?;
            }
            let dispatch_started = spawned.load(std::sync::atomic::Ordering::Acquire);
            return Err(error).with_context(|| {
                if dispatch_started {
                    format!(
                        "provider dispatched: {} launch admission failed; process tree reaped and outcome requires reconciliation",
                        host.as_str()
                    )
                } else {
                    format!("{} provider launch failed before dispatch", host.as_str())
                }
            });
        }
    };
    anyhow::ensure!(
        !process.timed_out,
        "provider dispatched: {} exceeded the {} second wall-clock budget; process tree reaped; outcome requires reconciliation",
        host.as_str(),
        contract.wall_clock_budget_seconds
    );
    anyhow::ensure!(
        process.worker_error.is_none() && process.reap_receipt.proves_complete_reap(),
        "provider dispatched: {} cleanup failed; outcome is unknown: {:?}",
        host.as_str(),
        process.worker_error
    );
    let reap_receipt = process.reap_receipt.clone();
    let output = std::process::Output {
        status: std::process::ExitStatus::from_raw(
            process.exit_code.unwrap_or(i32::MAX).cast_unsigned(),
        ),
        stdout: process.stdout,
        stderr: process.stderr,
    };
    let sanitized_stdout = sanitize_managed_output(&output.stdout);
    let sanitized_stderr = sanitize_managed_output(&output.stderr);
    std::fs::create_dir_all(&invocation_root).with_context(
        || "provider dispatched: create invocation archive failed; outcome is unknown",
    )?;
    let stdout_ref = structured_capture
        .is_none()
        .then(|| invocation_root.join("stdout.jsonl"));
    let stderr_ref = structured_capture
        .is_none()
        .then(|| invocation_root.join("stderr.log"));
    if let Some(stdout_ref) = stdout_ref.as_ref() {
        std::fs::write(stdout_ref, &sanitized_stdout.bytes).with_context(
            || "provider dispatched: write stdout archive failed; outcome is unknown",
        )?;
    }
    if let Some(stderr_ref) = stderr_ref.as_ref() {
        std::fs::write(stderr_ref, &sanitized_stderr.bytes).with_context(
            || "provider dispatched: write stderr archive failed; outcome is unknown",
        )?;
    }
    let mut result_receipt = json!({
        "schema_version": "eliot-host-launch-result-v1",
        "contract_hash": contract.contract_hash,
        "request_hash": request_hash,
        "idempotency_key": contract.idempotency_key,
        "host": host,
        "exit_status": output.status.code(),
        "success": output.status.success(),
        "stdout_ref": stdout_ref,
        "stderr_ref": stderr_ref,
        "stdout_hash": hash_bytes(&sanitized_stdout.bytes),
        "stderr_hash": hash_bytes(&sanitized_stderr.bytes),
        "stdout_redaction": sanitized_stdout.receipt,
        "stderr_redaction": sanitized_stderr.receipt,
        "governor_daemon": &daemon_readiness,
        "launch_boundary": launch_boundary,
        "bounded_auditor_authority": canonical_authority.bounded_auditor,
        "reap_receipt": reap_receipt,
        "candidate_only": true,
        "provider_outcome_status": if structured_capture.is_some() {
            "pending_structured_validation"
        } else {
            "process_exit_observed"
        },
        "structured_capture": {
            "requested": structured_capture.is_some(),
            "status": if structured_capture.is_some() {
                "pending"
            } else {
                "not_requested"
            }
        }
    });
    let captured_value = if structured_capture.is_some() {
        Some(persist_and_parse_structured_host_output(
            host,
            &invocation_root,
            &sanitized_stdout.bytes,
            &mut result_receipt,
        )?)
    } else {
        atomic_write_json(&invocation_root.join("result.json"), &result_receipt).with_context(
            || "provider dispatched: write invocation result failed; outcome is unknown",
        )?;
        None
    };
    if let (Some(capture), Some(value)) = (structured_capture, captured_value) {
        *capture = value;
    } else {
        std::io::stdout()
            .write_all(&sanitized_stdout.bytes)
            .context("provider dispatched: forward provider stdout failed")?;
        std::io::stderr()
            .write_all(&sanitized_stderr.bytes)
            .context("provider dispatched: forward provider stderr failed")?;
    }
    if !output.status.success() {
        bail!(
            "provider dispatched: {} supervised launch exited with {}",
            host.as_str(),
            output.status
        );
    }
    Ok(())
}

pub(crate) async fn invoke_ul_reasoning(
    config_path: &Path,
    cwd: &Path,
    request: &eliot_types::UlReasoningRequest,
) -> Result<Value> {
    invoke_ul_reasoning_with_scope(config_path, cwd, request, HostLaunchScope::default(), None)
        .await
}

pub(crate) async fn prepare_ul_auditor_scope(
    config_path: &Path,
    host: AgentHostId,
    project_id: ProjectId,
    task_id: TaskId,
    session_id: SessionId,
    client_instance: &str,
) -> Result<HostLaunchScope> {
    prepare_auditor_scope(
        config_path,
        host,
        project_id,
        task_id,
        session_id,
        client_instance,
        30,
    )
    .await
}

#[allow(dead_code)]
pub(crate) async fn prepare_cognitive_external_scope(
    config_path: &Path,
    host: AgentHostId,
    project_id: ProjectId,
    task_id: TaskId,
    session_id: SessionId,
    client_instance: &str,
) -> Result<HostLaunchScope> {
    prepare_auditor_scope(
        config_path,
        host,
        project_id,
        task_id,
        session_id,
        client_instance,
        360,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn prepare_auditor_scope(
    config_path: &Path,
    host: AgentHostId,
    project_id: ProjectId,
    task_id: TaskId,
    session_id: SessionId,
    client_instance: &str,
    ttl_minutes: i64,
) -> Result<HostLaunchScope> {
    let agent_session_id = AgentSessionId::from_uuid(session_id.as_uuid());
    register_session(
        config_path,
        host,
        Some(agent_session_id.to_string()),
        Some(client_instance.to_owned()),
    )?;
    let capability_scope = external_auditor_capability_scope();
    let grant = grant_role(
        config_path,
        &task_id.to_string(),
        &agent_session_id.to_string(),
        "auditor",
        capability_scope,
        ttl_minutes,
    )
    .await?;
    let role_lease_id = grant
        .pointer("/task_role_lease/role_lease_id")
        .and_then(Value::as_str)
        .context("UL auditor role grant returned no TaskRoleLease")?
        .to_owned();
    let role_lease_epoch = grant
        .pointer("/task_role_lease/epoch")
        .and_then(Value::as_u64)
        .context("UL auditor role grant returned no lease epoch")?;
    let operation_generation = grant
        .pointer("/task_role_lease/generation")
        .and_then(Value::as_u64)
        .context("UL auditor role grant returned no operation generation")?;
    Ok(HostLaunchScope {
        project_id: Some(project_id),
        agent_session_id: Some(agent_session_id),
        task_id: Some(task_id),
        work_item_id: None,
        role_lease_id: Some(role_lease_id),
        role_lease_epoch,
        operation_generation,
        work_lease_id: None,
        worktree_lease_id: None,
        planned_verifier_ref: None,
        baseline_commit: None,
        allowed_paths: Vec::new(),
        forbidden_paths: vec![
            "global-provider-config".to_owned(),
            "truth-promotion".to_owned(),
        ],
    })
}

fn external_auditor_capability_scope() -> Vec<String> {
    let mut capability_scope = crate::mcp_stdio::PART_E_WORKER_TOOLS
        .iter()
        .copied()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    capability_scope.extend([
        "emit_candidate_observation".to_owned(),
        "request_controller_review".to_owned(),
    ]);
    capability_scope
}

pub(crate) async fn invoke_ul_scoped_reasoning(
    config_path: &Path,
    cwd: &Path,
    request: &eliot_types::UlReasoningRequest,
    scope: HostLaunchScope,
) -> Result<Value> {
    if scope.project_id != Some(request.project_id)
        || scope.task_id != Some(request.task_id)
        || scope.agent_session_id.is_none()
        || scope.role_lease_id.is_none()
    {
        bail!(
            "UL scoped provider launch requires matching project/task plus AgentSessionHostBinding and TaskRoleLease"
        );
    }
    let provider_session = (request.route.host() == AgentHostId::Claude).then(|| {
        scope
            .agent_session_id
            .map(|session| session.to_string())
            .context("Claude UL launch requires a fresh scoped session")
    });
    let provider_session = provider_session.transpose()?;
    invoke_ul_reasoning_with_scope(config_path, cwd, request, scope, provider_session).await
}

async fn invoke_ul_reasoning_with_scope(
    config_path: &Path,
    cwd: &Path,
    request: &eliot_types::UlReasoningRequest,
    scope: HostLaunchScope,
    provider_session: Option<String>,
) -> Result<Value> {
    let host = request.route.host();
    let doctor = doctor(config_path, host)?;
    if doctor.get("ready").and_then(Value::as_bool) != Some(true) {
        bail!("{} host doctor is not ready", host.as_str());
    }
    let prompt = format!(
        "REQUEST IDEMPOTENCY KEY: {}\n\n{}\n\nReturn one JSON value matching this exact schema and no surrounding prose:\n{}",
        request.idempotency_key,
        request.prompt,
        serde_json::to_string(&request.output_schema)?
    );
    let config_path = config_path.to_path_buf();
    let cwd = cwd.to_path_buf();
    let idempotency_key =
        (host == AgentHostId::Antigravity).then(|| request.idempotency_key.clone());
    let scoped = scope.task_id.is_some();
    let timeout_seconds =
        (host == AgentHostId::Antigravity || scoped).then_some(request.timeout_seconds);
    let model = request.model.clone();
    let output_schema = request.output_schema.clone();
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build supervised UL host runtime")?;
        let mut captured = Value::Null;
        runtime.block_on(launch(
            &config_path,
            host,
            HostMode::Supervised,
            Some(cwd),
            model,
            provider_session,
            scope,
            Some(prompt),
            idempotency_key,
            timeout_seconds,
            false,
            Some(output_schema),
            Some(&mut captured),
        ))?;
        Ok(captured)
    })
    .await
    .context("provider dispatched: supervised UL host task failed to join; outcome is unknown")?
}

fn parse_structured_host_output(host: AgentHostId, stdout: &[u8]) -> Result<Value> {
    if let Ok(value) = serde_json::from_slice::<Value>(stdout)
        && let Ok(structured) = structured_value_from_host_event(host, value)
    {
        return Ok(structured);
    }
    for line in stdout.rsplit(|byte| *byte == b'\n') {
        let line = line
            .iter()
            .copied()
            .skip_while(u8::is_ascii_whitespace)
            .collect::<Vec<_>>();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_slice::<Value>(&line)
            && let Ok(structured) = structured_value_from_host_event(host, value)
        {
            return Ok(structured);
        }
    }
    bail!(
        "{} supervised output contained no structured JSON result",
        host.as_str()
    )
}

fn structured_value_from_host_event(host: AgentHostId, value: Value) -> Result<Value> {
    if let Some(text) = value.as_str() {
        return parse_json_text(text);
    }
    if let Some(structured) = value.get("structured_output") {
        return Ok(structured.clone());
    }
    if let Some(result) = value.get("result") {
        if let Some(text) = result.as_str() {
            return parse_json_text(text);
        }
        if result.is_object() || result.is_array() {
            return Ok(result.clone());
        }
    }
    if value.get("answers").is_some()
        || value.get("purpose").is_some()
        || value.get("boundaries").is_some()
        || (host == AgentHostId::Antigravity && (value.is_object() || value.is_array()))
    {
        return Ok(value);
    }
    bail!("{} host event is not a structured UL result", host.as_str())
}

fn persist_and_parse_structured_host_output(
    host: AgentHostId,
    invocation_root: &Path,
    stdout: &[u8],
    result_receipt: &mut Value,
) -> Result<Value> {
    let result_path = invocation_root.join("result.json");
    atomic_write_json(&result_path, result_receipt).with_context(|| {
        "provider dispatched: write pre-parse invocation result failed; provider outcome is known but its receipt is incomplete"
    })?;

    match parse_structured_host_output(host, stdout) {
        Ok(value) => {
            let receipt = result_receipt
                .as_object_mut()
                .context("host launch result receipt is not an object")?;
            receipt.insert(
                "provider_outcome_status".to_owned(),
                json!("structured_output_valid"),
            );
            receipt.insert("structured_output_valid".to_owned(), json!(true));
            receipt.insert(
                "structured_capture".to_owned(),
                json!({
                    "requested": true,
                    "status": "valid",
                    "output_hash": hash_bytes(&serde_json::to_vec(&value)?)
                }),
            );
            atomic_write_json(&result_path, result_receipt).with_context(|| {
                "provider dispatched: write valid structured-output receipt failed; provider outcome is known but its receipt is incomplete"
            })?;
            Ok(value)
        }
        Err(error) => {
            let receipt = result_receipt
                .as_object_mut()
                .context("host launch result receipt is not an object")?;
            receipt.insert(
                "provider_outcome_status".to_owned(),
                json!("invalid_structured_output"),
            );
            receipt.insert("structured_output_valid".to_owned(), json!(false));
            receipt.insert(
                "structured_capture".to_owned(),
                json!({
                    "requested": true,
                    "status": "invalid",
                    "error_code": "INVALID_STRUCTURED_OUTPUT",
                    "structural_diagnostic": structured_output_diagnostic(stdout)
                }),
            );
            atomic_write_json(&result_path, result_receipt).with_context(|| {
                "provider dispatched: write invalid structured-output receipt failed; provider outcome is known but its receipt is incomplete"
            })?;
            Err(error).context("provider dispatched: structured output contract was invalid")
        }
    }
}

fn parse_json_text(text: &str) -> Result<Value> {
    let text = text.trim();
    if let Ok(value) = serde_json::from_str(text) {
        return Ok(value);
    }
    if let Some(fenced) = text
        .strip_prefix("```json")
        .or_else(|| text.strip_prefix("```"))
        .and_then(|value| value.strip_suffix("```"))
        .map(str::trim)
        && let Ok(value) = serde_json::from_str(fenced)
    {
        return Ok(value);
    }
    for (open, close) in [('{', '}'), ('[', ']')] {
        if let (Some(start), Some(end)) = (text.find(open), text.rfind(close))
            && start < end
            && let Ok(value) = serde_json::from_str(&text[start..=end])
        {
            return Ok(value);
        }
    }
    bail!("structured host result is not JSON")
}

const STRUCTURAL_DIAGNOSTIC_MAX_LINES: usize = 16;
const STRUCTURAL_DIAGNOSTIC_MAX_KEYS: usize = 32;
const STRUCTURAL_KEY_ALLOWLIST: &[&str] = &[
    "answer",
    "answers",
    "applicability",
    "boundaries",
    "candidate",
    "candidates",
    "completion",
    "content",
    "data",
    "delta",
    "delivery_surface",
    "event",
    "final",
    "first_action",
    "influence_receipt",
    "marker",
    "memory_handle",
    "message",
    "messages",
    "output",
    "outputs",
    "parts",
    "payload",
    "purpose",
    "response",
    "result",
    "role",
    "status",
    "structured_output",
    "text",
    "type",
];

fn structured_output_diagnostic(stdout: &[u8]) -> Value {
    let whole_document = serde_json::from_slice::<Value>(stdout)
        .ok()
        .map(|value| structural_json_projection(&value));
    let line_documents = stdout
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .take(STRUCTURAL_DIAGNOSTIC_MAX_LINES)
        .map(|value| structural_json_projection(&value))
        .collect::<Vec<_>>();
    json!({
        "schema_version": "eliot-structured-output-diagnostic-v1",
        "byte_length": stdout.len(),
        "whole_document": whole_document,
        "line_documents": line_documents,
        "raw_output_retained": false
    })
}

fn structural_json_projection(value: &Value) -> Value {
    let kind = json_value_kind(value);
    let keys = value.as_object().map(|object| {
        object
            .iter()
            .take(STRUCTURAL_DIAGNOSTIC_MAX_KEYS)
            .map(|(name, nested)| {
                let retained_name = STRUCTURAL_KEY_ALLOWLIST
                    .contains(&name.as_str())
                    .then(|| name.clone());
                json!({
                    "name": retained_name,
                    "name_hash": retained_name
                        .is_none()
                        .then(|| hash_bytes(name.as_bytes())),
                    "value_kind": json_value_kind(nested)
                })
            })
            .collect::<Vec<_>>()
    });
    json!({
        "kind": kind,
        "keys": keys,
        "key_count": value.as_object().map_or(0, serde_json::Map::len)
    })
}

fn json_value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

include!("launch_support.rs");

#[allow(clippy::too_many_lines)]
/// Decides what a Claude hook event is allowed to do.
///
/// Three outcomes, and the distinction between the last two matters:
///
/// - `deny` blocks the call. A task is attached and the session is about to
///   mutate without holding a work lease, which is the one thing this gate
///   exists to stop.
/// - `recorded` allows the call and is worth persisting: a task is attached, so
///   the event is evidence about that task.
/// - `passive` allows the call and is worth nothing. No task is attached, so
///   the session is not ELIOT's business. The plugin is installed at user
///   scope and sees every project on the machine, so this is the common case.
///
/// Pulled out of the event handler so the blocking rule can be exercised
/// directly: a gate that is never tested is indistinguishable from one that
/// only records.
const fn claude_hook_decision(
    declared_event: &str,
    task_attached: bool,
    holds_work_lease: bool,
) -> &'static str {
    let mutation_gate_point = matches!(
        declared_event.as_bytes(),
        b"PreToolUse" | b"tool.execute.before"
    );
    if !task_attached {
        return "passive";
    }
    if mutation_gate_point && !holds_work_lease {
        return "deny";
    }
    "recorded"
}

fn record_event(config_path: &Path, host: AgentHostId, declared_event: &str) -> Result<Value> {
    ensure_l7_host(host)?;
    let mut raw = Vec::new();
    std::io::stdin().take(64 * 1024 + 1).read_to_end(&mut raw)?;
    let mut envelope = HostEventService.normalize(host, declared_event, &raw)?;
    envelope.task_id = env_parse("ELIOT_TASK_ID")?;
    envelope.work_item_id = env_parse("ELIOT_WORK_ITEM_ID")?;
    let lease: Option<WorkLeaseId> = env_parse("ELIOT_WORK_LEASE_ID")?;
    let decision =
        claude_hook_decision(declared_event, envelope.task_id.is_some(), lease.is_some());
    // The plugin is installed at user scope, so these hooks fire in every
    // Claude session on this machine, including projects that have nothing to
    // do with ELIOT. An unbound event describes no task and changes no ELIOT
    // state, so persisting it writes two files per tool call to record that
    // something unrelated happened. Answer and get out of the way.
    let path = if decision == "passive" {
        None
    } else {
        let event_root = runtime_root(config_path)
            .join("reports")
            .join("host-events")
            .join(host.as_str());
        let path = event_root.join(format!("{}.json", Uuid::new_v4()));
        atomic_write_json(&path, &envelope)?;
        atomic_write_json(&event_root.join("latest.json"), &envelope)?;
        Some(path)
    };
    if host == AgentHostId::Claude {
        if decision == "deny" {
            return Ok(json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "attached mutating task has no current work lease reference"
                }
            }));
        }
        if declared_event == "SessionStart" {
            return Ok(json!({
                "continue": true,
                "suppressOutput": true,
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": "For a material project task, load the matching eliot:* skill and use ELIOT project identity/current state before broad search or mutation. Skills guide; current task leases and gates authorize."
                }
            }));
        }
        return Ok(json!({
            "continue": true,
            "suppressOutput": true
        }));
    }
    Ok(json!({
        "decision": decision,
        "reason": (decision == "deny").then_some("attached mutating task has no current work lease reference"),
        "event_ref": path,
        "raw_payload_stored": false,
        "host_identity_granted_role": false
    }))
}

fn env_parse<T>(name: &str) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse()
                .map_err(|error| anyhow::anyhow!("parse {name}: {error}"))
        })
        .transpose()
}

fn parse_host(value: &str) -> Result<AgentHostId> {
    match value.trim().to_ascii_lowercase().as_str() {
        "opencode" => Ok(AgentHostId::OpenCode),
        "claude" | "claude-code" => Ok(AgentHostId::Claude),
        "codex" => Ok(AgentHostId::Codex),
        "antigravity" | "agy" => Ok(AgentHostId::Antigravity),
        other => bail!("unknown agent host: {other}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_launch_scope(
    project: Option<String>,
    agent_session: Option<String>,
    task: Option<String>,
    work_item: Option<String>,
    role_lease: Option<String>,
    work_lease: Option<String>,
    worktree_lease: Option<String>,
    planned_verifier_ref: Option<String>,
    baseline_commit: Option<String>,
    write_paths: Vec<String>,
) -> Result<HostLaunchScope> {
    Ok(HostLaunchScope {
        project_id: project
            .map(|value| ProjectId::from_str(&value).context("parse --project"))
            .transpose()?,
        agent_session_id: agent_session
            .map(|value| AgentSessionId::from_str(&value).context("parse --agent-session"))
            .transpose()?,
        task_id: task
            .map(|value| TaskId::from_str(&value).context("parse --task"))
            .transpose()?,
        work_item_id: work_item
            .map(|value| WorkItemId::from_str(&value).context("parse --work-item"))
            .transpose()?,
        role_lease_id: role_lease,
        role_lease_epoch: 0,
        operation_generation: 0,
        work_lease_id: work_lease
            .map(|value| WorkLeaseId::from_str(&value).context("parse --work-lease"))
            .transpose()?,
        worktree_lease_id: worktree_lease
            .map(|value| WorktreeLeaseId::from_str(&value).context("parse --worktree-lease"))
            .transpose()?,
        planned_verifier_ref,
        baseline_commit,
        allowed_paths: write_paths,
        forbidden_paths: Vec::new(),
    })
}

async fn bind_launch_scope(
    config_path: &Path,
    host: AgentHostId,
    cwd: Option<&Path>,
    scope: &mut HostLaunchScope,
    bounded_auditor: bool,
) -> Result<LaunchCanonicalAuthority> {
    if scope.task_id.is_none()
        && scope.role_lease_id.is_none()
        && scope.work_lease_id.is_none()
        && scope.worktree_lease_id.is_none()
    {
        scope.agent_session_id = None;
        return Ok(LaunchCanonicalAuthority::default());
    }
    let task_id = scope
        .task_id
        .context("scoped host launch requires --task")?;
    let role_lease_id = scope
        .role_lease_id
        .as_deref()
        .context("scoped host launch requires --role-lease")?;
    let state = delegation_runtime::load_state(&runtime_root(config_path))?;
    let now = OffsetDateTime::now_utc();
    let role = state
        .task_role_leases
        .iter()
        .find(|lease| {
            lease.role_lease_id == role_lease_id
                && lease.task_id == task_id
                && lease.expires_at > now
        })
        .context("no active matching TaskRoleLease")?;
    let binding = state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == role.agent_session_id)
        .context("TaskRoleLease session has no host binding")?;
    if binding.host_identity.host_id != host {
        bail!("TaskRoleLease is bound to a different agent host");
    }
    if scope
        .agent_session_id
        .is_some_and(|session| session != role.agent_session_id)
    {
        bail!("--agent-session does not match TaskRoleLease holder");
    }
    scope.agent_session_id = Some(role.agent_session_id);
    if bounded_auditor {
        let authority = validate_bounded_auditor_authority(config_path, &state, scope, now).await?;
        return Ok(LaunchCanonicalAuthority {
            managed: None,
            bounded_auditor: Some(authority),
        });
    }
    let work_state = delegation_runtime::load_work_state(&runtime_root(config_path))?;
    if let Some(work_lease_id) = scope.work_lease_id {
        let active = work_state.leases.iter().any(|lease| {
            lease.work_lease_id == work_lease_id
                && lease.task_id == task_id
                && lease.agent_session_id == role.agent_session_id
                && work_lease_is_active(lease)
        });
        if !active {
            bail!("no active matching WorkLease for scoped host launch");
        }
    }
    if host == AgentHostId::Antigravity {
        validate_antigravity_scope(&state, &work_state, cwd, scope, now)?;
        return Ok(LaunchCanonicalAuthority {
            managed: Some(
                validate_canonical_antigravity_authority(config_path, &state, &work_state, scope)
                    .await?,
            ),
            bounded_auditor: None,
        });
    }
    Ok(LaunchCanonicalAuthority::default())
}

async fn validate_bounded_auditor_authority(
    config_path: &Path,
    delegation_state: &DelegationState,
    scope: &HostLaunchScope,
    now: OffsetDateTime,
) -> Result<BoundedAuditorCanonicalAuthority> {
    let project_id = scope
        .project_id
        .context("bounded auditor launch requires --project")?;
    let task_id = scope
        .task_id
        .context("bounded auditor launch requires --task")?;
    let session_id = scope
        .agent_session_id
        .context("bounded auditor launch requires --agent-session")?;
    let role_lease_id = scope
        .role_lease_id
        .as_deref()
        .context("bounded auditor launch requires --role-lease")?;
    let role = delegation_state
        .task_role_leases
        .iter()
        .find(|role| role.role_lease_id == role_lease_id)
        .context("bounded auditor TaskRoleLease disappeared")?;
    validate_bounded_auditor_shape(role, scope, now)?;
    let binding = delegation_state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == session_id)
        .context("bounded auditor host binding disappeared")?;
    if binding.bound_project_id != Some(project_id)
        || binding.bound_task_id != Some(task_id)
        || !binding
            .task_role_lease_refs
            .iter()
            .any(|reference| reference == role_lease_id)
    {
        bail!("bounded auditor host binding is not canonically task-scoped");
    }

    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    let (task, task_receipt) = current_task_authority(&store, project_id, task_id).await?;
    let (_, role_receipt, role_authority) = current_role_authority(
        config_path,
        &store,
        delegation_state,
        project_id,
        task_id,
        role_lease_id,
        task.memory_revision.value(),
    )
    .await?;
    let host_binding_receipt =
        current_host_binding_authority(&store, project_id, task_id, binding, &role_authority)
            .await?;
    let task_receipt_ref = WriteReceiptRef {
        receipt_id: task_receipt.receipt_id,
        write_id: task_receipt.write_id,
    };
    let role_receipt_ref = WriteReceiptRef {
        receipt_id: role_receipt.receipt_id,
        write_id: role_receipt.write_id,
    };
    let host_binding_receipt_ref = WriteReceiptRef {
        receipt_id: host_binding_receipt.receipt_id,
        write_id: host_binding_receipt.write_id,
    };
    let authority_hash = hash_json(&json!({
        "authority_kind": "bounded_auditor",
        "project_id": project_id,
        "task_id": task_id,
        "session_id": session_id,
        "role_lease_id": role_lease_id,
        "task_receipt": task_receipt_ref,
        "role_receipt": role_receipt_ref,
        "host_binding_receipt": host_binding_receipt_ref,
        "work_authority": Value::Null,
    }))?;
    Ok(BoundedAuditorCanonicalAuthority {
        task_receipt: task_receipt_ref,
        role_receipt: role_receipt_ref,
        host_binding_receipt: host_binding_receipt_ref,
        authority_hash,
    })
}

fn validate_bounded_auditor_shape(
    role: &eliot_types::TaskRoleLease,
    scope: &HostLaunchScope,
    now: OffsetDateTime,
) -> Result<()> {
    let task_id = scope
        .task_id
        .context("bounded auditor launch requires --task")?;
    let session_id = scope
        .agent_session_id
        .context("bounded auditor launch requires --agent-session")?;
    if role.task_id != task_id
        || role.agent_session_id != session_id
        || role.role != AgentRole::Auditor
        || role.expires_at <= now
        || scope.work_item_id.is_some()
        || scope.work_lease_id.is_some()
        || scope.worktree_lease_id.is_some()
        || scope.planned_verifier_ref.is_some()
        || !scope.allowed_paths.is_empty()
    {
        bail!("bounded auditor scope must be active, read-only, and free of work authority");
    }
    Ok(())
}

fn validate_antigravity_scope(
    delegation_state: &DelegationState,
    work_state: &WorkState,
    cwd: Option<&Path>,
    scope: &mut HostLaunchScope,
    now: OffsetDateTime,
) -> Result<()> {
    let project_id = scope
        .project_id
        .context("governed Antigravity launch requires --project")?;
    let task_id = scope
        .task_id
        .context("governed Antigravity launch requires --task")?;
    let work_item_id = scope
        .work_item_id
        .context("governed Antigravity launch requires --work-item")?;
    let agent_session_id = scope
        .agent_session_id
        .context("governed Antigravity launch requires --agent-session")?;
    let role_lease_id = scope
        .role_lease_id
        .as_deref()
        .context("governed Antigravity launch requires --role-lease")?;
    let work_lease_id = scope
        .work_lease_id
        .context("governed Antigravity launch requires --work-lease")?;
    let worktree_lease_id = scope
        .worktree_lease_id
        .context("governed Antigravity launch requires --worktree-lease")?;
    let cwd = cwd.context("governed Antigravity launch requires --cwd")?;
    let planned_verifier_ref = scope
        .planned_verifier_ref
        .as_deref()
        .context("governed Antigravity launch requires --planned-verifier-ref")?;
    crate::mcp_stdio::RegisteredTaskVerifier::from_reference(planned_verifier_ref)
        .context("governed Antigravity planned verifier reference is unregistered or stale")?;

    let role = delegation_state
        .task_role_leases
        .iter()
        .find(|lease| lease.role_lease_id == role_lease_id)
        .context("governed Antigravity TaskRoleLease was not found")?;
    if role.task_id != task_id
        || role.agent_session_id != agent_session_id
        || role.expires_at <= now
        || role.role == AgentRole::Controller
    {
        bail!("governed Antigravity TaskRoleLease is expired or scope-mismatched");
    }

    let work = work_state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == work_lease_id)
        .context("governed Antigravity WorkLease was not found")?;
    if !work_lease_is_active(work)
        || work.project_id != project_id
        || work.task_id != task_id
        || work.work_item_id != work_item_id
        || work.agent_session_id != agent_session_id
    {
        bail!("governed Antigravity WorkLease is expired or scope-mismatched");
    }

    let worktree = work_state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .context("governed Antigravity WorktreeLease was not found")?;
    if worktree.state != WorktreeLeaseState::Active
        || worktree.expires_at <= now
        || worktree.project_id != project_id
        || worktree.task_id != task_id
        || worktree.work_item_id != work_item_id
        || worktree.work_lease_id != work_lease_id
        || worktree.holder_session_id != agent_session_id
    {
        bail!("governed Antigravity WorktreeLease is expired or scope-mismatched");
    }
    let requested_cwd = cwd
        .canonicalize()
        .context("canonicalize governed Antigravity --cwd")?;
    let canonical_worktree = PathBuf::from(&worktree.worktree_path)
        .canonicalize()
        .context("canonicalize governed Antigravity WorktreeLease path")?;
    if requested_cwd != canonical_worktree {
        bail!("--cwd must equal the canonical WorktreeLease path");
    }
    assert_managed_path_is_local_and_private(&canonical_worktree)?;
    let actual_head = git_text(&canonical_worktree, &["rev-parse", "HEAD"])?;
    if actual_head != worktree.base_commit {
        bail!("current worktree HEAD does not match the canonical WorktreeLease baseline");
    }
    scope.baseline_commit = Some(actual_head);

    let requested_write = normalize_write_set(&scope.allowed_paths)?;
    let canonical_write = normalize_write_set(&worktree.allowed_write_set)?;
    if requested_write.is_empty() || requested_write != canonical_write {
        bail!("--write-path set must exactly match the canonical WorktreeLease write set");
    }
    if requested_write
        .iter()
        .any(|path| !path_in_scope(path, &work.scope.write_set))
    {
        bail!("governed Antigravity write set escapes the active WorkLease");
    }
    scope.allowed_paths = requested_write.into_iter().collect();
    Ok(())
}

fn hash_json(value: &Value) -> Result<String> {
    Ok(format!(
        "blake3:{}",
        blake3::hash(&serde_json::to_vec(value)?).to_hex()
    ))
}

fn receipt_ref_from_option(
    value: Option<&WriteReceiptRef>,
    authority: &str,
) -> Result<WriteReceiptRef> {
    value
        .cloned()
        .with_context(|| format!("{authority} lacks a canonical WriteReceipt"))
}

async fn resolve_canonical_receipt(
    store: &CanonicalStore,
    reference: &WriteReceiptRef,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    authority: &str,
) -> Result<WriteReceipt> {
    let receipt = store
        .write_receipt_by_id(&reference.write_id)
        .await?
        .with_context(|| format!("{authority} WriteReceipt does not resolve canonically"))?;
    if receipt.receipt_id != reference.receipt_id
        || receipt.write_id != reference.write_id
        || receipt.project_id != project_id
        || task_id.is_some_and(|expected| receipt.task_id != Some(expected))
        || receipt.status != WriteStatus::Committed
        || receipt.memory_revision.is_none()
        || receipt.project_sequence.is_none()
        || receipt.rejected_reason.is_some()
    {
        bail!("{authority} canonical WriteReceipt is stale, rejected, or scope-mismatched");
    }
    Ok(receipt)
}

fn body_without_local_receipt<T: Serialize>(value: &T) -> Result<Value> {
    let mut body = serde_json::to_value(value)?;
    if let Some(object) = body.as_object_mut()
        && object.contains_key("write_receipt")
    {
        object.insert("write_receipt".to_owned(), Value::Null);
    }
    Ok(body)
}

fn json_difference_paths(expected: &Value, observed: &Value) -> Vec<String> {
    fn collect(expected: &Value, observed: &Value, path: &str, output: &mut Vec<String>) {
        match (expected, observed) {
            (Value::Object(expected), Value::Object(observed)) => {
                let keys = expected
                    .keys()
                    .chain(observed.keys())
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                for key in keys {
                    let child = if path.is_empty() {
                        key.to_owned()
                    } else {
                        format!("{path}.{key}")
                    };
                    match (expected.get(key), observed.get(key)) {
                        (Some(expected), Some(observed)) => {
                            collect(expected, observed, &child, output);
                        }
                        _ => output.push(child),
                    }
                }
            }
            (Value::Array(expected), Value::Array(observed)) => {
                let length = expected.len().max(observed.len());
                for index in 0..length {
                    let child = format!("{path}[{index}]");
                    match (expected.get(index), observed.get(index)) {
                        (Some(expected), Some(observed)) => {
                            collect(expected, observed, &child, output);
                        }
                        _ => output.push(child),
                    }
                }
            }
            _ if expected != observed => output.push(path.to_owned()),
            _ => {}
        }
    }

    let mut output = Vec::new();
    collect(expected, observed, "", &mut output);
    output
}

fn normalize_authority_json(
    value: &Value,
    normalization: CanonicalBodyNormalization,
) -> Result<Value> {
    let CanonicalBodyNormalization::Rfc3339Fields(fields) = normalization else {
        return Ok(value.clone());
    };
    let mut normalized = value.clone();
    let object = normalized
        .as_object_mut()
        .context("timestamp-normalized canonical authority body must be an object")?;
    for field in fields {
        let mut value = &mut *object;
        let mut segments = field.split('.').peekable();
        let leaf = loop {
            let segment = segments
                .next()
                .with_context(|| format!("canonical authority timestamp path {field} is empty"))?;
            let child = value.get_mut(segment).with_context(|| {
                format!("canonical authority body lacks timestamp field {field}")
            })?;
            if segments.peek().is_none() {
                break child;
            }
            value = child.as_object_mut().with_context(|| {
                format!("canonical authority timestamp parent for {field} is not an object")
            })?;
        };
        let value = leaf;
        if value.is_null() {
            continue;
        }
        let raw = value
            .as_str()
            .with_context(|| format!("canonical authority timestamp {field} is not a string"))?;
        let timestamp = OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
            .with_context(|| format!("canonical authority timestamp {field} is not RFC3339"))?;
        *value = Value::String(timestamp.unix_timestamp_nanos().to_string());
    }
    Ok(normalized)
}

fn validate_canonical_observation_identity(
    observation: &CanonicalToolObservation,
    receipt: &WriteReceipt,
    project_id: ProjectId,
    expected: &CanonicalAuthorityBody<'_>,
) -> Result<()> {
    let created_identity = receipt
        .created_records
        .iter()
        .any(|record| record == &observation.observation_id);
    let observed_body = observation.payload.get(expected.payload_key);
    let normalized_observed_body = if expected
        .body
        .get("write_receipt")
        .is_some_and(Value::is_null)
    {
        observed_body.map(body_without_local_receipt).transpose()?
    } else {
        observed_body.cloned()
    };
    let normalized_expected_body = normalize_authority_json(expected.body, expected.normalization)?;
    let normalized_observed_body = normalized_observed_body
        .as_ref()
        .map(|body| normalize_authority_json(body, expected.normalization))
        .transpose()?;
    let body_matches = normalized_observed_body.as_ref() == Some(&normalized_expected_body);
    let expected_revision = receipt.memory_revision.context("missing revision")?;
    let expected_sequence = receipt.project_sequence.context("missing sequence")?;
    let mut differences = Vec::new();
    if receipt.command_kind != SemanticCommandKind::ToolObservationRecord {
        differences.push("command_kind".to_owned());
    }
    if observation.observation_id != receipt.write_id.to_string() {
        differences.push("observation_id".to_owned());
    }
    if observation.write_id != receipt.write_id {
        differences.push("write_id".to_owned());
    }
    if observation.project_id != project_id {
        differences.push("project_id".to_owned());
    }
    if observation.task_id != expected.task_id {
        differences.push("task_id".to_owned());
    }
    if observation.memory_revision != expected_revision {
        differences.push("memory_revision".to_owned());
    }
    if observation.project_sequence != expected_sequence {
        differences.push("project_sequence".to_owned());
    }
    if observation.scope != expected.scope {
        differences.push("scope".to_owned());
    }
    if observation.authority != expected.authority {
        differences.push("authority".to_owned());
    }
    if observation.tool_name != expected.tool_name {
        differences.push("tool_name".to_owned());
    }
    if !created_identity {
        differences.push("created_record_identity".to_owned());
    }
    if !body_matches {
        let observed_hash = normalized_observed_body
            .as_ref()
            .map(hash_json)
            .transpose()?
            .unwrap_or_else(|| "missing".to_owned());
        let body_paths = normalized_observed_body.as_ref().map_or_else(
            || "missing".to_owned(),
            |observed| json_difference_paths(&normalized_expected_body, observed).join("|"),
        );
        differences.push(format!(
            "body(paths={body_paths},expected_hash={},observed_hash={observed_hash})",
            hash_json(&normalized_expected_body)?
        ));
    }
    if !differences.is_empty() {
        bail!(
            "{} canonical observation identity differs: {}",
            expected.label,
            differences.join(",")
        );
    }
    Ok(())
}

async fn resolve_latest_canonical_authority_body(
    store: &CanonicalStore,
    reference: &WriteReceiptRef,
    project_id: ProjectId,
    entity_kind: &str,
    entity_ref: &str,
    expected: CanonicalAuthorityBody<'_>,
) -> Result<WriteReceipt> {
    let observations = store
        .latest_authority_observations_by_entity(
            project_id,
            expected.task_id,
            entity_kind,
            entity_ref,
        )
        .await?;
    let latest = latest_canonical_authority_observation(&observations, reference, expected.label)?;
    let receipt = resolve_canonical_receipt(
        store,
        reference,
        project_id,
        expected.task_id,
        expected.label,
    )
    .await?;
    validate_canonical_observation_identity(latest, &receipt, project_id, &expected)?;
    Ok(receipt)
}

fn latest_canonical_authority_observation<'a>(
    observations: &'a [CanonicalToolObservation],
    reference: &WriteReceiptRef,
    label: &str,
) -> Result<&'a CanonicalToolObservation> {
    let latest = observations
        .first()
        .with_context(|| format!("{label} has no current canonical entity record"))?;
    if observations.get(1).is_some_and(|prior| {
        prior.memory_revision == latest.memory_revision
            && prior.project_sequence == latest.project_sequence
    }) {
        bail!("{label} current canonical entity record is ambiguous");
    }
    if latest.write_id != reference.write_id {
        bail!("{label} local projection is older than the current canonical entity record");
    }
    Ok(latest)
}

async fn current_task_authority(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<(TaskContract, WriteReceipt)> {
    let task = store
        .task_contract_by_id(task_id)
        .await?
        .context("managed Antigravity requires a current canonical TaskContract")?;
    if task.project_id != project_id || task.status != TaskContractStatus::Open {
        bail!("managed Antigravity requires the open current TaskContract in the exact project");
    }
    let receipt = store
        .write_receipt_by_id(&task.write_id)
        .await?
        .context("TaskContract canonical WriteReceipt does not resolve")?;
    if receipt.project_id != project_id
        || receipt.task_id != Some(task_id)
        || receipt.command_kind != SemanticCommandKind::TaskContractWrite
        || receipt.status != WriteStatus::Committed
        || receipt.memory_revision != Some(task.memory_revision)
        || !receipt
            .created_records
            .iter()
            .any(|record| record == &task_id.to_string())
        || receipt.rejected_reason.is_some()
    {
        bail!("TaskContract canonical WriteReceipt is stale, rejected, or scope-mismatched");
    }
    Ok((task, receipt))
}

async fn current_session_authority(
    store: &CanonicalStore,
    work_state: &WorkState,
    project_id: ProjectId,
    session_id: AgentSessionId,
) -> Result<WriteReceipt> {
    let session = work_state
        .sessions
        .iter()
        .find(|session| session.agent_session_id == session_id)
        .context("managed Antigravity AgentSession is absent from the current work projection")?;
    if session.project_id != project_id
        || !matches!(
            session.status,
            AgentSessionStatus::Active | AgentSessionStatus::Idle
        )
    {
        bail!("managed Antigravity AgentSession is inactive or project-mismatched");
    }
    let reference = receipt_ref_from_option(session.write_receipt.as_ref(), "AgentSession")?;
    let body = body_without_local_receipt(session)?;
    resolve_latest_canonical_authority_body(
        store,
        &reference,
        project_id,
        "agent_session",
        &session_id.to_string(),
        CanonicalAuthorityBody {
            label: "AgentSession",
            task_id: None,
            scope: "work/agent-session",
            authority: "eliot-work-coordination-service",
            tool_name: "eliot_work_coordination",
            payload_key: "agent_session",
            body: &body,
            normalization: CanonicalBodyNormalization::Rfc3339Fields(&[
                "started_at",
                "last_heartbeat_at",
                "stopped_at",
            ]),
        },
    )
    .await
}

async fn current_role_authority(
    config_path: &Path,
    store: &CanonicalStore,
    delegation_state: &DelegationState,
    project_id: ProjectId,
    task_id: TaskId,
    role_lease_id: &str,
    task_revision: u64,
) -> Result<(u64, WriteReceipt, RoleLeaseAuthorityRecord)> {
    let role = delegation_state
        .task_role_leases
        .iter()
        .find(|role| role.role_lease_id == role_lease_id)
        .context("managed Antigravity TaskRoleLease disappeared")?;
    let role_value = serde_json::to_value(role)?;
    let authority: RoleLeaseAuthorityRecord =
        serde_json::from_reader(File::open(role_authority_path(config_path, role_lease_id))?)?;
    if authority.role_lease_id != role_lease_id
        || authority.lease_hash != hash_json(&role_value)?
        || authority.task_revision != task_revision
    {
        bail!("TaskRoleLease canonical authority is stale or tampered");
    }
    let receipt = resolve_latest_canonical_authority_body(
        store,
        &authority.canonical_receipt,
        project_id,
        "task_role_lease",
        role_lease_id,
        CanonicalAuthorityBody {
            label: "TaskRoleLease",
            task_id: Some(task_id),
            scope: "governed host authority",
            authority: "canonical Eliot host boundary",
            tool_name: "eliot-governor-host",
            payload_key: "receipt_body",
            body: &role_value,
            normalization: CanonicalBodyNormalization::Rfc3339Fields(&["expires_at"]),
        },
    )
    .await?;
    Ok((role.epoch, receipt, authority))
}

async fn current_host_binding_authority(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: TaskId,
    binding: &AgentSessionHostBinding,
    authority: &RoleLeaseAuthorityRecord,
) -> Result<WriteReceipt> {
    let body = serde_json::to_value(binding)?;
    if hash_json(&body)? != authority.host_binding_hash {
        bail!("AgentSessionHostBinding local body differs from canonical authority");
    }
    resolve_latest_canonical_authority_body(
        store,
        &authority.canonical_host_binding_receipt,
        project_id,
        "host_binding",
        &binding.agent_session_id.to_string(),
        CanonicalAuthorityBody {
            label: "AgentSessionHostBinding",
            task_id: Some(task_id),
            scope: "governed host authority",
            authority: "canonical Eliot host boundary",
            tool_name: "eliot-governor-host",
            payload_key: "receipt_body",
            body: &body,
            normalization: CanonicalBodyNormalization::Exact,
        },
    )
    .await
}

async fn current_work_authority(
    store: &CanonicalStore,
    work_state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
    work_lease_id: WorkLeaseId,
    worktree_lease_id: WorktreeLeaseId,
) -> Result<ManagedWorkAuthority> {
    let work_lease = work_state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == work_lease_id)
        .cloned()
        .context("managed Antigravity WorkLease disappeared")?;
    let work_reference = receipt_ref_from_option(work_lease.write_receipt.as_ref(), "WorkLease")?;
    let work_body = body_without_local_receipt(&work_lease)?;
    let work_receipt = resolve_latest_canonical_authority_body(
        store,
        &work_reference,
        project_id,
        "work_lease",
        &work_lease_id.to_string(),
        CanonicalAuthorityBody {
            label: "WorkLease",
            task_id: Some(task_id),
            scope: "work/work-lease",
            authority: "eliot-work-coordination-service",
            tool_name: "eliot_work_coordination",
            payload_key: "work_lease",
            body: &work_body,
            normalization: CanonicalBodyNormalization::Rfc3339Fields(&[
                "decision.expires_at",
                "granted_at",
                "expires_at",
                "renewed_at",
                "released_at",
                "revoked_at",
            ]),
        },
    )
    .await?;
    let worktree_lease = work_state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .cloned()
        .context("managed Antigravity WorktreeLease disappeared")?;
    let worktree_reference =
        receipt_ref_from_option(worktree_lease.write_receipt.as_ref(), "WorktreeLease")?;
    let worktree_body = body_without_local_receipt(&worktree_lease)?;
    let worktree_receipt = resolve_latest_canonical_authority_body(
        store,
        &worktree_reference,
        project_id,
        "worktree_lease",
        &worktree_lease_id.to_string(),
        CanonicalAuthorityBody {
            label: "WorktreeLease",
            task_id: Some(task_id),
            scope: "worktree-lease",
            authority: "local-worktree-governor",
            tool_name: "eliot_worktree_governor",
            payload_key: "worktree_lease",
            body: &worktree_body,
            normalization: CanonicalBodyNormalization::Rfc3339Fields(&[
                "issued_at",
                "expires_at",
                "cleaned_at",
            ]),
        },
    )
    .await?;
    Ok(ManagedWorkAuthority {
        work_lease,
        work_receipt,
        worktree_lease,
        worktree_receipt,
    })
}

async fn validate_canonical_antigravity_authority(
    config_path: &Path,
    delegation_state: &DelegationState,
    work_state: &WorkState,
    scope: &HostLaunchScope,
) -> Result<ManagedCanonicalAuthority> {
    let project_id = scope
        .project_id
        .context("missing canonical project scope")?;
    let task_id = scope.task_id.context("missing canonical task scope")?;
    let session_id = scope
        .agent_session_id
        .context("missing canonical session scope")?;
    let role_lease_id = scope
        .role_lease_id
        .as_deref()
        .context("missing canonical role scope")?;
    let work_lease_id = scope
        .work_lease_id
        .context("missing canonical work scope")?;
    let worktree_lease_id = scope
        .worktree_lease_id
        .context("missing canonical worktree scope")?;
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    let (task, task_receipt) = current_task_authority(&store, project_id, task_id).await?;
    let session_receipt =
        current_session_authority(&store, work_state, project_id, session_id).await?;
    let (role_epoch, role_receipt, role_authority) = current_role_authority(
        config_path,
        &store,
        delegation_state,
        project_id,
        task_id,
        role_lease_id,
        task.memory_revision.value(),
    )
    .await?;
    let work = current_work_authority(
        &store,
        work_state,
        project_id,
        task_id,
        work_lease_id,
        worktree_lease_id,
    )
    .await?;
    let host_binding = delegation_state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == session_id)
        .cloned()
        .context("managed Antigravity host binding disappeared")?;
    let host_binding_receipt =
        current_host_binding_authority(&store, project_id, task_id, &host_binding, &role_authority)
            .await?;
    let authority_material = json!({
        "task_revision": task.memory_revision,
        "task_receipt": task_receipt,
        "session_receipt": session_receipt,
        "role_receipt": role_receipt,
        "host_binding_receipt": host_binding_receipt,
        "work_receipt": work.work_receipt,
        "worktree_receipt": work.worktree_receipt,
        "role_epoch": role_epoch,
        "work_epoch": work.work_lease.epoch,
        "worktree_baseline": work.worktree_lease.base_commit,
        "planned_verifier_ref": scope.planned_verifier_ref,
    });
    Ok(ManagedCanonicalAuthority {
        task_receipt,
        session_receipt,
        role_receipt,
        host_binding_receipt,
        work_receipt: work.work_receipt,
        worktree_receipt: work.worktree_receipt,
        work_lease: work.work_lease,
        worktree_lease: work.worktree_lease,
        host_binding,
        authority_hash: hash_json(&authority_material)?,
    })
}

fn normalize_write_set(paths: &[String]) -> Result<BTreeSet<String>> {
    paths
        .iter()
        .map(|path| normalize_relative_path(path))
        .collect()
}

fn normalize_relative_path(value: &str) -> Result<String> {
    let path = Path::new(value.trim());
    if value.trim().is_empty() || path.is_absolute() {
        bail!("write paths must be non-empty relative paths");
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("write path escapes the governed worktree: {value}");
            }
        }
    }
    if parts.is_empty() {
        bail!("write paths must not resolve to the worktree root");
    }
    Ok(parts.join("/"))
}

fn path_is_within(child: &Path, parent: &Path) -> Result<bool> {
    let normalize = |path: &Path| -> Result<String> {
        let absolute = std::path::absolute(path)?;
        Ok(absolute
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .trim_end_matches(['\\', '/'])
            .replace('/', "\\")
            .to_ascii_lowercase())
    };
    let child = normalize(child)?;
    let parent = normalize(parent)?;
    Ok(child == parent || child.starts_with(&format!("{parent}\\")))
}

fn assert_managed_path_is_local_and_private(path: &Path) -> Result<()> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is required for managed Antigravity isolation")?;
    let owned = local.join("Eliot");
    if !path_is_within(path, &owned)? {
        bail!("managed Antigravity worktrees must be caller-owned under LocalAppData/Eliot");
    }
    for forbidden in [
        std::env::var_os("OneDrive").map(PathBuf::from),
        std::env::var_os("OneDriveCommercial").map(PathBuf::from),
        std::env::var_os("ProgramData").map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    {
        if path_is_within(path, &forbidden)? {
            bail!("managed Antigravity path is inside forbidden global or OneDrive state");
        }
    }
    Ok(())
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = StdCommand::new("git")
        .current_dir(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        bail!(
            "git {:?} failed in {}: {}",
            args,
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_bytes(root, args)?)?.trim().to_owned())
}

fn register_session(
    config_path: &Path,
    host: AgentHostId,
    session: Option<String>,
    client_instance: Option<String>,
) -> Result<Value> {
    let session = session
        .map(|value| AgentSessionId::from_str(&value).context("parse --session"))
        .transpose()?
        .unwrap_or_else(AgentSessionId::new_v7);
    let (implementation_name, capability_envelope) = if host == AgentHostId::Codex {
        (
            "OpenAI Codex (in-process primary host)".to_owned(),
            AgentCapabilityEnvelope {
                capabilities: vec![
                    "delegate".to_owned(),
                    "review".to_owned(),
                    "verify".to_owned(),
                    "controller".to_owned(),
                ],
                structured_output: true,
                resumable: true,
                interactive: true,
                supervised: true,
            },
        )
    } else {
        let profile = HostProfileService.probe(host)?;
        (
            profile.implementation_name,
            AgentCapabilityEnvelope {
                capabilities: profile.launch_capabilities,
                structured_output: profile.protocol_surfaces.structured_output,
                resumable: profile.supported_modes.iter().any(|mode| mode == "resume"),
                interactive: profile
                    .supported_modes
                    .iter()
                    .any(|mode| mode == "interactive_client"),
                supervised: profile
                    .supported_modes
                    .iter()
                    .any(|mode| mode == "supervised_noninteractive"),
            },
        )
    };
    let mut state = delegation_runtime::load_state(&runtime_root(config_path))?;
    let binding = HostBrokerService.register_session(
        &mut state,
        session,
        host,
        implementation_name,
        client_instance.unwrap_or_else(|| session.to_string()),
        capability_envelope,
    )?;
    delegation_runtime::save_host_broker_state(&runtime_root(config_path), &state)?;
    Ok(json!({
        "schema_version": "eliot-host-session-registration-v1",
        "binding": binding,
        "host_identity_granted_role": false
    }))
}

fn deterministic_host_write_id(key: &str) -> WriteId {
    let digest = blake3::hash(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(Uuid::from_bytes(bytes))
}

fn role_authority_path(config_path: &Path, role_lease_id: &str) -> PathBuf {
    role_authority_path_from_root(&runtime_root(config_path), role_lease_id)
}

fn role_authority_path_from_root(root: &Path, role_lease_id: &str) -> PathBuf {
    root.join("reports")
        .join("role-lease-authority")
        .join(format!(
            "{}.json",
            blake3::hash(role_lease_id.as_bytes()).to_hex()
        ))
}

async fn write_canonical_host_observation(
    config_path: &Path,
    project_id: ProjectId,
    task_id: TaskId,
    agent_session_id: AgentSessionId,
    key: &str,
    receipt_kind: &str,
    body: &Value,
) -> Result<(WriteReceiptRef, WriteReceipt)> {
    let response = named_pipe_ipc::host_governor_request(
        &host_governor_instance(config_path)?,
        "host/observation-record",
        json!({
            "project_id": project_id,
            "task_id": task_id,
            "agent_session_id": agent_session_id,
            "key": key,
            "receipt_kind": receipt_kind,
            "body": body,
        }),
    )
    .await
    .with_context(|| {
        format!(
            "route managed host observation through the daemon-owned WriterActor: receipt_kind={receipt_kind} key={key}"
        )
    })?;
    let output: HostObservationOutput =
        serde_json::from_value(response).context("decode private host observation receipt")?;
    Ok((output.canonical_receipt, output.write_receipt))
}

async fn write_canonical_host_observation_with_writer(
    writer: &WriterHandle,
    project_id: ProjectId,
    task_id: TaskId,
    agent_session_id: AgentSessionId,
    key: &str,
    receipt_kind: &str,
    body: &Value,
) -> Result<(WriteReceiptRef, WriteReceipt)> {
    let write_id = deterministic_host_write_id(key);
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(agent_session_id.as_uuid()),
            session_id: Some(SessionId::from_uuid(agent_session_id.as_uuid())),
            project_id,
            task_id: Some(task_id),
            scope: "governed host authority".to_owned(),
            authority: "canonical Eliot host boundary".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot-governor-host".to_owned(),
        observation: format!("canonical {receipt_kind}"),
        payload: json!({
            "receipt_kind": receipt_kind,
            "body_hash": hash_json(body)?,
            "receipt_body": body,
        }),
    });
    let receipt = writer
        .submit(WriteAdmissionService.admit(&command)?)
        .await?;
    let reference = WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    };
    Ok((reference, receipt))
}

async fn grant_role(
    config_path: &Path,
    task: &str,
    session: &str,
    role: &str,
    capability: Vec<String>,
    ttl_minutes: i64,
) -> Result<Value> {
    let instance = host_governor_instance(config_path)?;
    named_pipe_ipc::host_governor_request(
        &instance,
        "host/role-grant",
        json!({
            "task": task,
            "session": session,
            "role": role,
            "capability": capability,
            "ttl_minutes": ttl_minutes,
        }),
    )
    .await
    .context("route host role grant through the daemon-owned WriterActor")
}

pub(crate) fn host_governor_instance(config_path: &Path) -> Result<RuntimeInstance> {
    let default_instance = RuntimeInstance::select(config_path, Some(DEFAULT_INSTANCE_NAME))?;
    let default_matches_config = default_instance
        .read_publication(named_pipe_ipc::IPC_PROTOCOL_VERSION)
        .is_ok_and(|publication| {
            path_identity(&publication.config_path) == path_identity(config_path)
        });
    if default_matches_config {
        Ok(default_instance)
    } else {
        RuntimeInstance::select(config_path, None)
    }
}

pub(crate) async fn grant_role_from_daemon(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    params: Value,
) -> Result<Value> {
    let input: HostRoleGrantInput =
        serde_json::from_value(params).context("decode private host role grant RPC")?;
    store.migrate_schema().await?;
    grant_role_with_writer(root, store, writer, input).await
}

pub(crate) async fn open_operation_scope_from_daemon(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    params: Value,
) -> Result<Value> {
    let input: OperationAuthorityOpenRequest =
        serde_json::from_value(params).context("decode private operation scope open RPC")?;
    store.migrate_schema().await?;
    let receipt = open_operation_scope_with_writer(root, store, writer, input).await?;
    Ok(serde_json::to_value(receipt)?)
}

pub(crate) async fn close_operation_scope_from_daemon(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    params: Value,
) -> Result<Value> {
    let input: OperationAuthorityCloseRequest =
        serde_json::from_value(params).context("decode private operation scope close RPC")?;
    store.migrate_schema().await?;
    let receipt = close_operation_scope_with_writer(root, store, writer, input).await?;
    Ok(serde_json::to_value(receipt)?)
}

fn deterministic_operation_role_lease_id(operation_id: &str) -> String {
    format!(
        "operation-role-lease:{}",
        blake3::hash(operation_id.as_bytes()).to_hex()
    )
}

fn operation_launch_scope(
    input: &OperationAuthorityOpenRequest,
    role_lease_id: String,
    role_lease_epoch: u64,
) -> HostLaunchScope {
    HostLaunchScope {
        project_id: Some(input.project_id),
        agent_session_id: Some(input.agent_session_id),
        task_id: Some(input.task_id),
        work_item_id: None,
        role_lease_id: Some(role_lease_id),
        role_lease_epoch,
        operation_generation: input.generation,
        work_lease_id: None,
        worktree_lease_id: None,
        planned_verifier_ref: None,
        baseline_commit: None,
        allowed_paths: Vec::new(),
        forbidden_paths: vec![
            "global-provider-config".to_owned(),
            "truth-promotion".to_owned(),
        ],
    }
}

fn load_role_authority_record(root: &Path, role_lease_id: &str) -> Result<RoleLeaseAuthorityRecord> {
    let path = role_authority_path_from_root(root, role_lease_id);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read role authority projection {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("decode role authority projection {}", path.display()))
}

fn validate_operation_open(input: &OperationAuthorityOpenRequest) -> Result<()> {
    ensure!(
        input.schema_version == OPERATION_AUTHORITY_SCHEMA_VERSION,
        "unsupported operation authority schema"
    );
    ensure!(
        !input.operation_id.trim().is_empty()
            && !input.client_instance_id.trim().is_empty()
            && !input.idempotency_key.trim().is_empty(),
        "operation authority identity fields must be nonempty"
    );
    ensure!(input.generation > 0, "operation generation must be nonzero");
    ensure!(
        (1..=30 * 60).contains(&input.ttl_seconds),
        "operation authority TTL must be between 1 and 1800 seconds"
    );
    if input.purpose == ExternalAgentPurpose::McpPreflight {
        ensure!(
            input.ttl_seconds <= 5 * 60,
            "MCP preflight authority TTL exceeds five minutes"
        );
    }
    ensure!(
        input.role != AgentRole::Controller,
        "one-shot external operation cannot acquire Controller authority"
    );
    ensure!(
        !input.capability_scope.is_empty()
            && input
                .capability_scope
                .iter()
                .all(|capability| !capability.trim().is_empty()),
        "operation authority requires a nonempty capability scope"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn open_operation_scope_with_writer(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    input: OperationAuthorityOpenRequest,
) -> Result<OperationAuthorityOpenReceipt> {
    validate_operation_open(&input)?;
    let task = store
        .task_contract_by_id(input.task_id)
        .await?
        .context("operation authority requires a current canonical TaskContract")?;
    ensure!(
        task.status == TaskContractStatus::Open && task.project_id == input.project_id,
        "operation authority requires an open TaskContract in the exact project"
    );
    let role_lease_id = deterministic_operation_role_lease_id(&input.operation_id);
    let state = delegation_runtime::load_state(root)?;
    if let Some(job) = state
        .operation_jobs
        .iter()
        .find(|job| job.job_id == input.operation_id || job.invocation_id == input.operation_id)
    {
        ensure!(
            job.job_id == input.operation_id
                && job.invocation_id == input.operation_id
                && job.host_id == input.host
                && job.generation == input.generation
                && job.idempotency_key == input.idempotency_key
                && job.role_lease_id.as_deref() == Some(role_lease_id.as_str()),
            "operation scope open replay conflicts with its existing owner"
        );
        let lease = state
            .task_role_leases
            .iter()
            .find(|lease| lease.role_lease_id == role_lease_id)
            .context("operation scope replay has no role lease")?;
        ensure!(
            lease.state == AuthorityLeaseState::Active
                && lease.lifetime == AuthorityLeaseLifetime::OperationBound
                && lease.owner_operation_id.as_deref() == Some(input.operation_id.as_str())
                && lease.generation == input.generation,
            "operation scope replay has no current operation-bound authority"
        );
        let authority = load_role_authority_record(root, &role_lease_id)?;
        return Ok(OperationAuthorityOpenReceipt {
            operation_id: input.operation_id.clone(),
            purpose: input.purpose,
            generation: input.generation,
            launch_scope: operation_launch_scope(&input, role_lease_id, lease.epoch),
            operation_job_id: job.job_id.clone(),
            role_authority_receipt: authority.canonical_receipt,
            host_binding_authority_receipt: authority.canonical_host_binding_receipt,
            operation_job_authority_receipt: authority
                .canonical_operation_job_receipt
                .context("operation scope replay has no canonical job receipt")?,
            state_hash: hash_json(&serde_json::to_value(&state)?)?,
            idempotent_replay: true,
            opened_at: authority.opened_at.context("operation scope replay has no open time")?,
        });
    }
    ensure!(
        !state.operation_jobs.iter().any(|job| {
            job.idempotency_key == input.idempotency_key
                || (job.host_id == input.host
                    && job.generation == input.generation
                    && matches!(job.state, OperationJobState::Queued | OperationJobState::Running))
        }),
        "operation scope conflicts with an active owner or idempotency key"
    );
    ensure!(
        !state.task_role_leases.iter().any(|lease| {
            lease.agent_session_id == input.agent_session_id
                && lease.state == AuthorityLeaseState::Active
        }),
        "operation session already owns active authority"
    );

    let now = OffsetDateTime::now_utc();
    let mut owner_shell = state;
    let binding = HostBrokerService.register_session_generation(
        &mut owner_shell,
        input.agent_session_id,
        input.host,
        input.host.as_str().to_owned(),
        input.client_instance_id.clone(),
        AgentCapabilityEnvelope {
            capabilities: input.capability_scope.clone(),
            structured_output: true,
            resumable: true,
            interactive: false,
            supervised: true,
        },
        input.generation,
        Some(input.operation_id.clone()),
    )?;
    HostBrokerService.bind_session_scope(
        &mut owner_shell,
        binding.agent_session_id,
        input.project_id,
        input.task_id,
    )?;
    let mut grant = HostBrokerService.prepare_role_grant(
        &owner_shell,
        input.task_id,
        input.agent_session_id,
        input.role,
        input.capability_scope.clone(),
        i64::try_from(input.ttl_seconds.div_ceil(60))?,
        Some(input.operation_id.clone()),
    )?;
    grant.role_lease_id.clone_from(&role_lease_id);
    grant.expires_at = now + time::Duration::seconds(i64::try_from(input.ttl_seconds)?);
    let prepared_job = OperationJob {
        job_id: input.operation_id.clone(),
        invocation_id: input.operation_id.clone(),
        host_id: input.host,
        state: OperationJobState::Queued,
        attempt: 0,
        resume_session_id: None,
        result_ref: None,
        idempotency_key: input.idempotency_key.clone(),
        created_at: now,
        updated_at: now,
        generation: input.generation,
        phase: OperationPhase::Prepared,
        phase_started_at: Some(now),
        last_progress_at: Some(now),
        phase_deadline_at: Some(grant.expires_at),
        absolute_deadline_at: Some(grant.expires_at),
        restart_count: 0,
        runtime_contract_sha256: None,
        role_lease_id: Some(role_lease_id.clone()),
        role_lease_epoch: Some(grant.epoch),
    };
    owner_shell.operation_jobs.push(prepared_job.clone());
    delegation_runtime::save_host_broker_state(root, &owner_shell)?;

    let mut activated_state = owner_shell;
    let mut activated = HostBrokerService.activate_role_grants(
        &mut activated_state,
        &[grant],
        AuthorityLeaseLifetime::OperationBound,
        None,
        input.generation,
    )?;
    let role_lease = activated
        .pop()
        .context("operation authority activation returned no role lease")?;
    let job = activated_state
        .operation_jobs
        .iter_mut()
        .find(|job| job.job_id == input.operation_id)
        .context("operation owner job disappeared before activation")?;
    HostBrokerService.transition(job, OperationJobState::Running, None)?;
    let running_job = job.clone();
    let active_binding = activated_state
        .agent_host_sessions
        .iter()
        .find(|candidate| candidate.agent_session_id == input.agent_session_id)
        .cloned()
        .context("operation host binding disappeared before activation")?;

    let role_value = serde_json::to_value(&role_lease)?;
    let binding_value = serde_json::to_value(&active_binding)?;
    let job_value = serde_json::to_value(&running_job)?;
    let (role_authority_receipt, _) = write_canonical_host_observation_with_writer(
        writer,
        input.project_id,
        input.task_id,
        input.agent_session_id,
        &format!("host-role-lease:{role_lease_id}"),
        "host_role_lease_authority",
        &role_value,
    )
    .await?;
    let (host_binding_authority_receipt, _) = write_canonical_host_observation_with_writer(
        writer,
        input.project_id,
        input.task_id,
        input.agent_session_id,
        &format!("host-binding:{}:{}", input.agent_session_id, input.task_id),
        "host_binding_authority",
        &binding_value,
    )
    .await?;
    let (operation_job_authority_receipt, _) = write_canonical_host_observation_with_writer(
        writer,
        input.project_id,
        input.task_id,
        input.agent_session_id,
        &format!("operation-job:{}", input.operation_id),
        "operation_job_authority",
        &job_value,
    )
    .await?;

    let state_hash = hash_json(&serde_json::to_value(&activated_state)?)?;
    let authority = RoleLeaseAuthorityRecord {
        schema_version: "eliot-host-role-lease-authority-v2".to_owned(),
        role_lease_id: role_lease_id.clone(),
        lease_hash: hash_json(&role_value)?,
        task_revision: task.memory_revision.value(),
        canonical_receipt: role_authority_receipt.clone(),
        host_binding_hash: hash_json(&binding_value)?,
        canonical_host_binding_receipt: host_binding_authority_receipt.clone(),
        operation_job_hash: Some(hash_json(&job_value)?),
        canonical_operation_job_receipt: Some(operation_job_authority_receipt.clone()),
        purpose: Some(input.purpose),
        generation: input.generation,
        state_hash: state_hash.clone(),
        opened_at: Some(now),
        close_idempotency_key: None,
        canonical_revoked_role_receipt: None,
        canonical_retired_binding_receipt: None,
        canonical_terminal_job_receipt: None,
    };
    atomic_write_json(&role_authority_path_from_root(root, &role_lease_id), &authority)?;
    delegation_runtime::save_host_broker_state(root, &activated_state)?;
    Ok(OperationAuthorityOpenReceipt {
        operation_id: input.operation_id.clone(),
        purpose: input.purpose,
        generation: input.generation,
        launch_scope: operation_launch_scope(&input, role_lease_id, role_lease.epoch),
        operation_job_id: running_job.job_id,
        role_authority_receipt,
        host_binding_authority_receipt,
        operation_job_authority_receipt,
        state_hash,
        idempotent_replay: false,
        opened_at: now,
    })
}

async fn ensure_operation_close_canonical_receipts(
    writer: &WriterHandle,
    input: &OperationAuthorityCloseRequest,
    authority: &RoleLeaseAuthorityRecord,
    final_role_lease: &TaskRoleLease,
    final_host_binding: &AgentSessionHostBinding,
    final_operation_job: &OperationJob,
) -> Result<(WriteReceiptRef, WriteReceiptRef, WriteReceiptRef)> {
    let close_key = blake3::hash(input.idempotency_key.as_bytes())
        .to_hex()
        .to_string();
    let canonical_revoked_role_receipt = match &authority.canonical_revoked_role_receipt {
        Some(receipt) => receipt.clone(),
        None => {
            write_canonical_host_observation_with_writer(
                writer,
                input.project_id,
                input.task_id,
                input.agent_session_id,
                &format!(
                    "host-role-lease:{}:close:{close_key}",
                    input.role_lease_id
                ),
                "host_role_lease_authority",
                &serde_json::to_value(final_role_lease)?,
            )
            .await?
            .0
        }
    };
    let canonical_retired_binding_receipt =
        match &authority.canonical_retired_binding_receipt {
            Some(receipt) => receipt.clone(),
            None => {
                write_canonical_host_observation_with_writer(
                    writer,
                    input.project_id,
                    input.task_id,
                    input.agent_session_id,
                    &format!(
                        "host-binding:{}:{}:close:{close_key}",
                        input.agent_session_id, input.task_id
                    ),
                    "host_binding_authority",
                    &serde_json::to_value(final_host_binding)?,
                )
                .await?
                .0
            }
        };
    let canonical_terminal_job_receipt = match &authority.canonical_terminal_job_receipt {
        Some(receipt) => receipt.clone(),
        None => {
            write_canonical_host_observation_with_writer(
                writer,
                input.project_id,
                input.task_id,
                input.agent_session_id,
                &format!("operation-job:{}:close:{close_key}", input.operation_id),
                "operation_job_authority",
                &serde_json::to_value(final_operation_job)?,
            )
            .await?
            .0
        }
    };
    Ok((
        canonical_revoked_role_receipt,
        canonical_retired_binding_receipt,
        canonical_terminal_job_receipt,
    ))
}

#[allow(clippy::too_many_lines)]
async fn close_operation_scope_with_writer(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    input: OperationAuthorityCloseRequest,
) -> Result<OperationAuthorityCloseReceipt> {
    ensure!(
        input.schema_version == OPERATION_AUTHORITY_SCHEMA_VERSION,
        "unsupported operation authority schema"
    );
    ensure!(
        input.generation > 0
            && input.expected_epoch > 0
            && !input.operation_id.trim().is_empty()
            && !input.idempotency_key.trim().is_empty()
            && !input.reason.trim().is_empty(),
        "operation close identity fields are invalid"
    );
    let task = store
        .task_contract_by_id(input.task_id)
        .await?
        .context("operation close requires a canonical TaskContract")?;
    ensure!(
        task.project_id == input.project_id,
        "operation close project/task scope mismatch"
    );
    let state = delegation_runtime::load_state(root)?;
    let lease = state
        .task_role_leases
        .iter()
        .find(|lease| lease.role_lease_id == input.role_lease_id)
        .context("operation close role lease is missing")?;
    let mut authority = load_role_authority_record(root, &input.role_lease_id)?;
    let legacy_recovery = lease.lifetime == AuthorityLeaseLifetime::Legacy
        && lease.seal_attempt_id.as_deref() == Some("legacy-live-grant")
        && lease.owner_operation_id.is_none()
        && input.purpose == ExternalAgentPurpose::ProviderSmoke;
    ensure!(
        authority.generation == input.generation
            && (authority.purpose == Some(input.purpose)
                || (legacy_recovery && authority.purpose.is_none())),
        "operation close purpose or generation differs from open"
    );
    if lease.state == AuthorityLeaseState::Revoked {
        let binding = state
            .agent_host_sessions
            .iter()
            .find(|binding| binding.agent_session_id == input.agent_session_id)
            .cloned()
            .context("closed operation host binding is missing")?;
        let job = state
            .operation_jobs
            .iter()
            .find(|job| {
                job.job_id == input.operation_id
                    || (legacy_recovery && job.invocation_id == input.operation_id)
            })
            .cloned()
            .context("closed operation job is missing")?;
        let exact_operation_owner = lease.lifetime == AuthorityLeaseLifetime::OperationBound
            && lease.owner_operation_id.as_deref() == Some(input.operation_id.as_str())
            && lease.seal_attempt_id.is_none();
        let deterministic_recovery_key = format!("{}:close", job.idempotency_key);
        ensure!(
            lease.task_id == input.task_id
                && lease.agent_session_id == input.agent_session_id
                && lease.epoch == input.expected_epoch
                && lease.generation == input.generation
                && (exact_operation_owner || legacy_recovery)
                && binding.state == AgentSessionState::Retired
                && job.invocation_id == input.operation_id
                && job.generation == input.generation
                && !matches!(job.state, OperationJobState::Queued | OperationJobState::Running),
            "partial operation close no longer matches its exact local fence"
        );
        ensure!(
            authority.close_idempotency_key.as_deref()
                == Some(input.idempotency_key.as_str())
                || (authority.close_idempotency_key.is_none()
                    && input.idempotency_key == deterministic_recovery_key),
            "operation close replay changed the close idempotency key"
        );
        let revocation = state
            .authority_revocation_receipts
            .iter()
            .find(|receipt| {
                receipt.role_lease_id == input.role_lease_id
                    && receipt.prior_epoch == input.expected_epoch
                    && receipt.prior_generation == input.generation
            })
            .cloned()
            .context("closed operation revocation receipt is missing")?;
        authority.close_idempotency_key = Some(input.idempotency_key.clone());
        authority.purpose = Some(input.purpose);
        authority.lease_hash = hash_json(&serde_json::to_value(lease)?)?;
        authority.host_binding_hash = hash_json(&serde_json::to_value(&binding)?)?;
        authority.operation_job_hash = Some(hash_json(&serde_json::to_value(&job)?)?);
        authority.state_hash = hash_json(&serde_json::to_value(&state)?)?;
        atomic_write_json(
            &role_authority_path_from_root(root, &input.role_lease_id),
            &authority,
        )?;
        let (
            canonical_revoked_role_receipt,
            canonical_retired_binding_receipt,
            canonical_terminal_job_receipt,
        ) = ensure_operation_close_canonical_receipts(
            writer, &input, &authority, lease, &binding, &job,
        )
        .await?;
        authority.canonical_revoked_role_receipt =
            Some(canonical_revoked_role_receipt.clone());
        authority.canonical_retired_binding_receipt =
            Some(canonical_retired_binding_receipt.clone());
        authority.canonical_terminal_job_receipt =
            Some(canonical_terminal_job_receipt.clone());
        authority.canonical_receipt = canonical_revoked_role_receipt.clone();
        authority.canonical_host_binding_receipt = canonical_retired_binding_receipt.clone();
        authority.canonical_operation_job_receipt = Some(canonical_terminal_job_receipt.clone());
        atomic_write_json(
            &role_authority_path_from_root(root, &input.role_lease_id),
            &authority,
        )?;
        return Ok(OperationAuthorityCloseReceipt {
            operation_id: input.operation_id,
            purpose: input.purpose,
            generation: input.generation,
            authority_revocation_receipt: revocation,
            canonical_revoked_role_receipt,
            canonical_retired_binding_receipt,
            canonical_terminal_job_receipt,
            final_role_lease: lease.clone(),
            final_host_binding: binding,
            final_job_state: job.state,
            final_operation_job: job,
            state_hash: hash_json(&serde_json::to_value(&state)?)?,
            idempotent_replay: true,
        });
    }
    let operation_bound_owner = lease.lifetime == AuthorityLeaseLifetime::OperationBound
        && lease.owner_operation_id.as_deref() == Some(input.operation_id.as_str())
        && lease.seal_attempt_id.is_none();
    let legacy_owner = legacy_recovery
        && state.operation_jobs.iter().any(|job| {
            job.invocation_id == input.operation_id
                && job.generation == input.generation
                && !matches!(job.state, OperationJobState::Queued | OperationJobState::Running)
                && job.result_ref.is_some()
        })
        && state.agent_invocations.iter().any(|request| {
            request.invocation_id == input.operation_id
                && request.role_lease_id == input.role_lease_id
                && request.role_lease_epoch == input.expected_epoch
                && request.operation_generation == input.generation
        })
        && state.agent_results.iter().any(|result| {
            result.invocation_id == input.operation_id
                && result.role_lease_epoch == input.expected_epoch
                && result.operation_generation == input.generation
                && result.canonical_receipt.is_some()
        });
    ensure!(
        lease.task_id == input.task_id
            && lease.agent_session_id == input.agent_session_id
            && lease.state == AuthorityLeaseState::Active
            && (operation_bound_owner || legacy_owner)
            && lease.epoch == input.expected_epoch
            && lease.generation == input.generation,
        "operation close does not match the exact active owner or legacy smoke proof"
    );
    let mut fenced = state;
    let final_role_lease = HostBrokerService.revoke_role(
        &mut fenced,
        &input.role_lease_id,
        input.expected_epoch,
        &input.reason,
        None,
    )?;
    let final_host_binding = HostBrokerService.retire_session(
        &mut fenced,
        input.agent_session_id,
        &input.reason,
    )?;
    let job = fenced
        .operation_jobs
        .iter_mut()
        .find(|job| {
            (job.job_id == input.operation_id || legacy_recovery)
                && job.invocation_id == input.operation_id
                && job.generation == input.generation
        })
        .context("operation close owner job is missing or stale")?;
    job.state = match input.terminal_outcome {
        OperationAuthorityTerminalOutcome::Completed => OperationJobState::Completed,
        OperationAuthorityTerminalOutcome::FailedBeforeDispatch
        | OperationAuthorityTerminalOutcome::FailedAfterDispatch => OperationJobState::Failed,
        OperationAuthorityTerminalOutcome::Cancelled => OperationJobState::Cancelled,
        OperationAuthorityTerminalOutcome::TimedOut => OperationJobState::TimedOut,
        OperationAuthorityTerminalOutcome::ReconciledUnknown => OperationJobState::Reconciled,
    };
    job.phase = match job.state {
        OperationJobState::Completed | OperationJobState::Reconciled => OperationPhase::Completed,
        OperationJobState::Cancelled
        | OperationJobState::Failed
        | OperationJobState::TimedOut
        | OperationJobState::UnknownOutcome => OperationPhase::Failed,
        _ => OperationPhase::Abandoned,
    };
    job.result_ref.clone_from(&input.result_or_failure_ref);
    let now = OffsetDateTime::now_utc();
    job.phase_started_at = Some(now);
    job.last_progress_at = Some(now);
    job.updated_at = now;
    let final_operation_job = job.clone();
    let authority_revocation_receipt = fenced
        .authority_revocation_receipts
        .iter()
        .find(|receipt| {
            receipt.role_lease_id == input.role_lease_id
                && receipt.prior_epoch == input.expected_epoch
                && receipt.prior_generation == input.generation
        })
        .cloned()
        .context("operation close produced no revocation receipt")?;
    delegation_runtime::save_host_broker_state(root, &fenced)?;

    let role_value = serde_json::to_value(&final_role_lease)?;
    let binding_value = serde_json::to_value(&final_host_binding)?;
    let job_value = serde_json::to_value(&final_operation_job)?;
    let state_hash = hash_json(&serde_json::to_value(&fenced)?)?;
    authority.lease_hash = hash_json(&role_value)?;
    authority.host_binding_hash = hash_json(&binding_value)?;
    authority.operation_job_hash = Some(hash_json(&job_value)?);
    authority.state_hash.clone_from(&state_hash);
    authority.purpose = Some(input.purpose);
    authority.close_idempotency_key = Some(input.idempotency_key.clone());
    atomic_write_json(
        &role_authority_path_from_root(root, &input.role_lease_id),
        &authority,
    )?;
    let (
        canonical_revoked_role_receipt,
        canonical_retired_binding_receipt,
        canonical_terminal_job_receipt,
    ) = ensure_operation_close_canonical_receipts(
        writer,
        &input,
        &authority,
        &final_role_lease,
        &final_host_binding,
        &final_operation_job,
    )
    .await?;
    authority.canonical_receipt = canonical_revoked_role_receipt.clone();
    authority.canonical_host_binding_receipt = canonical_retired_binding_receipt.clone();
    authority.canonical_operation_job_receipt = Some(canonical_terminal_job_receipt.clone());
    authority.canonical_revoked_role_receipt = Some(canonical_revoked_role_receipt.clone());
    authority.canonical_retired_binding_receipt = Some(canonical_retired_binding_receipt.clone());
    authority.canonical_terminal_job_receipt = Some(canonical_terminal_job_receipt.clone());
    atomic_write_json(
        &role_authority_path_from_root(root, &input.role_lease_id),
        &authority,
    )?;
    Ok(OperationAuthorityCloseReceipt {
        operation_id: input.operation_id,
        purpose: input.purpose,
        generation: input.generation,
        authority_revocation_receipt,
        canonical_revoked_role_receipt,
        canonical_retired_binding_receipt,
        canonical_terminal_job_receipt,
        final_role_lease,
        final_host_binding,
        final_job_state: final_operation_job.state,
        final_operation_job,
        state_hash,
        idempotent_replay: false,
    })
}

pub(crate) async fn record_host_observation_from_daemon(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    params: Value,
) -> Result<Value> {
    let input: HostObservationInput =
        serde_json::from_value(params).context("decode private host observation RPC")?;
    validate_host_observation_authority(root, store, &input).await?;
    let (canonical_receipt, write_receipt) = write_canonical_host_observation_with_writer(
        writer,
        input.project_id,
        input.task_id,
        input.agent_session_id,
        &input.key,
        &input.receipt_kind,
        &input.body,
    )
    .await?;
    Ok(serde_json::to_value(HostObservationOutput {
        canonical_receipt,
        write_receipt,
    })?)
}

async fn validate_host_observation_authority(
    root: &Path,
    store: &CanonicalStore,
    input: &HostObservationInput,
) -> Result<()> {
    let identity = host_observation_identity(input)?;
    if input.key != identity.expected_key {
        bail!("private host observation key is not canonical for its typed receipt body");
    }
    let task = store
        .task_contract_by_id(input.task_id)
        .await?
        .context("private host observation task does not exist")?;
    if task.project_id != input.project_id {
        bail!("private host observation project/task scope mismatch");
    }
    let state = delegation_runtime::load_state(root)?;
    let binding = state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == input.agent_session_id)
        .context("private host observation session has no host binding")?;
    if identity
        .host_id
        .is_some_and(|host_id| host_id != binding.host_identity.host_id)
    {
        bail!("private host observation body host differs from its session binding");
    }
    let persisted = state
        .agent_invocations
        .iter()
        .find(|request| request.invocation_id == identity.invocation_id);
    if identity.requires_persisted_request && persisted.is_none() {
        bail!("private host observation has no persisted managed invocation request");
    }
    let expected_role_lease_id = identity
        .role_lease_id
        .as_deref()
        .or_else(|| persisted.map(|request| request.role_lease_id.as_str()));
    let role = state
        .task_role_leases
        .iter()
        .find(|role| {
            role.task_id == input.task_id
                && role.agent_session_id == input.agent_session_id
                && expected_role_lease_id.is_none_or(|expected| expected == role.role_lease_id)
        })
        .context("private host observation has no exact task role lease")?;
    if !binding
        .task_role_lease_refs
        .iter()
        .any(|role_lease_id| role_lease_id == &role.role_lease_id)
    {
        bail!("private host observation role lease is absent from its session binding");
    }
    if let Some(request) = persisted
        && (request.project_id != input.project_id
            || request.task_id != input.task_id
            || request.role_lease_id != role.role_lease_id)
    {
        bail!("private host observation differs from persisted managed invocation scope");
    }
    Ok(())
}

fn host_observation_identity(input: &HostObservationInput) -> Result<HostObservationIdentity> {
    match input.receipt_kind.as_str() {
        "agent_invocation_request" => {
            let request: AgentInvocationRequest = serde_json::from_value(input.body.clone())
                .context("decode managed AgentInvocationRequest observation")?;
            if request.project_id != input.project_id || request.task_id != input.task_id {
                bail!("managed AgentInvocationRequest body scope mismatch");
            }
            Ok(HostObservationIdentity {
                expected_key: format!("managed-agent-invocation:{}", request.invocation_id),
                invocation_id: request.invocation_id,
                role_lease_id: Some(request.role_lease_id),
                host_id: None,
                requires_persisted_request: false,
            })
        }
        "operation_job" => {
            let job: eliot_types::OperationJob = serde_json::from_value(input.body.clone())
                .context("decode managed OperationJob observation")?;
            let state_key = serde_json::to_string(&job.state)?;
            Ok(HostObservationIdentity {
                expected_key: format!(
                    "managed-operation-job:{}:{state_key}:{}",
                    job.job_id,
                    job.result_ref.as_deref().unwrap_or("none")
                ),
                invocation_id: job.invocation_id,
                role_lease_id: None,
                host_id: Some(job.host_id),
                requires_persisted_request: job.state != eliot_types::OperationJobState::Queued,
            })
        }
        "agent_result" => {
            let result: AgentResultEnvelope = serde_json::from_value(input.body.clone())
                .context("decode managed AgentResultEnvelope observation")?;
            if result.canonical_receipt.is_some() {
                bail!("managed AgentResultEnvelope observation must be unreceipted");
            }
            Ok(HostObservationIdentity {
                expected_key: format!("managed-provider-result:{}", result.result_id),
                invocation_id: result.invocation_id,
                role_lease_id: None,
                host_id: Some(result.host_id),
                requires_persisted_request: true,
            })
        }
        "managed_host_launch_result" => managed_launch_observation_identity(input),
        _ => bail!("private host observation receipt_kind is not allowlisted"),
    }
}

fn managed_launch_observation_identity(
    input: &HostObservationInput,
) -> Result<HostObservationIdentity> {
    if input.body.get("schema_version").and_then(Value::as_str)
        != Some("eliot-managed-host-launch-result-v1")
    {
        bail!("managed host launch observation has the wrong schema version");
    }
    let invocation_id = input
        .body
        .get("invocation_id")
        .and_then(Value::as_str)
        .context("managed host launch observation has no invocation_id")?;
    for (field, expected) in [
        ("project_id", input.project_id.to_string()),
        ("task_id", input.task_id.to_string()),
        ("agent_session_id", input.agent_session_id.to_string()),
    ] {
        if input
            .body
            .pointer(&format!("/scope/{field}"))
            .and_then(Value::as_str)
            != Some(expected.as_str())
        {
            bail!("managed host launch observation scope field {field} differs");
        }
    }
    let host_id: AgentHostId = serde_json::from_value(
        input
            .body
            .get("host")
            .cloned()
            .context("managed host launch observation has no host")?,
    )?;
    Ok(HostObservationIdentity {
        invocation_id: invocation_id.to_owned(),
        expected_key: format!("managed-host-result:{invocation_id}"),
        role_lease_id: input
            .body
            .pointer("/scope/role_lease_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        host_id: Some(host_id),
        requires_persisted_request: true,
    })
}

async fn grant_role_with_writer(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    input: HostRoleGrantInput,
) -> Result<Value> {
    let task_id = TaskId::from_str(&input.task).context("parse --task")?;
    let agent_session_id = AgentSessionId::from_str(&input.session).context("parse --session")?;
    let role = parse_role(&input.role)?;
    let task_contract = store
        .task_contract_by_id(task_id)
        .await?
        .context("role grant requires a current canonical TaskContract")?;
    if task_contract.status != TaskContractStatus::Open {
        bail!("role grant requires an open current canonical TaskContract");
    }
    let mut state = delegation_runtime::load_state(root)?;
    let (role_lease, controller_lease) = HostBrokerService.grant_role(
        &mut state,
        task_id,
        agent_session_id,
        role,
        input.capability,
        input.ttl_minutes,
    )?;
    let host_binding = HostBrokerService.bind_session_scope(
        &mut state,
        agent_session_id,
        task_contract.project_id,
        task_id,
    )?;
    let lease_value = serde_json::to_value(&role_lease)?;
    let host_binding_value = serde_json::to_value(&host_binding)?;
    let (canonical_receipt, _) = write_canonical_host_observation_with_writer(
        writer,
        task_contract.project_id,
        task_id,
        agent_session_id,
        &format!("host-role-lease:{}", role_lease.role_lease_id),
        "host_role_lease_authority",
        &lease_value,
    )
    .await?;
    let (canonical_host_binding_receipt, _) = write_canonical_host_observation_with_writer(
        writer,
        task_contract.project_id,
        task_id,
        agent_session_id,
        &format!("host-binding:{}:{task_id}", host_binding.agent_session_id),
        "host_binding_authority",
        &host_binding_value,
    )
    .await?;
    let canonical_controller_lease_receipt = if let Some(controller_lease) = &controller_lease {
        let (receipt, _) = write_canonical_host_observation_with_writer(
            writer,
            task_contract.project_id,
            task_id,
            agent_session_id,
            &format!("controller-lease:{}", controller_lease.controller_lease_id),
            "controller_lease",
            &serde_json::to_value(controller_lease)?,
        )
        .await?;
        Some(receipt)
    } else {
        None
    };
    let authority = RoleLeaseAuthorityRecord {
        schema_version: "eliot-host-role-lease-authority-v1".to_owned(),
        role_lease_id: role_lease.role_lease_id.clone(),
        lease_hash: hash_json(&lease_value)?,
        task_revision: task_contract.memory_revision.value(),
        canonical_receipt: canonical_receipt.clone(),
        host_binding_hash: hash_json(&host_binding_value)?,
        canonical_host_binding_receipt: canonical_host_binding_receipt.clone(),
        operation_job_hash: None,
        canonical_operation_job_receipt: None,
        purpose: None,
        generation: role_lease.generation,
        state_hash: hash_json(&serde_json::to_value(&state)?)?,
        opened_at: role_lease.activated_at,
        close_idempotency_key: None,
        canonical_revoked_role_receipt: None,
        canonical_retired_binding_receipt: None,
        canonical_terminal_job_receipt: None,
    };
    atomic_write_json(
        &role_authority_path_from_root(root, &role_lease.role_lease_id),
        &authority,
    )?;
    delegation_runtime::save_host_broker_state(root, &state)?;
    Ok(json!({
        "schema_version": "eliot-task-role-grant-v1",
        "task_role_lease": role_lease,
        "controller_lease": controller_lease,
        "canonical_authority_receipt": canonical_receipt,
        "canonical_host_binding_receipt": canonical_host_binding_receipt,
        "canonical_controller_lease_receipt": canonical_controller_lease_receipt,
        "admin_authority_granted": false
    }))
}

fn broker_status(config_path: &Path) -> Result<Value> {
    let state = delegation_runtime::load_state(&runtime_root(config_path))?;
    Ok(json!({
        "schema_version": "eliot-host-broker-v1",
        "host_sessions": state.agent_host_sessions,
        "task_role_leases": state.task_role_leases,
        "controller_leases": state.controller_leases,
        "agent_invocations": state.agent_invocations,
        "operation_jobs": state.operation_jobs,
        "agent_results": state.agent_results,
        "agent_result_dispositions": state.agent_result_dispositions
    }))
}

fn parse_role(value: &str) -> Result<AgentRole> {
    match value.trim().to_ascii_lowercase().as_str() {
        "controller" => Ok(AgentRole::Controller),
        "worker" | "implementer" => Ok(AgentRole::Implementer),
        "reviewer" => Ok(AgentRole::Reviewer),
        "auditor" => Ok(AgentRole::Auditor),
        "verifier" => Ok(AgentRole::Verifier),
        other => bail!("unknown task role: {other}"),
    }
}

fn parse_mode(value: &str) -> Result<HostMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "interactive" => Ok(HostMode::Interactive),
        "supervised" | "noninteractive" => Ok(HostMode::Supervised),
        other => bail!("unknown host mode: {other}"),
    }
}

fn ensure_l7_host(host: AgentHostId) -> Result<()> {
    if matches!(host, AgentHostId::OpenCode | AgentHostId::Claude) {
        Ok(())
    } else {
        bail!("{} is not an L7 managed integration target", host.as_str())
    }
}
