//! The Antigravity provider command surface.
//!
//! Antigravity is one external provider among several, and its commands carry
//! provider-specific installation, enablement and smoke-test detail that the
//! rest of the command layer does not share. Keeping it here means the generic
//! commands stay readable and a change to this provider stays in one file.

// This child module is a decomposition boundary for the parent command
// implementation and deliberately consumes its private service vocabulary.
#[allow(clippy::wildcard_imports)]
use super::*;

pub fn run_antigravity_windows_discover(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let discovery = antigravity_windows_install_discovery();
    write_antigravity_report_pair(
        &root,
        "antigravity-windows-install",
        "Antigravity Windows Install Discovery",
        &discovery,
    )?;
    write_json(&discovery)
}

pub fn run_antigravity_version_check(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    let binary = resolution
        .selected_path
        .as_deref()
        .context("official signed Antigravity CLI was not resolved")?;
    let gate = AntigravityVersionGateService.probe(Path::new(binary));
    write_antigravity_report_pair(
        &root,
        "antigravity-version-gate",
        "Antigravity Version Gate",
        &gate,
    )?;
    if !gate.allowed {
        write_json(&gate)?;
        bail!("Antigravity CLI is below the required automation version 1.1.1");
    }
    write_json(&gate)
}

pub fn run_antigravity_install_receipt(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let discovery = antigravity_windows_install_discovery();
    let version_gate = discovery
        .official_cli_path
        .as_deref()
        .filter(|_| discovery.official_cli_exists)
        .map(|binary| AntigravityVersionGateService.probe(Path::new(binary)));
    let receipt =
        AntigravityOfficialCliInstallerService.status_receipt(&discovery, version_gate.as_ref());
    write_antigravity_report_pair(
        &root,
        "antigravity-install-receipt",
        "Antigravity Official CLI Install Receipt",
        &receipt,
    )?;
    write_json(&receipt)
}

pub fn run_antigravity_resolve(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    write_antigravity_report_pair(
        &root,
        "antigravity-resolution",
        "Antigravity Resolution",
        &resolution,
    )?;
    write_json(&resolution)
}

pub fn run_antigravity_detect(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, probe, _contract) = antigravity_resolution_probe_contract();
    write_antigravity_report_pair(
        &root,
        "antigravity-resolution",
        "Antigravity Resolution",
        &resolution,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-detection",
        "Antigravity Detection",
        &probe,
    )?;
    write_json(&probe)
}

pub fn run_antigravity_status(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, mut probe, contract) = antigravity_resolution_probe_contract();
    let enablement = latest_antigravity_enablement(&root)?;
    let disable = latest_antigravity_disable(&root)?;
    let enablement_is_current = enablement.as_ref().is_some_and(|receipt| {
        receipt
            .expires_at
            .is_none_or(|expires_at| expires_at > time::OffsetDateTime::now_utc())
            && disable
                .as_ref()
                .is_none_or(|disabled| disabled.created_at < receipt.created_at)
    });
    if enablement_is_current {
        probe.provider_state = AntigravityProviderState::ReadyEnabled;
    }
    let home = antigravity_home()?;
    let official_plugin = AntigravityOfficialPluginService.status(&home);
    let mcp_configs = AntigravityMcpConfigService.status(&home);
    let official_plugin_ready = (official_plugin.gui_installed || official_plugin.cli_installed)
        && official_plugin.official_schema_valid
        && official_plugin.skill_visible
        && official_plugin.rule_visible;
    let mcp_registered = mcp_configs.iter().any(|status| {
        status.surface == eliot_types::AntigravityMcpConfigSurface::Gui && status.registered
    });
    let doctor = AntigravityDoctorIntegration.status(
        &resolution,
        &probe,
        &contract,
        official_plugin_ready,
        mcp_registered,
        antigravity_mcp_tools_governed_only(),
    );
    write_antigravity_report_pair(
        &root,
        "antigravity-detection",
        "Antigravity Detection",
        &probe,
    )?;
    write_antigravity_report_pair(&root, "antigravity-doctor", "Antigravity Doctor", &doctor)?;
    write_json(&serde_json::json!({
        "doctor": doctor,
        "official_plugin": official_plugin,
        "mcp_configs": mcp_configs
    }))
}

pub fn run_antigravity_doctor(config_path: &Path) -> Result<()> {
    run_antigravity_status(config_path)
}

pub fn run_antigravity_command_contract(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (_resolution, _probe, contract) = antigravity_resolution_probe_contract();
    write_antigravity_report_pair(
        &root,
        "antigravity-contract",
        "Antigravity Command Contract",
        &contract,
    )?;
    write_json(&contract)
}

pub fn run_antigravity_request(
    config_path: &Path,
    project: &str,
    task: &str,
    mode: &str,
    question: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mode = parse_antigravity_mode(mode)?;
    let request = antigravity_review_request(project, task, mode, question);
    let request_path = antigravity_latest_request_path(&root);
    write_report_pair(
        &request_path,
        &root
            .join("reports")
            .join("antigravity-runs")
            .join("latest-request.md"),
        &request,
        &typed_report_markdown("Antigravity Request", &request)?,
    )?;
    write_json(&request)
}

pub fn run_antigravity_run(config_path: &Path, request_id: &str, dry_run: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let request = latest_antigravity_request(&root)?
        .with_context(|| "no latest Antigravity request found; run antigravity request first")?;
    if request_id != "latest" && request_id != request.request_id {
        bail!("requested Antigravity request id does not match latest request");
    }
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let gate = AntigravityExecutionGate.decide(
        &request,
        &resolution,
        &probe,
        &contract,
        None,
        None,
        false,
        false,
        dry_run,
    );
    let run = if gate.decision == AntigravityExecutionGateDecisionKind::AllowDryRun {
        AntigravityRunner.run_fixture(&request, &contract, &repo_root())?
    } else {
        AntigravityRunner.blocked_run(&request, &contract, &gate, &repo_root())
    };
    write_antigravity_report_pair(&root, "antigravity-runs", "Antigravity Run", &run)?;
    write_json(&run)
}

pub fn run_antigravity_job_status(config_path: &Path, run_id: &str) -> Result<()> {
    let run = latest_antigravity_run(&runtime_root(config_path))?
        .with_context(|| "no latest Antigravity run found; run antigravity run first")?;
    if run_id != "latest" && run_id != run.run_id {
        bail!("requested Antigravity run id does not match latest run");
    }
    let status = serde_json::json!({
        "component": "antigravity_job_status",
        "run_id": run.run_id,
        "request_id": run.request_id,
        "state": run.state,
        "dry_run": run.dry_run,
        "fixture_runner": run.fixture_runner,
        "message": run.message
    });
    write_json(&status)
}

pub fn run_antigravity_result(config_path: &Path, run_id: &str) -> Result<()> {
    let run = latest_antigravity_run(&runtime_root(config_path))?
        .with_context(|| "no latest Antigravity run found; run antigravity run first")?;
    if run_id != "latest" && run_id != run.run_id {
        bail!("requested Antigravity run id does not match latest run");
    }
    let result = run
        .normalized_result
        .with_context(|| "latest Antigravity run has no normalized result")?;
    write_json(&result)
}

pub fn run_antigravity_plugin_schema(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let manifest_path = official_antigravity_plugin_source(config_path).join("plugin.json");
    let manifest: serde_json::Value =
        serde_json::from_reader(std::fs::File::open(&manifest_path)?)?;
    let valid = AntigravityOfficialPluginService.official_manifest_valid(&manifest);
    let report = serde_json::json!({
        "component": "antigravity_official_plugin_schema",
        "manifest_path": manifest_path,
        "manifest": manifest,
        "official_schema_valid": valid,
        "checked_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-plugin-schema",
        "Antigravity Official Plugin Schema",
        &report,
    )?;
    if !valid {
        write_json(&report)?;
        bail!("official Antigravity plugin manifest is invalid");
    }
    write_json(&report)
}

#[allow(clippy::too_many_lines)]
pub fn run_antigravity_plugin_install_official(
    config_path: &Path,
    admin_confirm: bool,
) -> Result<()> {
    if !admin_confirm {
        bail!("official Antigravity plugin install requires --admin-confirm");
    }
    let root = runtime_root(config_path);
    let home = antigravity_home()?;
    let source = official_antigravity_plugin_source(config_path).canonicalize()?;
    let binary = resolved_antigravity_binary()?;
    let version_gate = AntigravityVersionGateService.probe(&binary);
    if !version_gate.allowed {
        bail!("official plugin install requires Antigravity CLI >= 1.1.1");
    }

    let validate = ProcessCommand::new(&binary)
        .args(["plugin", "validate"])
        .arg(&source)
        .current_dir(project_root_from_config(config_path))
        .output()?;
    if !validate.status.success() {
        let failure = serde_json::json!({
            "component": "antigravity_official_plugin_install",
            "stage": "validate",
            "succeeded": false,
            "stdout": String::from_utf8_lossy(&validate.stdout),
            "stderr": String::from_utf8_lossy(&validate.stderr)
        });
        write_antigravity_report_pair(
            &root,
            "antigravity-plugin-install",
            "Antigravity Official Plugin Install",
            &failure,
        )?;
        bail!("agy plugin validate failed for official ELIOT plugin");
    }

    let prior_status = AntigravityOfficialPluginService.status(&home);
    let uninstall = if prior_status.gui_installed || prior_status.cli_installed {
        let output = ProcessCommand::new(&binary)
            .args(["plugin", "uninstall", "eliot-antigravity"])
            .current_dir(project_root_from_config(config_path))
            .output()?;
        if !output.status.success() {
            let failure = serde_json::json!({
                "component": "antigravity_official_plugin_install",
                "stage": "remove_previous_version",
                "succeeded": false,
                "stdout": String::from_utf8_lossy(&output.stdout),
                "stderr": String::from_utf8_lossy(&output.stderr)
            });
            write_antigravity_report_pair(
                &root,
                "antigravity-plugin-install",
                "Antigravity Official Plugin Install",
                &failure,
            )?;
            bail!("agy could not remove the previous official ELIOT plugin version");
        }
        Some(output)
    } else {
        None
    };

    let install = ProcessCommand::new(&binary)
        .args(["plugin", "install"])
        .arg(&source)
        .current_dir(project_root_from_config(config_path))
        .output()?;
    let list = ProcessCommand::new(&binary)
        .args(["plugin", "list"])
        .current_dir(project_root_from_config(config_path))
        .output()?;
    let list_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let status = AntigravityOfficialPluginService.status(&home);
    let files_written = installed_plugin_files(&status);
    let receipt = AntigravityOfficialPluginService.install_receipt(
        &status,
        install.status.success() && list.status.success(),
        &list_output,
        files_written,
    );
    let report = serde_json::json!({
        "receipt": receipt,
        "validate_stdout": String::from_utf8_lossy(&validate.stdout),
        "uninstall_stdout": uninstall.as_ref().map(|output| String::from_utf8_lossy(&output.stdout)),
        "uninstall_stderr": uninstall.as_ref().map(|output| String::from_utf8_lossy(&output.stderr)),
        "install_stdout": String::from_utf8_lossy(&install.stdout),
        "install_stderr": String::from_utf8_lossy(&install.stderr),
        "plugin_list_output": list_output,
        "status": status
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-plugin-install",
        "Antigravity Official Plugin Install",
        &report,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-official-plugin",
        "Antigravity Official Plugin Status",
        &status,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-plugin-install-receipt",
        "Antigravity Official Plugin Install Receipt",
        &receipt,
    )?;
    if !receipt.installed {
        write_json(&report)?;
        bail!("OfficialPluginInstallFailed");
    }
    write_json(&report)
}

pub fn run_antigravity_mcp_config_status(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let statuses = AntigravityMcpConfigService.status(&antigravity_home()?);
    write_antigravity_report_pair(
        &root,
        "antigravity-mcp",
        "Antigravity MCP Config Status",
        &statuses,
    )?;
    write_json(&statuses)
}

pub fn run_antigravity_mcp_register(config_path: &Path, admin_confirm: bool) -> Result<()> {
    if !admin_confirm {
        bail!("Antigravity MCP registration requires --admin-confirm");
    }
    let root = runtime_root(config_path);
    let home = antigravity_home()?;
    let project_root = project_root_from_config(config_path).canonicalize()?;
    let executable = release_eliot_executable(config_path)?;
    let receipt =
        AntigravityMcpConfigService.register_gui_for_project(&home, &executable, &project_root)?;
    let statuses = AntigravityMcpConfigService.status(&home);
    let gui_registered = statuses.iter().any(|status| {
        status.surface == eliot_types::AntigravityMcpConfigSurface::Gui && status.registered
    });
    let report = serde_json::json!({
        "component": "antigravity_mcp_registration",
        "receipt": receipt,
        "configs": statuses,
        "gui_registered": gui_registered,
        "registered_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-mcp-registration",
        "Antigravity MCP Registration",
        &receipt,
    )?;
    write_antigravity_report_pair(&root, "antigravity-mcp", "Antigravity MCP Status", &report)?;
    if !gui_registered {
        write_json(&report)?;
        bail!("Antigravity HOME MCP registration did not validate");
    }
    write_json(&report)
}

pub fn run_antigravity_mcp_backup_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let config_path = AntigravityMcpConfigService.config_paths(&antigravity_home()?)[0]
        .1
        .clone();
    let backups = config_path
        .parent()
        .and_then(|parent| std::fs::read_dir(parent).ok())
        .into_iter()
        .flatten()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("mcp_config.json.eliot-backup-"))
        })
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let report = serde_json::json!({
        "component": "antigravity_mcp_backup_list",
        "config_path": config_path,
        "backups": backups,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-mcp-backups",
        "Antigravity MCP Backups",
        &report,
    )?;
    write_json(&report)
}

pub fn run_antigravity_mcp_invocation_proof(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let run = latest_antigravity_run(&root)?.context("no real Antigravity run receipt found")?;
    let receipt = matching_antigravity_mcp_invocation(&root, &run)
        .context("no matching real Antigravity MCP invocation event found")?;
    let within_run = receipt.invoked_at >= run.created_at
        && run
            .completed_at
            .is_some_and(|completed_at| receipt.invoked_at <= completed_at);
    let proven = receipt.succeeded
        && receipt.matching_audit_event
        && receipt.audit_event_ref.is_some()
        && receipt.profile == "external_auditor"
        && within_run;
    let collective_route = if proven {
        Some(ensure_antigravity_collective_route(&root, &run)?)
    } else {
        None
    };
    let report = serde_json::json!({
        "component": "antigravity_mcp_invocation_proof",
        "receipt": receipt,
        "run_id": run.run_id,
        "audit_event_within_run": within_run,
        "collective_route": collective_route,
        "proven": proven,
        "checked_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-mcp-invocation-proof",
        "Antigravity MCP Invocation Proof",
        &report,
    )?;
    if !proven {
        write_json(&report)?;
        bail!("McpDiscoveredButInvocationBlocked");
    }
    write_json(&report)
}

pub fn run_antigravity_visibility(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let home = antigravity_home()?;
    let windows_install = antigravity_windows_install_discovery();
    let version_gate = windows_install
        .official_cli_path
        .as_deref()
        .filter(|_| windows_install.official_cli_exists)
        .map(|path| AntigravityVersionGateService.probe(Path::new(path)));
    let latest_run = latest_antigravity_run(&root)?;
    let mcp_invocation = latest_run
        .as_ref()
        .and_then(|run| matching_antigravity_mcp_invocation(&root, run));
    let report = AntigravityVisibilityService.report(
        AntigravityGuiProcessProbeService.probe(),
        windows_install,
        version_gate,
        AntigravityMcpConfigService.status(&home),
        mcp_invocation,
        AntigravityOfficialPluginService.status(&home),
        latest_antigravity_live_smoke(&root)?,
        latest_antigravity_typed(&root, "antigravity-disposable-worktree-smoke")?,
    );
    write_antigravity_report_pair(
        &root,
        "antigravity-visibility",
        "Antigravity Visibility",
        &report,
    )?;
    write_json(&report)
}

pub fn run_antigravity_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let latest_request = latest_antigravity_request(&root)?;
    let latest_run = latest_antigravity_run(&root)?;
    let runs = latest_run.iter().cloned().collect::<Vec<_>>();
    let telemetry = AntigravityTelemetryService.report(&probe, &runs);
    let home = antigravity_home()?;
    let official_plugin = AntigravityOfficialPluginService.status(&home);
    let mcp_configs = AntigravityMcpConfigService.status(&home);
    let official_plugin_ready = (official_plugin.gui_installed || official_plugin.cli_installed)
        && official_plugin.official_schema_valid
        && official_plugin.skill_visible
        && official_plugin.rule_visible;
    let mcp_registered = mcp_configs.iter().any(|status| {
        status.surface == eliot_types::AntigravityMcpConfigSurface::Gui && status.registered
    });
    let doctor = AntigravityDoctorIntegration.status(
        &resolution,
        &probe,
        &contract,
        official_plugin_ready,
        mcp_registered,
        antigravity_mcp_tools_governed_only(),
    );
    let report = antigravity_report(
        resolution,
        probe,
        contract,
        latest_request,
        latest_run,
        doctor,
        telemetry,
    );
    write_antigravity_report_pair(
        &root,
        "antigravity-telemetry",
        "Antigravity Telemetry",
        &report.telemetry,
    )?;
    write_antigravity_report_pair(&root, "antigravity-report", "Antigravity Report", &report)?;
    write_json(&report)
}

pub fn run_antigravity_auth_check(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let auth = AntigravityAuthCheckService.help_only(
        &probe,
        vec![
            "reports/antigravity-resolution/latest.json".to_owned(),
            "reports/antigravity-detection/latest.json".to_owned(),
            "reports/antigravity-contract/latest.json".to_owned(),
        ],
    );
    write_antigravity_report_pair(
        &root,
        "antigravity-resolution",
        "Antigravity Resolution",
        &resolution,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-detection",
        "Antigravity Detection",
        &probe,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-contract",
        "Antigravity Contract",
        &contract,
    )?;
    write_antigravity_report_pair(&root, "antigravity-auth", "Antigravity Auth", &auth)?;
    write_json(&auth)
}

pub fn run_antigravity_enable(config_path: &Path, scope: &str, admin_confirm: bool) -> Result<()> {
    if !admin_confirm {
        bail!("Antigravity enable requires --admin-confirm");
    }
    let root = runtime_root(config_path);
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let scope = parse_antigravity_enablement_scope(scope)?;
    let auth = latest_antigravity_auth(&root)?.unwrap_or_else(|| {
        AntigravityAuthCheckService.help_only(
            &probe,
            vec!["reports/antigravity-detection/latest.json".to_owned()],
        )
    });
    let previous_state = AntigravityEnablementService.state_from_probe(&probe, Some(&auth));
    write_antigravity_report_pair(&root, "antigravity-auth", "Antigravity Auth", &auth)?;
    if resolution.status != AntigravityBinaryResolutionStatus::Resolved
        || !contract.noninteractive_supported
        || matches!(
            previous_state,
            AntigravityEnablementState::NotInstalled
                | AntigravityEnablementState::InstalledNoNonInteractiveMode
                | AntigravityEnablementState::BlockedByPolicy
        )
    {
        let blocked = serde_json::json!({
            "component": "antigravity_enablement",
            "status": "blocked",
            "requested_scope": scope,
            "previous_state": previous_state,
            "provider_state": probe.provider_state,
            "binary_resolution_status": resolution.status,
            "noninteractive_supported": contract.noninteractive_supported,
            "reason": "real Antigravity enablement blocked because the governed CLI provider is unavailable or has no safe noninteractive contract",
            "created_at": time::OffsetDateTime::now_utc()
        });
        write_antigravity_report_pair(
            &root,
            "antigravity-enablement",
            "Antigravity Enablement",
            &blocked,
        )?;
        return write_json(&blocked);
    }
    let receipt = AntigravityEnablementService.enable(
        previous_state,
        scope,
        true,
        vec![
            "explicit local admin CLI confirmation received".to_owned(),
            "only governed real Antigravity smoke scopes are enabled".to_owned(),
        ],
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-enablement",
        "Antigravity Enablement",
        &receipt,
    )?;
    write_json(&receipt)
}

pub fn run_antigravity_disable(config_path: &Path, reason: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let previous_state = latest_antigravity_enablement(&root)?
        .map_or(AntigravityEnablementState::ReadyDisabled, |receipt| {
            receipt.requested_state
        });
    let receipt = AntigravityEnablementService.disable(previous_state, reason);
    write_antigravity_report_pair(
        &root,
        "antigravity-disable",
        "Antigravity Disable",
        &receipt,
    )?;
    write_json(&receipt)
}

#[allow(clippy::too_many_lines)]
pub async fn run_antigravity_live_smoke(config_path: &Path, mode: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_root = project_root_from_config(config_path).canonicalize()?;
    let mode = parse_antigravity_live_smoke_mode(mode)?;
    let runner =
        crate::host_runtime::supervised_process::SupervisedWindowsProcessRunner::new(config_path)?;
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    let probe = AntigravityCapabilityProbeService
        .probe_from_resolution_supervised(&resolution, &runner)
        .await;
    let contract = AntigravityCommandContractService.build(&resolution, &probe);
    let auth = latest_antigravity_auth(&root)?.unwrap_or_else(|| {
        AntigravityAuthCheckService.help_only(
            &probe,
            vec!["reports/antigravity-detection/latest.json".to_owned()],
        )
    });
    let enablement = latest_antigravity_enablement(&root)?;
    let disable = latest_antigravity_disable(&root)?;
    let smoke_service = AntigravityDisposableWorktreeSmokeService;
    let live_before = smoke_service.snapshot_live_tree(&project_root)?;
    write_antigravity_report_pair(
        &root,
        "antigravity-live-tree-before",
        "Antigravity Live Tree Before",
        &live_before,
    )?;
    let (mut work_state, work_lease) =
        antigravity_smoke_work_lease(&root, "antigravity-live-smoke")?;
    let worktree_root = std::env::temp_dir().join("eliot-governor-antigravity-worktrees");
    let worktree_lease = smoke_service
        .create_disposable_worktree(
            &mut work_state,
            &work_lease,
            &worktree_root,
            default_lease_ttl_minutes(),
        )
        .await?;
    let worktree_path = PathBuf::from(&worktree_lease.worktree_path);
    let smoke = AntigravityLiveSmokeService.build_request(
        work_lease.project_id,
        work_lease.work_lease_id,
        Some(worktree_lease.worktree_lease_id),
        mode,
    );
    let mut request = antigravity_review_request(
        "eliot-governor",
        "antigravity-live-smoke",
        match mode {
            AntigravityLiveSmokeMode::DisposableWorktreeAudit => AntigravityReviewMode::AuditPlan,
            AntigravityLiveSmokeMode::DisposableWorktreeCandidateNoApply => {
                AntigravityReviewMode::CandidateImplementation
            }
        },
        &AntigravityLiveSmokeService.disposable_worktree_prompt(),
    );
    request.project_id = work_lease.project_id;
    request.task_id = work_lease.task_id;
    request.work_lease_id = Some(work_lease.work_lease_id);
    request.worktree_lease_id = Some(worktree_lease.worktree_lease_id);
    request.provider_enabled = enablement.as_ref().is_some_and(|receipt| {
        let disabled_after_enable = disable
            .as_ref()
            .is_some_and(|disable| disable.created_at >= receipt.created_at);
        !disabled_after_enable
            && match mode {
                AntigravityLiveSmokeMode::DisposableWorktreeAudit => {
                    AntigravityEnablementService.receipt_allows_disposable_worktree_audit(receipt)
                }
                AntigravityLiveSmokeMode::DisposableWorktreeCandidateNoApply => {
                    AntigravityEnablementService
                        .receipt_allows_disposable_worktree_candidate(receipt)
                }
            }
    });

    let provider_gate_passed = provider_gate_verification_passed(&root)?;
    let gate = AntigravityExecutionGate.decide(
        &request,
        &resolution,
        &probe,
        &contract,
        Some(&work_lease),
        Some(&worktree_lease),
        provider_gate_passed,
        false,
        false,
    );
    let result = if resolution.status != AntigravityBinaryResolutionStatus::Resolved
        || !contract.noninteractive_supported
    {
        AntigravityLiveSmokeService.provider_unavailable_result(
            &smoke,
            "real Antigravity CLI is unavailable through governed PATH probes or lacks a safe noninteractive contract",
        )
    } else if gate.decision != AntigravityExecutionGateDecisionKind::AllowRealRun {
        let run = AntigravityRunner.blocked_run(&request, &contract, &gate, &worktree_path);
        write_antigravity_report_pair(&root, "antigravity-runs", "Antigravity Run", &run)?;
        AntigravityLiveSmokeService.result_from_run(&smoke, &run)
    } else {
        match AntigravityRunner
            .run_real_supervised(
                &request,
                &contract,
                &worktree_lease,
                &worktree_path,
                &runner,
            )
            .await
        {
            Ok(run) => {
                let inferred_auth = AntigravityAuthCheckService.from_probe_output(
                    &format!("{}\n{}", run.stdout_excerpt, run.stderr_excerpt),
                    run.state == eliot_types::AntigravityRunState::TimedOut,
                    vec!["reports/antigravity-runs/latest.json".to_owned()],
                );
                write_antigravity_report_pair(
                    &root,
                    "antigravity-auth",
                    "Antigravity Auth",
                    &inferred_auth,
                )?;
                write_antigravity_report_pair(&root, "antigravity-runs", "Antigravity Run", &run)?;
                AntigravityLiveSmokeService.result_from_run(&smoke, &run)
            }
            Err(error) => {
                let result = AntigravityLiveSmokeService.provider_unavailable_result(
                    &smoke,
                    format!("real Antigravity run could not be started safely: {error}"),
                );
                write_antigravity_report_pair(
                    &root,
                    "antigravity-live-smoke",
                    "Antigravity Live Smoke",
                    &result,
                )?;
                result
            }
        }
    };
    let evidence = match smoke_service
        .capture_cleanup_and_compare(
            &mut work_state,
            &live_before,
            worktree_lease.worktree_lease_id,
            &root.join("candidate-diffs").join("antigravity"),
            CandidateDiffService::default_max_diff_bytes(),
            result.marker_seen,
        )
        .await
    {
        Ok(evidence) => evidence,
        Err(error) => {
            let _ =
                WorktreeCleanupService.revoke(&mut work_state, worktree_lease.worktree_lease_id);
            let _ = WorktreeCleanupService
                .cleanup(&mut work_state, worktree_lease.worktree_lease_id)
                .await;
            return Err(error.into());
        }
    };
    write_antigravity_report_pair(
        &root,
        "antigravity-live-smoke",
        "Antigravity Live Smoke",
        &result,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-disposable-worktree-smoke",
        "Antigravity Disposable Worktree Smoke Evidence",
        &evidence,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-worktree-state",
        "Antigravity Worktree State",
        &work_state,
    )?;
    if enablement.is_some()
        && !matches!(
            enablement.as_ref().map(|receipt| receipt.approval_scope),
            Some(AntigravityEnablementScope::PersistentLocalAdmin)
        )
    {
        let disable = AntigravityEnablementService.disable(
            enablement
                .as_ref()
                .map_or(AntigravityEnablementState::ReadyDisabled, |receipt| {
                    receipt.requested_state
                }),
            "provider disabled after governed live smoke attempt",
        );
        write_antigravity_report_pair(
            &root,
            "antigravity-disable",
            "Antigravity Disable",
            &disable,
        )?;
    }
    let _ = write_antigravity_real_report_snapshot(&root, resolution, probe, contract, auth)?;
    let passed = result.status == AntigravityLiveSmokeStatus::Passed
        && evidence.marker_seen
        && evidence.live_tree_unchanged
        && evidence.candidate_only
        && evidence.taint == TaintClass::ExternalAgent
        && evidence.cleanup_state == eliot_types::WorktreeLeaseState::Cleaned;
    write_json(&serde_json::json!({
        "smoke": result,
        "worktree_evidence": evidence
    }))?;
    if !passed {
        bail!("governed Antigravity disposable-worktree smoke failed");
    }
    Ok(())
}

pub fn run_antigravity_rollback(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let previous_state = latest_antigravity_enablement(&root)?
        .map_or(AntigravityEnablementState::ReadyDisabled, |receipt| {
            receipt.requested_state
        });
    let receipt = AntigravityRollbackService.rollback(previous_state, "manual governed rollback");
    write_antigravity_report_pair(
        &root,
        "antigravity-disable",
        "Antigravity Disable",
        &receipt,
    )?;
    write_json(&serde_json::json!({
        "component": "antigravity_rollback",
        "cancels_process_group": AntigravityRollbackService.cancels_process_group(),
        "disable_receipt": receipt
    }))
}

pub fn run_antigravity_real_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let auth = latest_antigravity_auth(&root)?.unwrap_or_else(|| {
        AntigravityAuthCheckService.help_only(
            &probe,
            vec!["reports/antigravity-detection/latest.json".to_owned()],
        )
    });
    let report = write_antigravity_real_report_snapshot(&root, resolution, probe, contract, auth)?;
    write_json(&report)
}
