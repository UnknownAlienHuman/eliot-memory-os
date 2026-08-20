#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_engine::{
    AntigravityBinaryResolver, AntigravityCapabilityProbeService,
    AntigravityCommandContractService, AntigravityDisposableWorktreeSmokeService,
    AntigravityEnablementService, AntigravityEnvPolicyService, AntigravityExecutionGate,
    AntigravityLiveSmokeService, AntigravityMcpBoundaryService, AntigravityMcpConfigService,
    AntigravityOfficialPluginService, AntigravityRunner, AntigravityTextOutputNormalizer,
    AntigravityVersionGateService, AntigravityWindowsInstallDiscoveryService, WorkState,
    antigravity_review_request,
};
use eliot_types::{
    AgentId, AgentRole, AgentSessionId, AntigravityBinaryCandidateSource,
    AntigravityBinaryResolution, AntigravityBinaryResolutionStatus, AntigravityEnablementScope,
    AntigravityEnablementState, AntigravityExecutionGateDecisionKind, AntigravityLiveSmokeMode,
    AntigravityLiveSmokeStatus, AntigravityMcpConfigSurface, AntigravityResponseProtocolReceipt,
    AntigravityReviewMode, AntigravityRunState, AntigravityVersionGateStatus, AuthorityProfile,
    CandidateDiffStatus, ProjectId, RiskTier, TaintClass, TaskId, WorkItemId, WorkLease,
    WorkLeaseDecision, WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState,
    WorkScope, WorktreeLease, WorktreeLeaseId, WorktreeLeaseState,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use time::{Duration, OffsetDateTime};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const HELP: &str = "Usage: agy --print --prompt <PROMPT> --print-timeout <DURATION> --log-file <PATH> --sandbox <MODE> --disable-slash-commands --output-format <text|json> --model <MODEL> --effort <low|medium|high> --add-dir <PATH>";

#[test]
fn version_gate_requires_1_1_1() {
    let old = AntigravityVersionGateService.evaluate_output("agy version 1.1.0");
    let current = AntigravityVersionGateService.evaluate_output("Antigravity CLI v1.1.1");

    assert_eq!(old.status, AntigravityVersionGateStatus::TooOld);
    assert!(!old.allowed);
    assert_eq!(old.parsed_version.as_deref(), Some("1.1.0"));
    assert_eq!(old.minimum_version, "1.1.1");
    assert_eq!(current.status, AntigravityVersionGateStatus::Compatible);
    assert!(current.allowed);
    assert_eq!(current.parsed_version.as_deref(), Some("1.1.1"));
}

#[test]
fn official_windows_path_is_discovered_without_plain_agy_invocation() -> TestResult {
    let root = TempRoot::new("path-discovery")?;
    let local_app_data = root.path.join("LocalAppData");
    let official_path = AntigravityBinaryResolver::official_windows_cli_path(&local_app_data);
    fs::create_dir_all(official_path.parent().expect("official path parent"))?;
    fs::write(&official_path, b"unsigned test fixture")?;
    let config = eliot_types::AntigravityBinaryResolverConfig {
        explicit_binary: None,
        search_path_names: Vec::new(),
        reject_temp_download_paths: true,
        allow_install: false,
    };

    let discovery = AntigravityWindowsInstallDiscoveryService.discover(Some(&local_app_data));
    let resolution =
        AntigravityBinaryResolver.resolve_with_local_app_data(&config, Some(&local_app_data));

    assert_eq!(
        official_path,
        local_app_data.join("agy").join("bin").join("agy.exe")
    );
    assert!(discovery.official_cli_exists);
    assert_eq!(
        discovery.candidate_source,
        AntigravityBinaryCandidateSource::LocalAppDataOfficialInstall
    );
    assert_eq!(
        resolution.status,
        AntigravityBinaryResolutionStatus::Rejected
    );
    assert!(!resolution.plain_agy_invoked);
    assert!(!resolution.install_attempted);
    assert!(
        resolution
            .detection_commands
            .iter()
            .all(|command| command != "agy")
    );
    assert!(resolution.candidates.iter().any(|candidate| {
        candidate.source == AntigravityBinaryCandidateSource::LocalAppDataOfficialInstall
            && !candidate.accepted
            && candidate
                .rejection_reasons
                .iter()
                .any(|reason| reason.contains("temp/downloads"))
    }));
    Ok(())
}

#[test]
fn serde_accepts_old_live_smoke_name_but_serializes_disposable_name() -> TestResult {
    let mode: AntigravityLiveSmokeMode = serde_json::from_str(r#""read_only_audit""#)?;
    assert_eq!(mode, AntigravityLiveSmokeMode::DisposableWorktreeAudit);
    assert_eq!(
        serde_json::to_string(&mode)?,
        r#""disposable_worktree_audit""#
    );
    Ok(())
}

#[test]
fn enablement_uses_disposable_worktree_semantics() -> TestResult {
    let receipt = AntigravityEnablementService.enable(
        AntigravityEnablementState::ReadyDisabled,
        AntigravityEnablementScope::DisposableWorktreeAuditOnly,
        true,
        vec!["bounded disposable audit".to_owned()],
    )?;

    assert_eq!(
        receipt.requested_state,
        AntigravityEnablementState::EnabledForDisposableWorktreeAudit
    );
    assert!(AntigravityEnablementService.receipt_allows_disposable_worktree_audit(&receipt));
    assert!(!AntigravityEnablementService.receipt_allows_disposable_worktree_candidate(&receipt));
    Ok(())
}

#[test]
fn minimal_windows_environment_preserves_home_and_drops_secrets() {
    let input = vec![
        ("USERPROFILE".to_owned(), r"C:\Profiles\Eliot".to_owned()),
        ("HOME".to_owned(), r"C:\Profiles\Eliot".to_owned()),
        (
            "LOCALAPPDATA".to_owned(),
            r"C:\Profiles\Eliot\AppData\Local".to_owned(),
        ),
        ("PATH".to_owned(), r"C:\Windows\System32".to_owned()),
        ("AWS_SECRET_ACCESS_KEY".to_owned(), "hidden".to_owned()),
        ("GITHUB_TOKEN".to_owned(), "hidden".to_owned()),
        ("RUST_LOG".to_owned(), "trace".to_owned()),
    ];
    let filtered = AntigravityEnvPolicyService.minimal_windows_env(&input);
    let names = filtered
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();

    assert!(names.contains(&"USERPROFILE"));
    assert!(names.contains(&"HOME"));
    assert!(names.contains(&"LOCALAPPDATA"));
    assert!(names.contains(&"PATH"));
    assert!(names.contains(&"AGY_CLI_DISABLE_AUTO_UPDATE"));
    assert!(!names.contains(&"AWS_SECRET_ACCESS_KEY"));
    assert!(!names.contains(&"GITHUB_TOKEN"));
    assert!(!names.contains(&"RUST_LOG"));
}

#[test]
// This integration fixture keeps both config documents and their backup/readback
// assertions together so the atomic merge contract remains visible end to end.
#[allow(clippy::too_many_lines)]
fn mcp_config_merge_backs_up_both_home_configs_and_preserves_unknown_data() -> TestResult {
    let root = TempRoot::new("mcp-config")?;
    let home = root.path.join("home");
    let exe = root.path.join("bin").join("eliot-governor.exe");
    fs::create_dir_all(exe.parent().expect("exe parent"))?;
    fs::write(&exe, b"test executable")?;
    let paths = AntigravityMcpConfigService.config_paths(&home);
    let gui_path = paths[0].1.clone();
    fs::create_dir_all(gui_path.parent().expect("gui config parent"))?;
    let existing = json!({
        "theme": "keep-me",
        "futureField": {"enabled": true},
        "mcpServers": {
            "other-server": {
                "command": "other.exe",
                "custom": 7
            },
            "eliot-governor": {
                "disabled": true,
                "futureServerField": "keep",
                "env": {"GITHUB_TOKEN": "must-not-survive"}
            }
        }
    });
    fs::write(&gui_path, serde_json::to_vec_pretty(&existing)?)?;

    let receipts =
        AntigravityMcpConfigService.register_home_for_project(&home, &exe, &root.path)?;
    let statuses = AntigravityMcpConfigService.status(&home);
    let merged: Value = serde_json::from_slice(&fs::read(&gui_path)?)?;

    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().all(|receipt| {
        receipt.command == exe.display().to_string()
            && receipt.args
                == [
                    "mcp",
                    "stdio",
                    "--host",
                    "antigravity",
                    "--profile",
                    "external_auditor",
                    "--instance",
                    "default",
                ]
            && receipt.atomic_write
            && receipt.unknown_fields_preserved
            && receipt.unknown_servers_preserved
            && !receipt.secret_values_written
    }));
    let gui_receipt = receipts
        .iter()
        .find(|receipt| receipt.surface == AntigravityMcpConfigSurface::Gui)
        .expect("GUI registration receipt");
    let backup = Path::new(
        gui_receipt
            .backup_path
            .as_deref()
            .expect("existing GUI config backup"),
    );
    assert!(backup.is_file());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(backup)?)?,
        existing
    );
    assert_eq!(merged.get("theme"), Some(&json!("keep-me")));
    assert_eq!(
        merged.pointer("/mcpServers/other-server/custom"),
        Some(&json!(7))
    );
    assert_eq!(
        merged.pointer("/mcpServers/eliot-governor/futureServerField"),
        Some(&json!("keep"))
    );
    assert!(merged.pointer("/mcpServers/eliot-governor/env").is_none());
    assert_eq!(
        merged.pointer("/mcpServers/eliot-governor/disabled"),
        Some(&json!(false))
    );
    assert_eq!(
        merged.pointer("/mcpServers/eliot-governor/command"),
        Some(&json!(exe.display().to_string()))
    );
    assert_eq!(
        merged.pointer("/mcpServers/eliot-governor/args"),
        Some(&json!([
            "mcp",
            "stdio",
            "--host",
            "antigravity",
            "--profile",
            "external_auditor",
            "--instance",
            "default"
        ]))
    );
    assert!(statuses.iter().all(|status| {
        status.registered
            && status.command_absolute
            && status.profile_args_exact
            && !status.secret_fields_present
            && !status.recursion_detected
    }));
    Ok(())
}

#[test]
fn mcp_config_uses_home_gemini_config() -> TestResult {
    let root = TempRoot::new("mcp-home-paths")?;
    let paths = AntigravityMcpConfigService.config_paths(&root.path);
    assert_eq!(
        paths[0].1,
        root.path
            .join(".gemini")
            .join("config")
            .join("mcp_config.json")
    );
    assert_eq!(
        paths[1].1,
        root.path
            .join(".gemini")
            .join("antigravity-cli")
            .join("mcp_config.json")
    );
    Ok(())
}

#[test]
fn mcp_registration_uses_absolute_eliot_executable() -> TestResult {
    let root = TempRoot::new("mcp-absolute-exe")?;
    let exe = root.path.join("eliot-governor.exe");
    fs::write(&exe, b"test")?;
    let desired = AntigravityMcpConfigService.desired_server_value(&exe)?;
    assert!(
        Path::new(
            desired
                .get("command")
                .and_then(Value::as_str)
                .expect("command"),
        )
        .is_absolute()
    );
    assert!(
        AntigravityMcpConfigService
            .desired_server_value(Path::new("eliot-governor.exe"))
            .is_err()
    );
    Ok(())
}

#[test]
fn mcp_config_denies_antigravity_recursion_and_non_status_tools() {
    let recursive = Path::new(r"C:\Profiles\Eliot\AppData\Local\agy\bin\agy.exe");
    assert!(
        AntigravityMcpConfigService
            .desired_server_value(recursive)
            .is_err()
    );
    assert!(
        AntigravityMcpBoundaryService
            .invocation_receipt("external_auditor", "eliot_antigravity_request", true, false)
            .is_err()
    );
    assert!(
        AntigravityMcpBoundaryService
            .invocation_receipt("default", "eliot_current_state", true, true)
            .is_err()
    );
    assert!(
        AntigravityMcpBoundaryService
            .invocation_receipt("external_auditor", "eliot_current_state", true, true)
            .is_err()
    );
    let receipt = AntigravityMcpBoundaryService
        .invocation_receipt_with_audit(
            "external_auditor",
            "eliot_current_state",
            true,
            Some("reports/antigravity-mcp-invocations/latest.json"),
            true,
        )
        .expect("matching audit event permits receipt");
    assert!(receipt.matching_audit_event);
    assert!(receipt.audit_event_ref.is_some());
}

#[test]
fn official_plugin_install_receipt_uses_default_agent_package_contract() -> TestResult {
    let root = TempRoot::new("official-plugin-receipt")?;
    let home = root.path.join("home");
    let (gui_root, _) = AntigravityOfficialPluginService.plugin_roots(&home);
    fs::create_dir_all(gui_root.join("skills").join("eliot-governor"))?;
    fs::create_dir_all(gui_root.join("rules"))?;
    fs::write(
        gui_root.join("plugin.json"),
        serde_json::to_vec_pretty(&AntigravityOfficialPluginService.manifest_value())?,
    )?;
    fs::write(
        gui_root
            .join("skills")
            .join("eliot-governor")
            .join("SKILL.md"),
        b"skill",
    )?;
    fs::write(gui_root.join("rules").join("boundary.md"), b"bounded")?;
    let status = AntigravityOfficialPluginService.status(&home);

    let failed = AntigravityOfficialPluginService.install_receipt(
        &status,
        false,
        "eliot-antigravity",
        Vec::new(),
    );
    let missing_list = AntigravityOfficialPluginService.install_receipt(
        &status,
        true,
        "No imported plugins.",
        Vec::new(),
    );
    let installed = AntigravityOfficialPluginService.install_receipt(
        &status,
        true,
        "eliot-antigravity enabled",
        vec![gui_root.display().to_string()],
    );

    assert!(!failed.installed);
    assert!(!missing_list.installed);
    assert!(installed.installed);
    assert!(installed.install_command_succeeded);
    assert!(installed.listed_by_agy);
    assert!(!installed.agent_visible);
    assert!(installed.skill_visible);
    Ok(())
}

#[test]
fn official_plugin_list_must_show_eliot_plugin() -> TestResult {
    let root = TempRoot::new("official-plugin-list")?;
    let status = AntigravityOfficialPluginService.status(&root.path);
    let receipt = AntigravityOfficialPluginService.install_receipt(
        &status,
        true,
        "No imported plugins.",
        Vec::new(),
    );
    assert!(!receipt.listed_by_agy);
    assert!(!receipt.installed);
    Ok(())
}

#[test]
fn agent_visibility_requires_installed_agent_not_source_file() -> TestResult {
    let root = TempRoot::new("plugin-source-is-not-install")?;
    let home = root.path.join("home");
    let source = root.path.join("source");
    fs::create_dir_all(source.join("agents").join("eliot-auditor"))?;
    fs::create_dir_all(source.join("skills").join("eliot-governor"))?;
    fs::write(
        source.join("agents").join("eliot-auditor").join("agent.md"),
        b"source only",
    )?;
    fs::write(
        source
            .join("skills")
            .join("eliot-governor")
            .join("SKILL.md"),
        b"source only",
    )?;
    let status = AntigravityOfficialPluginService.status(&home);
    assert!(!status.agent_visible);
    Ok(())
}

#[test]
fn skill_visibility_requires_installed_or_loaded_skill() -> TestResult {
    let root = TempRoot::new("skill-source-is-not-install")?;
    let home = root.path.join("home");
    let source = root
        .path
        .join("source")
        .join("skills")
        .join("eliot-governor");
    fs::create_dir_all(&source)?;
    fs::write(source.join("SKILL.md"), b"source only")?;
    assert!(!AntigravityOfficialPluginService.status(&home).skill_visible);
    Ok(())
}

#[test]
fn mcp_discovery_is_not_invocation_success() {
    let receipt = AntigravityMcpBoundaryService.invocation_receipt_with_audit(
        "external_auditor",
        "eliot_current_state",
        true,
        None,
        true,
    );
    assert!(receipt.is_err());
}

#[test]
fn mcp_invocation_receipt_requires_matching_eliot_audit_event() {
    assert!(
        AntigravityMcpBoundaryService
            .invocation_receipt_with_audit(
                "external_auditor",
                "eliot_current_state",
                true,
                None,
                true,
            )
            .is_err()
    );
    assert!(
        AntigravityMcpBoundaryService
            .invocation_receipt_with_audit(
                "external_auditor",
                "eliot_current_state",
                true,
                Some("reports/antigravity-mcp-invocations/latest.json"),
                true,
            )
            .is_ok()
    );
}

#[test]
fn official_plugin_schema_and_status_are_detected_without_installing() -> TestResult {
    let root = TempRoot::new("official-plugin")?;
    let home = root.path.join("home");
    let (gui_root, cli_root) = AntigravityOfficialPluginService.plugin_roots(&home);
    let manifest = AntigravityOfficialPluginService.manifest_value();
    assert!(AntigravityOfficialPluginService.official_manifest_valid(&manifest));
    assert!(
        !AntigravityOfficialPluginService
            .official_manifest_valid(&json!({"name": "eliot-governor"}))
    );

    fs::create_dir_all(cli_root.join("skills").join("eliot-auditor"))?;
    fs::create_dir_all(cli_root.join("agents").join("eliot-auditor"))?;
    fs::create_dir_all(cli_root.join("rules"))?;
    fs::write(
        cli_root.join("plugin.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    fs::write(cli_root.join("mcp_config.json"), br#"{"mcpServers":{}}"#)?;
    fs::write(
        cli_root
            .join("skills")
            .join("eliot-auditor")
            .join("SKILL.md"),
        b"candidate-only auditor",
    )?;
    fs::write(
        cli_root
            .join("agents")
            .join("eliot-auditor")
            .join("agent.md"),
        b"auditor",
    )?;
    fs::write(
        cli_root.join("rules").join("eliot-governor.md"),
        b"governed",
    )?;

    let status = AntigravityOfficialPluginService.status(&home);
    let receipt = AntigravityOfficialPluginService.status_only_install_receipt(&status);

    assert!(!gui_root.exists());
    assert!(!status.gui_installed);
    assert!(status.cli_installed);
    assert!(status.official_schema_valid);
    assert!(status.mcp_config_present);
    assert!(status.skill_visible);
    assert!(status.agent_visible);
    assert!(status.rule_visible);
    assert!(!receipt.attempted);
    assert!(receipt.installed);
    assert!(receipt.files_written.is_empty());
    Ok(())
}

#[test]
fn public_antigravity_mcp_surface_is_status_only() {
    let tools = ["eliot_current_state", "eliot_recall_l0"];
    let catalog_tools = ["eliot_current_state", "eliot_recall_l0", "eliot_fetch_l2"];
    assert!(AntigravityMcpBoundaryService.exposes_only_governed(&tools, &catalog_tools));
    assert!(AntigravityMcpBoundaryService.no_raw_agy_tools(&tools));
}

#[test]
fn real_agy_run_requires_worktree_lease() -> TestResult {
    let mut request = antigravity_review_request(
        "eliot-governor",
        "g3b-gate",
        AntigravityReviewMode::AuditPlan,
        "inspect",
    );
    request.provider_enabled = true;
    let work_lease = active_work_lease(
        request.project_id,
        request.task_id,
        Path::new("."),
        vec!["src/lib.rs".to_owned()],
    )?;
    request.work_lease_id = Some(work_lease.work_lease_id);
    let missing = real_gate(&request, Some(&work_lease), None);
    assert_eq!(
        missing.decision,
        AntigravityExecutionGateDecisionKind::RequireWorktreeLease
    );

    let worktree_lease =
        active_worktree_lease(&work_lease, WorktreeLeaseId::new_v7(), Path::new("."));
    request.worktree_lease_id = Some(worktree_lease.worktree_lease_id);
    let allowed = real_gate(&request, Some(&work_lease), Some(&worktree_lease));
    assert_eq!(
        allowed.decision,
        AntigravityExecutionGateDecisionKind::AllowRealRun
    );

    let mut mismatched = worktree_lease.clone();
    mismatched.work_lease_id = WorkLeaseId::new_v7();
    let denied = real_gate(&request, Some(&work_lease), Some(&mismatched));
    assert_eq!(
        denied.decision,
        AntigravityExecutionGateDecisionKind::RequireWorktreeLease
    );
    Ok(())
}

#[test]
fn real_agy_run_cwd_must_equal_worktree_path_and_rejects_live_repo() -> TestResult {
    let root = TempRoot::new("runner-cwd")?;
    let live = root.path.join("live");
    let disposable = root.path.join("disposable");
    fs::create_dir_all(&live)?;
    fs::create_dir_all(&disposable)?;
    let mut request = antigravity_review_request(
        "eliot-governor",
        "runner-cwd",
        AntigravityReviewMode::AuditPlan,
        "inspect",
    );
    request.provider_enabled = true;
    let work_lease = active_work_lease(
        request.project_id,
        request.task_id,
        &live,
        vec!["src/lib.rs".to_owned()],
    )?;
    let worktree_lease = active_worktree_lease(&work_lease, WorktreeLeaseId::new_v7(), &disposable);
    request.work_lease_id = Some(work_lease.work_lease_id);
    request.worktree_lease_id = Some(worktree_lease.worktree_lease_id);

    let result = AntigravityRunner.run_real(&request, &contract(), &worktree_lease, &live);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn plan_mode_does_not_remove_worktree_requirement() -> TestResult {
    let mut request = antigravity_review_request(
        "eliot-governor",
        "plan-mode-worktree",
        AntigravityReviewMode::AuditPlan,
        "inspect",
    );
    request.provider_enabled = true;
    let work_lease = active_work_lease(
        request.project_id,
        request.task_id,
        Path::new("."),
        Vec::new(),
    )?;
    request.work_lease_id = Some(work_lease.work_lease_id);
    let gate = real_gate(&request, Some(&work_lease), None);
    assert_eq!(
        gate.decision,
        AntigravityExecutionGateDecisionKind::RequireWorktreeLease
    );
    Ok(())
}

#[test]
fn provider_disabled_after_live_smoke() -> TestResult {
    let enabled = AntigravityEnablementService.enable(
        AntigravityEnablementState::ReadyDisabled,
        AntigravityEnablementScope::DisposableWorktreeAuditOnly,
        true,
        vec!["test".to_owned()],
    )?;
    let disabled =
        AntigravityEnablementService.disable(enabled.requested_state, "live smoke complete");
    assert_eq!(
        disabled.new_state,
        AntigravityEnablementState::DisabledAfterSmoke
    );
    assert!(disabled.created_at >= enabled.created_at);
    Ok(())
}

#[test]
fn disposable_worktree_prompt_requires_marker_and_candidate_final_line() {
    let prompt = AntigravityLiveSmokeService.disposable_worktree_prompt();
    let lower = prompt.to_ascii_lowercase();
    assert!(lower.contains("detached disposable worktree"));
    assert!(lower.contains("controller's live tree"));
    assert!(prompt.contains(AntigravityLiveSmokeService::EXPECTED_MARKER));
    assert!(prompt.contains(AntigravityLiveSmokeService::MCP_CALL_MARKER));
    assert!(prompt.ends_with(AntigravityLiveSmokeService::CANDIDATE_FINAL_LINE));
}

#[test]
fn smoke_result_requires_marker_and_preserves_external_candidate_taint() -> TestResult {
    let mut request = antigravity_review_request(
        "eliot-governor",
        "smoke-result",
        AntigravityReviewMode::AuditPlan,
        "inspect",
    );
    request.provider_enabled = true;
    request.work_lease_id = Some(WorkLeaseId::new_v7());
    request.worktree_lease_id = Some(WorktreeLeaseId::new_v7());
    let output = format!(
        "{} status=ready\n{}\ncandidate observation\n{}",
        AntigravityLiveSmokeService::MCP_CALL_MARKER,
        AntigravityLiveSmokeService::EXPECTED_MARKER,
        AntigravityLiveSmokeService::CANDIDATE_FINAL_LINE
    );
    let mut run = AntigravityRunner.run_fixture(&request, &contract(), Path::new("."))?;
    run.state = AntigravityRunState::Succeeded;
    run.dry_run = false;
    run.stdout_excerpt = output.clone();
    run.response_protocol_receipt = AntigravityResponseProtocolReceipt {
        structured_single_turn: true,
        expected_smoke_marker_seen: true,
        mcp_call_marker_seen: true,
        candidate_final_line_exact: true,
    };
    run.normalized_result = Some(AntigravityTextOutputNormalizer.normalize_text(&request, &output));
    let smoke = AntigravityLiveSmokeService.build_request(
        request.project_id,
        request.work_lease_id.expect("work lease"),
        request.worktree_lease_id,
        AntigravityLiveSmokeMode::DisposableWorktreeAudit,
    );
    let result = AntigravityLiveSmokeService.result_from_run(&smoke, &run);
    let normalized = run.normalized_result.expect("normalized result");

    assert_eq!(result.status, AntigravityLiveSmokeStatus::Passed);
    assert!(result.marker_seen);
    assert!(result.mcp_call_marker_seen);
    assert!(normalized.candidate_only);
    assert_eq!(normalized.taint, TaintClass::ExternalAgent);
    assert!(!normalized.rejected);
    assert!(normalized.write_receipt.is_none());
    Ok(())
}

#[tokio::test]
async fn live_tree_comparison_preserves_preexisting_dirty_state_candidate_taint_and_cleanup()
-> TestResult {
    let root = TempRoot::new("worktree-smoke")?;
    let repo = root.path.join("controller");
    let worktree_root = root.path.join("worktrees");
    let diff_root = root.path.join("diffs");
    initialize_git_repo(&repo)?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let work_lease = active_work_lease(project_id, task_id, &repo, vec!["src/lib.rs".to_owned()])?;
    let mut state = WorkState::default();
    state.leases.push(work_lease.clone());

    let live_file = repo.join("src").join("lib.rs");
    fs::write(
        &live_file,
        concat!(
            "pub fn live() -> &'static str { ",
            r#""dirty-live""#,
            " }\n"
        ),
    )?;
    let live_contents_before = fs::read_to_string(&live_file)?;
    let live_before = AntigravityDisposableWorktreeSmokeService.snapshot_live_tree(&repo)?;
    assert!(!live_before.status_porcelain.trim().is_empty());

    let worktree_lease = AntigravityDisposableWorktreeSmokeService
        .create_disposable_worktree(&mut state, &work_lease, &worktree_root, 10)
        .await?;
    let worktree_path = PathBuf::from(&worktree_lease.worktree_path);
    assert_eq!(worktree_lease.state, WorktreeLeaseState::Active);
    assert!(worktree_path.is_dir());
    assert_eq!(
        git_stdout(&worktree_path, &["rev-parse", "--abbrev-ref", "HEAD"])?,
        "HEAD"
    );

    fs::write(
        worktree_path.join("src").join("lib.rs"),
        concat!(
            "pub fn candidate() -> &'static str { ",
            r#""candidate-only""#,
            " }\n"
        ),
    )?;
    let evidence = AntigravityDisposableWorktreeSmokeService
        .capture_cleanup_and_compare(
            &mut state,
            &live_before,
            worktree_lease.worktree_lease_id,
            &diff_root,
            128 * 1024,
            true,
        )
        .await?;

    assert!(evidence.live_tree_unchanged);
    assert_eq!(
        evidence.candidate_diff_status,
        CandidateDiffStatus::Captured
    );
    assert_eq!(evidence.cleanup_state, WorktreeLeaseState::Cleaned);
    assert!(evidence.marker_seen);
    assert!(evidence.candidate_only);
    assert_eq!(evidence.taint, TaintClass::ExternalAgent);
    assert!(!worktree_path.exists());
    assert_eq!(fs::read_to_string(&live_file)?, live_contents_before);
    assert_eq!(state.candidate_diffs.len(), 1);
    assert!(Path::new(&state.candidate_diffs[0].diff_ref).is_file());
    assert_eq!(
        state
            .worktree_leases
            .iter()
            .find(|lease| lease.worktree_lease_id == worktree_lease.worktree_lease_id)
            .expect("tracked worktree lease")
            .state,
        WorktreeLeaseState::Cleaned
    );
    Ok(())
}

fn real_gate(
    request: &eliot_types::AntigravityReviewRequest,
    work_lease: Option<&WorkLease>,
    worktree_lease: Option<&WorktreeLease>,
) -> eliot_types::AntigravityExecutionGateDecision {
    let resolution = resolved_resolution();
    let probe = AntigravityCapabilityProbeService.probe_from_help("C:/Tools/agy.exe", HELP);
    let contract = AntigravityCommandContractService.build(&resolution, &probe);
    AntigravityExecutionGate.decide(
        request,
        &resolution,
        &probe,
        &contract,
        work_lease,
        worktree_lease,
        true,
        false,
        false,
    )
}

fn contract() -> eliot_types::AntigravityCommandContract {
    let resolution = resolved_resolution();
    let probe = AntigravityCapabilityProbeService.probe_from_help("C:/Tools/agy.exe", HELP);
    AntigravityCommandContractService.build(&resolution, &probe)
}

fn resolved_resolution() -> AntigravityBinaryResolution {
    let binary = std::env::current_exe().expect("current test executable");
    AntigravityBinaryResolver.resolve_known_paths(
        vec![(binary, AntigravityBinaryCandidateSource::WhereAgy)],
        false,
    )
}

fn active_work_lease(
    project_id: ProjectId,
    task_id: TaskId,
    repo_root: &Path,
    write_set: Vec<String>,
) -> TestResult<WorkLease> {
    let repo_root = if repo_root.exists() {
        repo_root.canonicalize()?
    } else {
        repo_root.to_path_buf()
    };
    let now = OffsetDateTime::now_utc();
    let work_lease_id = WorkLeaseId::new_v7();
    Ok(WorkLease {
        work_lease_id,
        work_item_id: WorkItemId::new_v7(),
        agent_session_id: AgentSessionId::new_v7(),
        agent_id: AgentId::new_v7(),
        project_id,
        task_id,
        role: AgentRole::Auditor,
        state: WorkLeaseState::Granted,
        epoch: 1,
        scope: WorkScope {
            repo_root: repo_root.display().to_string(),
            read_set: write_set.clone(),
            write_set,
            verifier_set: vec!["cargo-test".to_owned()],
            authority: AuthorityProfile::bounded_write(),
            risk_tier: RiskTier::Medium,
            max_files: 8,
            requires_active_work_lease: true,
        },
        decision: WorkLeaseDecision {
            kind: WorkLeaseDecisionKind::Granted,
            reason: WorkLeaseDecisionReason::NoConflict,
            message: "test lease".to_owned(),
            work_lease_id: Some(work_lease_id),
            conflicting_lease_ids: Vec::new(),
            expires_at: Some(now + Duration::minutes(30)),
        },
        conflict_refs: Vec::new(),
        granted_at: now,
        expires_at: now + Duration::minutes(30),
        renewed_at: None,
        released_at: None,
        revoked_at: None,
        write_receipt: None,
    })
}

fn active_worktree_lease(
    work_lease: &WorkLease,
    worktree_lease_id: WorktreeLeaseId,
    worktree_path: &Path,
) -> WorktreeLease {
    let now = OffsetDateTime::now_utc();
    WorktreeLease {
        worktree_lease_id,
        project_id: work_lease.project_id,
        task_id: work_lease.task_id,
        work_item_id: work_lease.work_item_id,
        work_lease_id: work_lease.work_lease_id,
        holder_session_id: work_lease.agent_session_id,
        repo_root: work_lease.scope.repo_root.clone(),
        worktree_path: worktree_path.display().to_string(),
        branch_name: format!("detached-{worktree_lease_id}"),
        base_commit: "test-head".to_owned(),
        allowed_read_set: work_lease.scope.read_set.clone(),
        allowed_write_set: work_lease.scope.write_set.clone(),
        state: WorktreeLeaseState::Active,
        issued_at: now,
        expires_at: now + Duration::minutes(30),
        cleaned_at: None,
        write_receipt: None,
    }
}

fn initialize_git_repo(repo: &Path) -> TestResult {
    fs::create_dir_all(repo.join("src"))?;
    git(repo, &["init", "--quiet"])?;
    git(repo, &["config", "user.email", "eliot@example.invalid"])?;
    git(repo, &["config", "user.name", "ELIOT Test"])?;
    fs::write(
        repo.join("src").join("lib.rs"),
        concat!(
            "pub fn baseline() -> &'static str { ",
            r#""baseline""#,
            " }\n"
        ),
    )?;
    git(repo, &["add", "--", "src/lib.rs"])?;
    git(repo, &["commit", "--quiet", "-m", "baseline"])?;
    Ok(())
}

fn git(cwd: &Path, args: &[&str]) -> TestResult {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

fn git_stdout(cwd: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(label: &str) -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!("eliot-g3b-{label}-{}", ProjectId::new_v7()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let controller = self.path.join("controller");
        if controller.is_dir() {
            let _ = Command::new("git")
                .args(["worktree", "prune"])
                .current_dir(&controller)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}
