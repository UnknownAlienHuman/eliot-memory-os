//! Governed MCP tool-surface policy oracle.
//! Architecture: A2.3 — transport policy; A12.3 — MCP surface governance; ARCH-SEC-02 — tool exposure boundary; A13.6 — audit surface.
//! Implementation: R9 — test oracle; I7.6 — tool allowlist verification; I7.7 — negative tool denial.
//! Scope: test-oracle and transport-policy only; no production, semantic, Kernel, Governor, Store, shell, Git, command execution, authority, default/retry/mint ownership.

use super::*;

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_tools_list_contains_only_governed_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    assert_eq!(
        names,
        vec![
            "eliot_task_contract_create",
            "eliot_task_state",
            "eliot_task_action_request",
            "eliot_task_observation_record",
            "eliot_agent_candidate_submit",
            "eliot_task_verification_run",
            "eliot_host_session_status",
            "eliot_project_identity",
            "eliot_current_state",
            "eliot_recall_l0",
            "eliot_fetch_l2",
            "eliot_compile_packet_l3",
            "eliot_understanding_outcome_record",
            "eliot_memory_influence_trace",
            "eliot_context_cargo_receipt",
            "eliot_task_meaning",
            "eliot_memory_corpus_profile",
            "eliot_experience_recall",
            "eliot_experience_reinstate",
            "eliot_experience_form",
            "eliot_experience_abstract",
            "eliot_experience_maturity_transition",
            "eliot_negative_transfer_record",
            "eliot_cognitive_lab_evaluate",
            "eliot_cognitive_failure_localization_record",
            "eliot_submit_understanding_proof",
            "eliot_cognitive_gate",
            "eliot_submit_completion_proof",
            "eliot_codecortex_scan",
            "eliot_codecortex_latest",
            "eliot_external_review_providers",
            "eliot_external_review_request",
            "eliot_external_review_job_status",
            "eliot_external_review_result",
            "eliot_external_review_report",
            "eliot_external_review_run_mock",
            "eliot_agent_delegate",
            "eliot_agent_job_claim",
            "eliot_agent_job_status",
            "eliot_agent_result_submit",
            "eliot_agent_result_finalize",
            "eliot_agent_result",
            "eliot_agent_result_disposition",
            "eliot_delegate_review",
            "eliot_delegate_status",
            "eliot_delegate_result",
            "eliot_delegate_report",
            "eliot_delegation_calibration_status",
            "eliot_delegation_calibration_report",
            "eliot_delegation_policy_candidate",
            "eliot_delegation_promotion_status",
            "eliot_antigravity_visibility",
            "eliot_antigravity_mcp_status",
            "eliot_antigravity_plugin_status",
            "eliot_antigravity_live_smoke_status",
            "eliot_antigravity_real_report",
            "eliot_eval_case_list",
            "eliot_eval_suite_list",
            "eliot_eval_run",
            "eliot_eval_verdict",
            "eliot_eval_report",
            "eliot_eval_smoke",
            "eliot_eval_coverage",
            "eliot_eval_baseline_list",
            "eliot_eval_compare",
            "eliot_eval_gate",
            "eliot_eval_profiles",
            "eliot_eval_trend",
            "eliot_verify_profiles",
            "eliot_verify_inventory",
            "eliot_verify_plan",
            "eliot_verify_report",
            "eliot_verify_cost_report",
            "eliot_verify_last_verdict",
            "eliot_metrics_registry",
            "eliot_metrics_dashboard",
            "eliot_metrics_slo",
            "eliot_metrics_latency",
            "eliot_metrics_cost",
            "eliot_metrics_quality",
            "eliot_metrics_report",
            "eliot_trace_completeness",
            "eliot_replay_case_create",
            "eliot_replay_set_create",
            "eliot_replay_run",
            "eliot_replay_report",
            "eliot_sleep_run",
            "eliot_sleep_report",
            "eliot_dream_candidate_create",
            "eliot_dream_report",
            "eliot_meta_experiment_run",
            "eliot_meta_experiment_disposition",
            "eliot_l11_status",
            "eliot_action_plan",
            "eliot_action_lease_status",
            "eliot_patch_preflight",
            "eliot_patch_apply",
            "eliot_patch_status",
            "eliot_verifier_status",
            "eliot_work_create",
            "eliot_work_claim",
            "eliot_work_status",
            "eliot_work_renew",
            "eliot_work_release",
            "eliot_work_conflicts",
            "eliot_worktree_create",
            "eliot_worktree_status",
            "eliot_worktree_capture_diff",
            "eliot_worktree_review",
            "eliot_worktree_cleanup",
            "eliot_blackboard_add",
            "eliot_blackboard_list",
            "eliot_blackboard_ack",
            "eliot_mailbox_send",
            "eliot_mailbox_inbox",
            "eliot_mailbox_ack",
            "eliot_recovery_scan",
            "eliot_collective_trace",
            "eliot_runtime_status",
            "eliot_autonomy_run_status",
            "eliot_runtime_health",
            "eliot_module_list",
            "eliot_module_health",
            "eliot_logs_query",
            "eliot_service_status",
            "eliot_ipc_status",
            "eliot_readiness_report",
            "eliot_startup_recovery_report",
            "eliot_credentials_report",
            "eliot_adapter_list",
            "eliot_adapter_health",
            "eliot_adapter_inspect",
            "eliot_adapter_execute_test",
            "eliot_doctor_report",
            "eliot_data_root_status",
            "eliot_backup_report",
            "eliot_restore_report",
            "eliot_blob_report",
            "eliot_maintenance_status",
            "eliot_incident_list",
            "eliot_memory_curation_preview",
            "eliot_memory_lifecycle_status",
            "eliot_memory_lifecycle_propose",
            "eliot_memory_lifecycle_vitality",
            "eliot_memory_lifecycle_gravity",
            "eliot_memory_lifecycle_influence",
            "eliot_skill_list",
            "eliot_skill_inspect",
            "eliot_skill_estimate",
            "eliot_skill_filter",
            "eliot_skill_influence",
            "eliot_skill_execution_proof",
            "eliot_skill_create_candidate",
            "eliot_skill_curator_run",
            "eliot_skill_curator_proposals",
            "eliot_skill_curator_inspect",
            "eliot_skill_curator_report",
            "eliot_skill_curator_gate",
            "eliot_autonomy_contract_write",
            "eliot_autonomy_approval_request",
            "eliot_autonomy_runtime_action",
        ]
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_external_review_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_external_review_providers",
        "eliot_external_review_request",
        "eliot_external_review_job_status",
        "eliot_external_review_result",
        "eliot_external_review_report",
        "eliot_external_review_run_mock",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("external_review"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_external_review_providers"
                    | "eliot_external_review_request"
                    | "eliot_external_review_job_status"
                    | "eliot_external_review_result"
                    | "eliot_external_review_report"
                    | "eliot_external_review_run_mock"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_real_provider_raw_exec_secret_patch_truth_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_run_gemini",
        "eliot_run_antigravity",
        "eliot_raw_exec",
        "eliot_raw_secret",
        "eliot_raw_patch",
        "eliot_raw_truth",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    assert!(names.iter().all(|name| {
        [
            "run_gemini",
            "run_antigravity",
            "raw_exec",
            "raw_secret",
            "raw_patch",
            "raw_truth",
        ]
        .iter()
        .all(|needle| !name.contains(needle))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_antigravity_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_antigravity_visibility",
        "eliot_antigravity_mcp_status",
        "eliot_antigravity_plugin_status",
        "eliot_antigravity_live_smoke_status",
        "eliot_antigravity_real_report",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("antigravity") || name.contains("agy"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_antigravity_visibility"
                    | "eliot_antigravity_mcp_status"
                    | "eliot_antigravity_plugin_status"
                    | "eliot_antigravity_live_smoke_status"
                    | "eliot_antigravity_real_report"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_raw_agy_agymcp_login_install_shell_secret_patch_truth_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    assert!(names.iter().all(|name| {
        [
            "raw_agy",
            "agy_mcp",
            "agymcp",
            "login",
            "install",
            "shell",
            "secret",
            "patch_truth",
            "truth",
        ]
        .iter()
        .all(|needle| !name.contains(needle))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_antigravity_auditor_profile_is_narrow_and_audited() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start_with_profile("external_auditor")?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    assert!(names.contains(&"eliot_runtime_status".to_owned()));
    assert!(names.contains(&"eliot_codecortex_latest".to_owned()));
    assert!(names.contains(&"eliot_antigravity_visibility".to_owned()));
    assert!(names.iter().all(|name| {
        ![
            "eliot_antigravity_request",
            "eliot_antigravity_status",
            "eliot_patch_apply",
            "eliot_action_plan",
            "eliot_submit_completion_proof",
            "eliot_worktree_create",
            "eliot_logs_query",
        ]
        .contains(&name.as_str())
    }));

    let runtime = client.tool_call(2, "eliot_runtime_status", &json!({}))?;
    assert_eq!(
        runtime.get("component").and_then(Value::as_str),
        Some("runtime_status")
    );
    for field in ["runtime_id", "auth_generation"] {
        let value = runtime
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("runtime status missing {field}"))?;
        uuid::Uuid::parse_str(value)?;
    }
    let receipt = test_runtime_root()
        .join("reports")
        .join("antigravity-mcp-invocations")
        .join("latest.json");
    let receipt: Value = serde_json::from_reader(fs::File::open(receipt)?)?;
    assert_eq!(
        receipt.get("tool_name").and_then(Value::as_str),
        Some("eliot_runtime_status")
    );
    assert_eq!(
        receipt.get("succeeded").and_then(Value::as_bool),
        Some(true)
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn antigravity_auditor_profile_has_minimal_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start_with_profile("external_auditor")?;
    let names = tool_names(&client.request(1, "tools/list", &json!({}))?)?;
    assert_eq!(
        names,
        [
            "eliot_task_state",
            "eliot_agent_candidate_submit",
            "eliot_host_session_status",
            "eliot_project_identity",
            "eliot_current_state",
            "eliot_recall_l0",
            "eliot_fetch_l2",
            "eliot_compile_packet_l3",
            "eliot_task_meaning",
            "eliot_memory_corpus_profile",
            "eliot_experience_recall",
            "eliot_experience_reinstate",
            "eliot_codecortex_latest",
            "eliot_external_review_report",
            "eliot_agent_result",
            "eliot_antigravity_visibility",
            "eliot_antigravity_mcp_status",
            "eliot_antigravity_plugin_status",
            "eliot_antigravity_live_smoke_status",
            "eliot_antigravity_real_report",
            "eliot_l11_status",
            "eliot_runtime_status",
            "eliot_autonomy_run_status",
            "eliot_runtime_health",
            "eliot_doctor_report",
            "eliot_memory_curation_preview",
            "eliot_memory_lifecycle_vitality",
            "eliot_memory_lifecycle_gravity",
            "eliot_skill_list",
            "eliot_skill_inspect",
        ]
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn antigravity_auditor_profile_denies_antigravity_recursion() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start_with_profile("external_auditor")?;
    let names = tool_names(&client.request(1, "tools/list", &json!({}))?)?;
    assert!(names.iter().all(|name| {
        !matches!(
            name.as_str(),
            "eliot_antigravity_request"
                | "eliot_antigravity_run"
                | "eliot_antigravity_enable"
                | "eliot_antigravity_disable"
                | "eliot_antigravity_status"
        )
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn antigravity_auditor_profile_denies_patch_runner() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start_with_profile("external_auditor")?;
    let names = tool_names(&client.request(1, "tools/list", &json!({}))?)?;
    assert!(names.iter().all(|name| {
        !name.contains("patch") && !name.contains("action") && !name.contains("worktree")
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn antigravity_auditor_profile_denies_completion_authority() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start_with_profile("external_auditor")?;
    let names = tool_names(&client.request(1, "tools/list", &json!({}))?)?;
    assert!(names.iter().all(|name| !name.contains("completion")));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn antigravity_auditor_profile_denies_credentials() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start_with_profile("external_auditor")?;
    let names = tool_names(&client.request(1, "tools/list", &json!({}))?)?;
    assert!(names.iter().all(|name| {
        !name.contains("credential")
            && !name.contains("secret")
            && !name.contains("token")
            && !name.contains("login")
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_lifecycle_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_memory_lifecycle_status",
        "eliot_memory_lifecycle_propose",
        "eliot_memory_lifecycle_vitality",
        "eliot_memory_lifecycle_gravity",
        "eliot_memory_lifecycle_influence",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("memory_lifecycle"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_memory_lifecycle_status"
                    | "eliot_memory_lifecycle_propose"
                    | "eliot_memory_lifecycle_vitality"
                    | "eliot_memory_lifecycle_gravity"
                    | "eliot_memory_lifecycle_influence"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_delete_purge_raw_db_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_memory_delete",
        "eliot_memory_purge",
        "eliot_raw_db_update",
        "eliot_raw_sql",
        "eliot_force_truth_change",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    assert!(names.iter().all(|name| {
        ["delete", "purge", "raw_db", "raw_sql", "force_truth"]
            .iter()
            .all(|needle| !name.contains(needle))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_eval_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_eval_case_list",
        "eliot_eval_suite_list",
        "eliot_eval_run",
        "eliot_eval_verdict",
        "eliot_eval_report",
        "eliot_eval_smoke",
        "eliot_eval_coverage",
        "eliot_eval_baseline_list",
        "eliot_eval_compare",
        "eliot_eval_gate",
        "eliot_eval_profiles",
        "eliot_eval_trend",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.starts_with("eliot_eval_"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_eval_case_list"
                    | "eliot_eval_suite_list"
                    | "eliot_eval_run"
                    | "eliot_eval_verdict"
                    | "eliot_eval_report"
                    | "eliot_eval_smoke"
                    | "eliot_eval_coverage"
                    | "eliot_eval_baseline_list"
                    | "eliot_eval_compare"
                    | "eliot_eval_gate"
                    | "eliot_eval_profiles"
                    | "eliot_eval_trend"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_eval_gate_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_eval_coverage",
        "eliot_eval_baseline_list",
        "eliot_eval_compare",
        "eliot_eval_gate",
        "eliot_eval_profiles",
        "eliot_eval_trend",
        "eliot_eval_report",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.starts_with("eliot_eval_"))
            .all(|name| {
                matches!(
                    name.as_str(),
                    "eliot_eval_case_list"
                        | "eliot_eval_suite_list"
                        | "eliot_eval_run"
                        | "eliot_eval_verdict"
                        | "eliot_eval_report"
                        | "eliot_eval_smoke"
                        | "eliot_eval_coverage"
                        | "eliot_eval_baseline_list"
                        | "eliot_eval_compare"
                        | "eliot_eval_gate"
                        | "eliot_eval_profiles"
                        | "eliot_eval_trend"
                )
            })
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_mutate_promote_raw_eval_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_eval_mutate",
        "eliot_eval_promote",
        "eliot_eval_raw",
        "eliot_eval_raw_sql",
        "eliot_eval_provider_run",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("eval"))
            .all(|name| {
                [
                    "baseline_create",
                    "fixture_mutate",
                    "suite_unfreeze",
                    "gate_override",
                    "policy_promote",
                    "raw_fixture_write",
                    "mutate",
                    "promote",
                    "raw",
                    "sql",
                    "db",
                    "provider",
                    "gemini",
                    "antigravity",
                ]
                .iter()
                .all(|needle| !name.contains(needle))
            })
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_baseline_create_fixture_mutate_override_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_eval_baseline_create",
        "eliot_eval_fixture_mutate",
        "eliot_eval_suite_unfreeze",
        "eliot_eval_gate_override",
        "eliot_eval_policy_promote",
        "eliot_eval_raw_fixture_write",
        "eliot_raw_sql",
        "eliot_raw_db",
        "eliot_raw_shell",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    assert!(names.iter().all(|name| {
        [
            "baseline_create",
            "fixture_mutate",
            "suite_unfreeze",
            "gate_override",
            "policy_promote",
            "raw_fixture_write",
            "raw_sql",
            "raw_db",
            "raw_shell",
        ]
        .iter()
        .all(|needle| !name.contains(needle))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_safe_verify_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_verify_profiles",
        "eliot_verify_inventory",
        "eliot_verify_plan",
        "eliot_verify_report",
        "eliot_verify_cost_report",
        "eliot_verify_last_verdict",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("verify"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_verify_profiles"
                    | "eliot_verify_inventory"
                    | "eliot_verify_plan"
                    | "eliot_verify_report"
                    | "eliot_verify_cost_report"
                    | "eliot_verify_last_verdict"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_raw_command_or_override_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_verify_run_raw_command",
        "eliot_verify_run_profile",
        "eliot_shell",
        "eliot_raw_sql",
        "eliot_raw_db",
        "eliot_test_ignore_failure",
        "eliot_test_delete",
        "eliot_profile_override_done",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    assert!(names.iter().all(|name| {
        [
            "raw_command",
            "raw_shell",
            "raw_exec",
            "raw_git",
            "raw_rg",
            "raw_ast",
            "raw_file",
            "raw_sql",
            "raw_db",
            "ignore_failure",
            "test_delete",
            "override_done",
            "profile_override",
            "run_profile",
        ]
        .iter()
        .all(|needle| !name.contains(needle))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_safe_metrics_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_metrics_registry",
        "eliot_metrics_dashboard",
        "eliot_metrics_slo",
        "eliot_metrics_latency",
        "eliot_metrics_cost",
        "eliot_metrics_quality",
        "eliot_metrics_report",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("metrics"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_metrics_registry"
                    | "eliot_metrics_dashboard"
                    | "eliot_metrics_slo"
                    | "eliot_metrics_latency"
                    | "eliot_metrics_cost"
                    | "eliot_metrics_quality"
                    | "eliot_metrics_report"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_raw_ingest_remote_export_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_metrics_record_raw",
        "eliot_metrics_ingest_raw",
        "eliot_metrics_raw_payload",
        "eliot_metrics_export_remote",
        "eliot_metrics_secret_metric",
        "eliot_metrics_raw_sql",
        "eliot_metrics_raw_db",
        "eliot_metrics_raw_shell",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    assert!(names.iter().all(|name| {
        [
            "record_raw",
            "ingest_raw",
            "raw_payload",
            "logs_raw",
            "secret_metric",
            "export_remote",
            "raw_sql",
            "raw_db",
            "raw_shell",
        ]
        .iter()
        .all(|needle| !name.contains(needle))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_action_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    assert!(names.contains(&"eliot_action_plan".to_owned()));
    assert!(names.contains(&"eliot_action_lease_status".to_owned()));
    assert!(names.contains(&"eliot_task_action_request".to_owned()));
    assert!(names.contains(&"eliot_autonomy_runtime_action".to_owned()));
    assert!(
        names
            .iter()
            .filter(|name| name.contains("action"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_action_plan"
                    | "eliot_action_lease_status"
                    | "eliot_task_action_request"
                    | "eliot_autonomy_runtime_action"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_work_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_work_create",
        "eliot_work_claim",
        "eliot_work_status",
        "eliot_work_renew",
        "eliot_work_release",
        "eliot_work_conflicts",
        "eliot_worktree_create",
        "eliot_worktree_status",
        "eliot_worktree_capture_diff",
        "eliot_worktree_review",
        "eliot_worktree_cleanup",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("work"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_work_create"
                    | "eliot_work_claim"
                    | "eliot_work_status"
                    | "eliot_work_renew"
                    | "eliot_work_release"
                    | "eliot_work_conflicts"
                    | "eliot_worktree_create"
                    | "eliot_worktree_status"
                    | "eliot_worktree_capture_diff"
                    | "eliot_worktree_review"
                    | "eliot_worktree_cleanup"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_worktree_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_worktree_create",
        "eliot_worktree_status",
        "eliot_worktree_capture_diff",
        "eliot_worktree_review",
        "eliot_worktree_cleanup",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("worktree"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_worktree_create"
                    | "eliot_worktree_status"
                    | "eliot_worktree_capture_diff"
                    | "eliot_worktree_review"
                    | "eliot_worktree_cleanup"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_tools_include_codecortex_only_governed() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    assert!(names.contains(&"eliot_codecortex_scan".to_owned()));
    assert!(names.contains(&"eliot_codecortex_latest".to_owned()));
    assert!(
        names
            .iter()
            .filter(|name| name.contains("codecortex"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_codecortex_scan" | "eliot_codecortex_latest"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_tools_include_only_governed_replay_surfaces() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_trace_completeness",
        "eliot_replay_case_create",
        "eliot_replay_set_create",
        "eliot_replay_run",
        "eliot_replay_report",
        "eliot_sleep_run",
        "eliot_sleep_report",
        "eliot_dream_candidate_create",
        "eliot_dream_report",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| {
                name.contains("trace")
                    || name.contains("replay")
                    || name.contains("sleep")
                    || name.contains("dream")
            })
            .all(|name| matches!(
                name.as_str(),
                "eliot_collective_trace"
                    | "eliot_memory_influence_trace"
                    | "eliot_trace_completeness"
                    | "eliot_replay_case_create"
                    | "eliot_replay_set_create"
                    | "eliot_replay_run"
                    | "eliot_replay_report"
                    | "eliot_sleep_run"
                    | "eliot_sleep_report"
                    | "eliot_dream_candidate_create"
                    | "eliot_dream_report"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_raw_replay_promotion_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for denied in [
        "promote",
        "apply",
        "force",
        "raw",
        "shell",
        "sql",
        "db",
        "truth",
        "policy_write",
    ] {
        assert!(
            names
                .iter()
                .filter(|name| {
                    name.contains("replay") || name.contains("sleep") || name.contains("dream")
                })
                .all(|name| !name.contains(denied)),
            "unexpected J0 tool containing {denied}"
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_tools_include_collective_only_governed() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_blackboard_add",
        "eliot_blackboard_list",
        "eliot_blackboard_ack",
        "eliot_mailbox_send",
        "eliot_mailbox_inbox",
        "eliot_mailbox_ack",
        "eliot_recovery_scan",
        "eliot_collective_trace",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| {
                name.contains("blackboard")
                    || name.contains("mailbox")
                    || name.contains("recovery")
                    || name.contains("collective")
            })
            .all(|name| matches!(
                name.as_str(),
                "eliot_blackboard_add"
                    | "eliot_blackboard_list"
                    | "eliot_blackboard_ack"
                    | "eliot_mailbox_send"
                    | "eliot_mailbox_inbox"
                    | "eliot_mailbox_ack"
                    | "eliot_recovery_scan"
                    | "eliot_collective_trace"
                    | "eliot_startup_recovery_report"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_runtime_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_runtime_status",
        "eliot_autonomy_run_status",
        "eliot_runtime_health",
        "eliot_module_list",
        "eliot_module_health",
        "eliot_logs_query",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| {
                name.contains("runtime")
                    || name.contains("module")
                    || name.contains("logs")
                    || name.contains("daemon")
                    || name.contains("ipc")
            })
            .all(|name| matches!(
                name.as_str(),
                "eliot_runtime_status"
                    | "eliot_autonomy_run_status"
                    | "eliot_autonomy_runtime_action"
                    | "eliot_runtime_health"
                    | "eliot_module_list"
                    | "eliot_module_health"
                    | "eliot_logs_query"
                    | "eliot_ipc_status"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_raw_runtime_shell_db_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_daemon_stop",
        "eliot_raw_log_file_read",
        "eliot_spawn_module",
        "eliot_run_module_command",
        "eliot_raw_ipc",
        "eliot_raw_shell",
        "eliot_raw_db",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    assert!(names.iter().all(|name| {
        ["raw", "shell", "git", "db", "spawn"]
            .iter()
            .all(|needle| !name.contains(needle))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_safe_h1_service_status_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_service_status",
        "eliot_ipc_status",
        "eliot_readiness_report",
        "eliot_startup_recovery_report",
        "eliot_credentials_report",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| {
                name.contains("service")
                    || name.contains("ipc")
                    || name.contains("readiness")
                    || name.contains("startup")
                    || name.contains("credential")
            })
            .all(|name| matches!(
                name.as_str(),
                "eliot_service_status"
                    | "eliot_ipc_status"
                    | "eliot_readiness_report"
                    | "eliot_startup_recovery_report"
                    | "eliot_credentials_report"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_h1_service_control_or_secret_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_service_install",
        "eliot_service_uninstall",
        "eliot_service_start",
        "eliot_service_stop",
        "eliot_service_restart",
        "eliot_ipc_smoke",
        "eliot_ipc_handshake",
        "eliot_ipc_send",
        "eliot_ipc_raw",
        "eliot_credentials_get",
        "eliot_credentials_resolve",
        "eliot_secret_read",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_safe_recovery_reports() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_doctor_report",
        "eliot_data_root_status",
        "eliot_backup_report",
        "eliot_restore_report",
        "eliot_blob_report",
        "eliot_maintenance_status",
        "eliot_incident_list",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| {
                name.contains("doctor")
                    || name.contains("data_root")
                    || name.contains("backup")
                    || name.contains("restore")
                    || name.contains("blob")
                    || name.contains("maintenance")
                    || name.contains("incident")
            })
            .all(|name| matches!(
                name.as_str(),
                "eliot_doctor_report"
                    | "eliot_data_root_status"
                    | "eliot_backup_report"
                    | "eliot_restore_report"
                    | "eliot_blob_report"
                    | "eliot_maintenance_status"
                    | "eliot_incident_list"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_dangerous_restore_or_delete_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_backup_run",
        "eliot_backup_create",
        "eliot_restore_run",
        "eliot_restore_apply",
        "eliot_import_run",
        "eliot_import_apply",
        "eliot_blob_gc_run",
        "eliot_blob_delete",
        "eliot_incident_open",
        "eliot_incident_close",
        "eliot_data_root_write",
        "eliot_maintenance_run",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    assert!(names.iter().all(|name| {
        [
            "backup_run",
            "backup_create",
            "restore_run",
            "restore_apply",
            "import_run",
            "import_apply",
            "blob_gc_run",
            "blob_delete",
            "incident_open",
            "incident_close",
            "data_root_write",
            "maintenance_run",
            "delete",
            "apply_restore",
        ]
        .iter()
        .all(|needle| !name.contains(needle))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_adapter_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_adapter_list",
        "eliot_adapter_health",
        "eliot_adapter_inspect",
        "eliot_adapter_execute_test",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("adapter"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_adapter_list"
                    | "eliot_adapter_health"
                    | "eliot_adapter_inspect"
                    | "eliot_adapter_execute_test"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_external_agent_or_raw_exec_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for forbidden in [
        "eliot_adapter_execute_raw",
        "eliot_run_external_agent",
        "eliot_run_gemini",
        "eliot_run_antigravity",
        "eliot_spawn_process",
        "eliot_shell",
        "eliot_git",
        "eliot_file_write",
        "eliot_raw_mcp",
    ] {
        assert!(!names.contains(&forbidden.to_owned()));
    }
    assert!(names.iter().all(|name| {
        [
            "execute_raw",
            "external_agent",
            "run_gemini",
            "run_antigravity",
            "spawn_process",
            "shell",
            "git",
            "file_write",
            "raw_mcp",
        ]
        .iter()
        .all(|needle| !name.contains(needle))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_patch_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_patch_preflight",
        "eliot_patch_apply",
        "eliot_patch_status",
        "eliot_verifier_status",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("patch") || name.contains("verifier"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_patch_preflight"
                    | "eliot_patch_apply"
                    | "eliot_patch_status"
                    | "eliot_verifier_status"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_no_raw_sql_tool() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    assert!(names.iter().all(|name| {
        name == "eliot_logs_query"
            || (!name.contains("sql")
                && !name.contains("query")
                && !name.contains("raw")
                && !name.contains("db"))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_external_agent_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    assert!(names.iter().all(|name| {
        if name.contains("antigravity") {
            matches!(
                name.as_str(),
                "eliot_antigravity_visibility"
                    | "eliot_antigravity_mcp_status"
                    | "eliot_antigravity_plugin_status"
                    | "eliot_antigravity_live_smoke_status"
                    | "eliot_antigravity_real_report"
            )
        } else {
            [
                "external_agent",
                "subagent",
                "gemini",
                "qdrant",
                "graphiti",
                "zep",
            ]
            .iter()
            .all(|needle| !name.contains(needle))
        }
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_skill_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    assert!(
        names
            .iter()
            .filter(|name| name.contains("skill"))
            .all(|name| {
                matches!(
                    name.as_str(),
                    "eliot_skill_list"
                        | "eliot_skill_inspect"
                        | "eliot_skill_estimate"
                        | "eliot_skill_filter"
                        | "eliot_skill_influence"
                        | "eliot_skill_execution_proof"
                        | "eliot_skill_create_candidate"
                        | "eliot_skill_curator_run"
                        | "eliot_skill_curator_proposals"
                        | "eliot_skill_curator_inspect"
                        | "eliot_skill_curator_report"
                        | "eliot_skill_curator_gate"
                )
            })
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_only_governed_curator_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    for tool in [
        "eliot_skill_curator_run",
        "eliot_skill_curator_proposals",
        "eliot_skill_curator_inspect",
        "eliot_skill_curator_report",
        "eliot_skill_curator_gate",
    ] {
        assert!(names.contains(&tool.to_owned()));
    }
    assert!(
        names
            .iter()
            .filter(|name| name.contains("skill_curator"))
            .all(|name| matches!(
                name.as_str(),
                "eliot_skill_curator_run"
                    | "eliot_skill_curator_proposals"
                    | "eliot_skill_curator_inspect"
                    | "eliot_skill_curator_report"
                    | "eliot_skill_curator_gate"
            ))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_apply_force_delete_raw_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    let denied = [
        "skill_curator_apply",
        "force_promote",
        "force_activate",
        "delete",
        "merge_raw",
        "patch_raw",
        "raw_skill",
        "raw_file",
        "raw_sql",
        "raw_db",
    ];
    assert!(
        names
            .iter()
            .all(|name| denied.iter().all(|needle| !name.contains(needle)))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_force_activate_delete_raw_skill_tools() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    let denied = [
        "force_activate",
        "promote_auto",
        "delete",
        "run_executable",
        "raw_skill",
        "raw_file",
        "raw_sql",
    ];
    assert!(
        names
            .iter()
            .all(|name| denied.iter().all(|needle| !name.contains(needle)))
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_no_raw_shell_rg_astgrep_git() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    let denied_segments = ["raw", "shell", "rg", "astgrep", "git"];
    let denied_compounds = [
        "ast_grep",
        "file_read",
        "read_file",
        "file_write",
        "write_file",
        "run_command",
    ];
    assert!(names.iter().all(|name| {
        denied_segments
            .iter()
            .all(|denied| !name.split('_').any(|segment| segment == *denied))
            && denied_compounds.iter().all(|denied| !name.contains(denied))
    }));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_exposes_no_raw_shell_or_git() -> TestResult {
    let _guard = TestLock::acquire()?;
    let mut client = McpClient::start()?;
    let response = client.request(1, "tools/list", &json!({}))?;
    let names = tool_names(&response)?;

    assert!(names.iter().all(|name| {
        ["raw", "shell", "git", "run_command"]
            .iter()
            .all(|needle| !name.contains(needle))
    }));
    Ok(())
}
