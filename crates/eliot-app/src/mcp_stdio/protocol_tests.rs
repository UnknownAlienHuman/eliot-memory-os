use super::catalog::{memory_lifecycle_tool_definitions, replay_tool_definitions};
use super::*;

#[test]
fn governor_bound_scope_defaults_ids_and_rejects_scope_spoofing() -> Result<()> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = SessionId::new_v7();
    let context = AuthenticatedRequestContext {
        session_id,
        bound_project_id: Some(project_id),
        bound_task_id: Some(task_id),
    };

    let task_state = enforce_bound_tool_scope(context, "eliot_task_state", json!({}))?;
    assert_eq!(task_state["project_id"], json!(project_id));
    assert_eq!(task_state["task_id"], json!(task_id));

    let recall = enforce_bound_tool_scope(
        context,
        "eliot_recall_l0",
        json!({
            "query": "neutral memory question"
        }),
    )?;
    assert_eq!(recall["project_id"], json!(project_id));
    assert!(recall.get("task_id").is_none());

    let skill_list = enforce_bound_tool_scope(context, "eliot_skill_list", json!({}))?;
    assert_eq!(skill_list["project"], json!(project_id));

    let matching = enforce_bound_tool_scope(
        context,
        "eliot_compile_packet_l3",
        json!({
            "project_id": project_id,
            "task_id": task_id
        }),
    )?;
    assert_eq!(matching["project_id"], json!(project_id));
    assert_eq!(matching["task_id"], json!(task_id));

    let project_error = enforce_bound_tool_scope(
        context,
        "eliot_recall_l0",
        json!({
            "project_id": ProjectId::new_v7(),
            "query": "wrong scope"
        }),
    )
    .err()
    .context("a bound host must not spoof project scope")?;
    assert!(project_error.to_string().contains("PROJECT_SCOPE_MISMATCH"));

    let task_error = enforce_bound_tool_scope(
        context,
        "eliot_task_state",
        json!({
            "task_id": TaskId::new_v7()
        }),
    )
    .err()
    .context("a bound host must not spoof task scope")?;
    assert!(task_error.to_string().contains("TASK_SCOPE_MISMATCH"));

    let unbound = enforce_bound_tool_scope(
        AuthenticatedRequestContext {
            session_id: SessionId::new_v7(),
            bound_project_id: None,
            bound_task_id: None,
        },
        "eliot_task_state",
        json!({}),
    )?;
    assert_eq!(unbound, json!({}));

    let agent_session_id = AgentSessionId::from_uuid(session_id.as_uuid());
    let mut broker_state = eliot_types::DelegationState::default();
    HostBrokerService.register_session(
        &mut broker_state,
        agent_session_id,
        AgentHostId::OpenCode,
        "OpenCode".to_owned(),
        "bound-scope-test".to_owned(),
        AgentCapabilityEnvelope::default(),
    )?;
    HostBrokerService.bind_session_scope(
        &mut broker_state,
        agent_session_id,
        project_id,
        task_id,
    )?;
    HostBrokerService.grant_role(
        &mut broker_state,
        task_id,
        agent_session_id,
        AgentRole::Implementer,
        vec!["mcp_stdio".to_owned()],
        30,
    )?;
    validate_canonical_host_scope(&broker_state, session_id, project_id, task_id)?;
    let daemon_project_error =
        validate_canonical_host_scope(&broker_state, session_id, ProjectId::new_v7(), task_id)
            .err()
            .context("daemon must reject a handshake project outside canonical authority")?;
    assert!(
        daemon_project_error
            .to_string()
            .contains("PROJECT_SCOPE_MISMATCH")
    );
    Ok(())
}

#[test]
fn cold_observe_candidate_is_fetchable_but_not_cue_indexed() {
    let mut payload = json!({
        "record_kind": "observation_candidate",
        "candidate_only": true,
        "capture_first": true,
        "candidate_disposition": "cold"
    });
    attach_observe_cue_bindings(&mut payload, true, &[]);
    assert_eq!(payload["record_kind"], "observation_candidate");
    assert_eq!(payload["candidate_only"], true);
    assert_eq!(payload["cue_binding_state"], "cold");
    assert!(payload.get("cue_bindings").is_none());

    let mut bound_payload = json!({
        "record_kind": "observation_candidate",
        "candidate_only": true,
        "capture_first": true,
        "candidate_disposition": "task_bound"
    });
    let binding = eliot_types::CueBinding {
        cue_kind: eliot_types::CueKind::FilePath,
        cue_value: "crates/eliot-app/src/lib.rs".to_owned(),
        match_mode: eliot_types::CueMatchMode::Exact,
        strength: eliot_types::CueStrength::Primary,
        expected_reuse_note: None,
    };
    attach_observe_cue_bindings(&mut bound_payload, false, &[binding]);
    assert_eq!(bound_payload["cue_binding_state"], "auto_bound");
    assert_eq!(
        bound_payload["cue_bindings"].as_array().map(Vec::len),
        Some(1)
    );
}

#[test]
fn automatic_observe_binding_is_bounded_and_invalid_cues_fall_back_to_cold() {
    let unusable = (0..32)
        .map(|index| eliot_types::CueBinding {
            cue_kind: eliot_types::CueKind::ErrorSignature,
            cue_value: format!("not-a-signature-{index}"),
            match_mode: eliot_types::CueMatchMode::Signature,
            strength: eliot_types::CueStrength::Primary,
            expected_reuse_note: None,
        })
        .collect();
    let normalized = normalize_auto_observe_bindings(unusable, None);
    assert!(normalized.is_empty());

    let mut cold_payload = json!({
        "record_kind": "observation_candidate",
        "candidate_only": true,
        "capture_first": true,
        "candidate_disposition": "cold"
    });
    attach_observe_cue_bindings(&mut cold_payload, true, &normalized);
    assert_eq!(cold_payload["cue_binding_state"], "cold");
    assert!(cold_payload.get("cue_bindings").is_none());

    let too_many_valid = (0..32)
        .map(|index| eliot_types::CueBinding {
            cue_kind: eliot_types::CueKind::FilePath,
            cue_value: format!("crates/eliot-app/src/file-{index}.rs"),
            match_mode: eliot_types::CueMatchMode::Exact,
            strength: eliot_types::CueStrength::Primary,
            expected_reuse_note: None,
        })
        .collect();
    assert_eq!(
        normalize_auto_observe_bindings(too_many_valid, None).len(),
        5
    );
}

#[test]
fn observe_scope_is_server_bound_and_has_no_project_selector() -> Result<()> {
    let Err(error) = observe_bound_project(AuthenticatedRequestContext {
        session_id: SessionId::new_v7(),
        bound_project_id: None,
        bound_task_id: None,
    }) else {
        return Err(anyhow::anyhow!(
            "unbound observe must not select a project from the request"
        ));
    };
    assert!(error.to_string().contains("Governor-bound project"));

    let schema = catalog::tool_definitions_for_profile(McpAccessProfile::ExternalAuditor)
        .into_iter()
        .find(|tool| tool["name"] == "eliot.observe")
        .context("eliot.observe must be catalogued")?;
    assert!(
        schema["inputSchema"]["properties"]
            .get("project_id")
            .is_none()
    );
    Ok(())
}

#[test]
fn bound_current_state_exposes_canonical_task_without_changing_unbound_shape() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let current_state =
        current_state_with_bound_task(json!({"project_id": project_id}), Some(task_id));
    assert_eq!(current_state["project_id"], json!(project_id));
    assert_eq!(current_state["task_id"], json!(task_id));

    let unbound_current_state =
        current_state_with_bound_task(json!({"project_id": project_id}), None);
    assert!(unbound_current_state.get("task_id").is_none());
}

/// Needs a live Governor config and a running daemon-owned writer.
#[tokio::test]
#[ignore = "requires ELIOT_GOVERNOR_CONFIG and a running daemon"]
#[allow(clippy::too_many_lines)]
async fn managed_host_observation_uses_the_daemon_owned_writer() -> Result<()> {
    let config_path = PathBuf::from(
        std::env::var_os("ELIOT_GOVERNOR_CONFIG")
            .context("ELIOT_GOVERNOR_CONFIG is required for host observation test")?,
    );
    let instance = RuntimeInstance::select(&config_path, None)?;
    let publication = instance.starting_publication(
        named_pipe_ipc::IPC_PROTOCOL_VERSION,
        &config_path,
        instance.publication_root(),
    )?;
    let daemon = McpDaemon::new(&config_path, &instance, &publication)?;
    daemon.codex_controller.ensure_schema().await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let agent_session_id = AgentSessionId::new_v7();
    let _ = dispatch_task_contract_create(
        &daemon.codex_controller,
        AuthenticatedRequestContext {
            session_id: SessionId::new_v7(),
            bound_project_id: None,
            bound_task_id: None,
        },
        json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7(),
            "title": "daemon-owned managed host observation",
            "acceptance_items": [
                {
                    "item_id": "observed",
                    "description": "managed observation uses the daemon writer",
                    "required_evidence": "observation"
                },
                {
                    "item_id": "verified",
                    "description": "redb remains exclusively owned by the daemon",
                    "required_evidence": "verification"
                }
            ]
        }),
    )
    .await?;

    let mut broker = eliot_types::DelegationState::default();
    HostBrokerService.register_session(
        &mut broker,
        agent_session_id,
        AgentHostId::Antigravity,
        "Google Antigravity".to_owned(),
        "host-observation-test".to_owned(),
        AgentCapabilityEnvelope::default(),
    )?;
    let (role, _) = HostBrokerService.grant_role(
        &mut broker,
        task_id,
        agent_session_id,
        AgentRole::Implementer,
        vec!["run_json".to_owned()],
        60,
    )?;
    let request = AgentInvocationRequest {
        invocation_id: format!("host-invocation:{}", uuid::Uuid::new_v4()),
        project_id,
        task_id,
        work_item_id: WorkItemId::new_v7(),
        requested_capabilities: vec!["run_json".to_owned()],
        role_lease_id: role.role_lease_id.clone(),
        role_lease_epoch: role.epoch,
        operation_generation: role.generation,
        runtime_contract_sha256: None,
        work_lease_id: None,
        packet_refs: Vec::new(),
        expected_result_kind: "candidate_unified_diff".to_owned(),
        verifier_ref: "eliot/verifier/daemon-receipt-resolution@1".to_owned(),
        idempotency_key: uuid::Uuid::new_v4().to_string(),
    };
    broker.agent_invocations.push(request.clone());
    delegation_runtime::save_host_broker_state(&daemon.host_governor.root, &broker)?;

    let config = load_config(&config_path)?;
    let lock_error = ControlWal::open(&config.control_wal)
        .err()
        .context("daemon must hold the exclusive control WAL lock")?;
    assert!(lock_error.to_string().contains("Database already open"));

    let response = daemon
        .handle_line(
            "host_governor",
            SessionId::new_v7(),
            None,
            None,
            &serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "host/observation-record",
                "params": {
                    "project_id": project_id,
                    "task_id": task_id,
                    "agent_session_id": agent_session_id,
                    "key": format!("managed-agent-invocation:{}", request.invocation_id),
                    "receipt_kind": "agent_invocation_request",
                    "body": request.clone(),
                }
            }))?,
        )
        .await?
        .context("private host observation returned no response")?;
    let response: Value = serde_json::from_str(&response)?;
    assert!(response.get("error").is_none(), "{response}");
    assert!(response.pointer("/result/canonical_receipt").is_some());
    assert_eq!(
        response.pointer("/result/write_receipt/status"),
        Some(&json!("committed"))
    );
    let denied = daemon
        .handle_line(
            "host_governor",
            SessionId::new_v7(),
            None,
            None,
            &serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "host/observation-record",
                "params": {
                    "project_id": project_id,
                    "task_id": task_id,
                    "agent_session_id": agent_session_id,
                    "key": "unbounded-host-observation",
                    "receipt_kind": "raw_host_payload",
                    "body": request,
                }
            }))?,
        )
        .await?
        .context("denied private host observation returned no response")?;
    let denied: Value = serde_json::from_str(&denied)?;
    assert!(denied.get("error").is_some());
    drop(daemon);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    Ok(())
}

#[test]
fn managed_verification_run_requires_typed_canonical_verifier_identity() -> Result<()> {
    let planned = RegisteredTaskVerifier::ReceiptResolution;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let write_id = WriteId::new_v7();
    let memory_revision = Some(MemoryRevision::new(7));
    let mut run = VerificationRun {
        verification_id: VerificationId::from_uuid(write_id.as_uuid()),
        claim_id: None,
        project_id: Some(project_id),
        task_id: Some(task_id),
        write_id: Some(write_id),
        memory_revision,
        verifier: planned.id().to_owned(),
        result: VerificationResult::Passed,
        summary: "typed canonical verifier identity".to_owned(),
        payload: json!({"verifier": planned.id()}),
    };
    validate_managed_verification_run_identity(
        &run,
        planned,
        project_id,
        task_id,
        write_id,
        memory_revision,
    )?;
    run.verifier = "fabricated-canonical-run-verifier".to_owned();
    let error = validate_managed_verification_run_identity(
        &run,
        planned,
        project_id,
        task_id,
        write_id,
        memory_revision,
    )
    .err()
    .context("canonical run.verifier mismatch was accepted")?;
    assert!(
        error
            .to_string()
            .contains("canonical verifier run identity differs from planned")
    );
    Ok(())
}

fn finalization_git(root: &Path, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn finalization_intent(
    label: &str,
    baseline: String,
    candidate: &[u8],
    changed_file: &str,
) -> Result<ManagedFinalizationIntent> {
    let finalization_id = format!("managed-finalization:{label}");
    Ok(ManagedFinalizationIntent {
        schema_version: "eliot-managed-finalization-intent-v2".to_owned(),
        finalization_id: finalization_id.clone(),
        invocation_id: format!("host-invocation:{label}"),
        project_id: ProjectId::new_v7(),
        task_id: TaskId::new_v7(),
        task_revision: MemoryRevision::new(1),
        task_write_id: WriteId::new_v7(),
        work_item_id: WorkItemId::new_v7(),
        controller_session_id: AgentSessionId::new_v7(),
        provider_result_id: format!("provider-result:{label}"),
        provider_output_hash: managed_candidate_hash(candidate),
        candidate_diff_hash: managed_candidate_hash(candidate),
        verifier_refs: vec![format!("verification:{}", VerificationId::new_v7())],
        candidate_diff_id: CandidateDiffId::from_uuid(deterministic_managed_uuid(
            "candidate-diff",
            &finalization_id,
        )),
        review_id: format!("review:{label}"),
        result_id: format!("result:{label}"),
        disposition_id: format!("disposition:{label}"),
        work_lease_id: WorkLeaseId::new_v7(),
        worktree_lease_id: WorktreeLeaseId::new_v7(),
        baseline_commit: baseline,
        changed_files: vec![changed_file.to_owned()],
        added_files: Vec::new(),
        modified_files: vec![changed_file.to_owned()],
        deleted_files: Vec::new(),
        authority_receipts: BTreeMap::new(),
        created_at: time::OffsetDateTime::parse(
            "2026-07-16T12:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )?,
    })
}

#[test]
fn legacy_finalization_records_without_verifier_refs_fail_deserialization() -> Result<()> {
    let intent = finalization_intent(
        "legacy-missing-verifier-refs",
        "0123456789abcdef".to_owned(),
        b"candidate",
        "candidate.txt",
    )?;
    let mut legacy_intent = serde_json::to_value(intent)?;
    let intent_object = legacy_intent
        .as_object_mut()
        .context("serialized finalization intent must be an object")?;
    intent_object.insert(
        "schema_version".to_owned(),
        json!("eliot-managed-finalization-intent-v1"),
    );
    intent_object.remove("verifier_refs");
    let intent_error = serde_json::from_value::<ManagedFinalizationIntent>(legacy_intent)
        .err()
        .context("legacy intent without verifier refs was accepted")?;
    assert!(intent_error.to_string().contains("verifier_refs"));

    let legacy_aggregate = json!({
        "schema_version": "eliot-managed-finalization-aggregate-v1",
        "finalization_id": "managed-finalization:legacy",
        "invocation_id": "host-invocation:legacy",
        "provider_output_hash": "blake3:legacy"
    });
    let aggregate_error = serde_json::from_value::<ManagedFinalizationAggregate>(legacy_aggregate)
        .err()
        .context("legacy aggregate without verifier refs was accepted")?;
    assert!(aggregate_error.to_string().contains("verifier_refs"));
    Ok(())
}

fn finalization_git_fixture(label: &str) -> Result<(PathBuf, Vec<u8>, ManagedFinalizationIntent)> {
    let root = std::env::temp_dir().join(format!(
        "eliot-managed-finalization-{label}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root)?;
    finalization_git(&root, &["init"])?;
    finalization_git(&root, &["config", "user.name", "Eliot Test"])?;
    finalization_git(
        &root,
        &["config", "user.email", "eliot-test@example.invalid"],
    )?;
    std::fs::write(root.join("candidate.txt"), "before\n")?;
    finalization_git(&root, &["add", "candidate.txt"])?;
    finalization_git(&root, &["commit", "-m", "baseline"])?;
    let baseline = finalization_git(&root, &["rev-parse", "HEAD"])?;
    std::fs::write(root.join("candidate.txt"), "after\n")?;
    let candidate = git_managed_bytes(
        &root,
        &["diff", "--binary", "--no-ext-diff", &baseline, "--"],
    )?;
    finalization_git(&root, &["restore", "candidate.txt"])?;
    let intent = finalization_intent(label, baseline, &candidate, "candidate.txt")?;
    Ok((root, candidate, intent))
}

#[test]
fn managed_finalization_commit_recovers_apply_and_replays_exactly() -> Result<()> {
    let (root, candidate, intent) = finalization_git_fixture("clean")?;
    let first = ensure_managed_candidate_commit(&root, &intent, &candidate)?;
    let replay = ensure_managed_candidate_commit(&root, &intent, &candidate)?;
    assert_eq!(first, replay);
    validate_managed_finalization_commit(&root, &intent, &first)?;
    std::fs::remove_dir_all(root)?;

    let (root, candidate, intent) = finalization_git_fixture("after-apply")?;
    apply_candidate_diff(&root, &candidate)?;
    let recovered = ensure_managed_candidate_commit(&root, &intent, &candidate)?;
    validate_managed_finalization_commit(&root, &intent, &recovered)?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn managed_finalization_serializer_is_per_invocation() {
    let first = managed_finalization_mutex("host-invocation:one");
    let replay = managed_finalization_mutex("host-invocation:one");
    let other = managed_finalization_mutex("host-invocation:two");
    assert!(Arc::ptr_eq(&first, &replay));
    assert!(!Arc::ptr_eq(&first, &other));
    let guard = first.lock().await;
    assert!(replay.try_lock().is_err());
    assert!(other.try_lock().is_ok());
    drop(guard);
    assert!(replay.try_lock().is_ok());
}

#[test]
fn operator_candidate_evidence_must_cover_exact_source_provenance() -> Result<()> {
    let claim_id = ClaimId::new_v7();
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let candidate = CanonicalClaimCard {
        claim_id,
        project_id,
        task_id: Some(task_id),
        scope: format!("task:{task_id}:agent-candidate-memory"),
        status: EpistemicStatus::Candidate,
        lifecycle_status: LifecycleStatus::Active,
        visibility: Visibility::Project,
        taint: TaintClass::ExternalAgent,
        authority: "mcp-profile:dynamic_agent".to_owned(),
        statement: "M6 reciprocal source candidate".to_owned(),
        payload: json!({
            "candidate_only": true,
            "provenance_refs": [
                "native-health:passed",
                "host-namespace:init-channel-closed"
            ]
        }),
        memory_revision: MemoryRevision::new(7),
        project_sequence: eliot_types::ProjectSequence::new(7),
        write_id: WriteId::from_uuid(claim_id.as_uuid()),
    };
    let exact = vec![
        "native-health:passed".to_owned(),
        "host-namespace:init-channel-closed".to_owned(),
    ];
    assert_eq!(
        require_operator_candidate_evidence(&candidate, &exact)?,
        exact
    );
    let superset = vec![
        "native-health:passed".to_owned(),
        "host-namespace:init-channel-closed".to_owned(),
        "operator-observation:confirmed".to_owned(),
    ];
    assert!(require_operator_candidate_evidence(&candidate, &superset).is_ok());
    assert!(
        require_operator_candidate_evidence(&candidate, &["unrelated-verifier:passed".to_owned()])
            .is_err()
    );
    assert_eq!(
        operator_candidate_claim_id(&format!("claim:{claim_id}"))?,
        claim_id
    );
    assert!(operator_candidate_scope_matches(
        &candidate, project_id, task_id
    ));
    let mut project_only = candidate.clone();
    project_only.task_id = None;
    assert!(!operator_candidate_scope_matches(
        &project_only,
        project_id,
        task_id
    ));
    assert!(!operator_candidate_scope_matches(
        &candidate,
        project_id,
        TaskId::new_v7()
    ));
    let binding = operator_candidate_lifecycle_binding(
        &candidate,
        project_id,
        task_id,
        &exact,
        &exact,
        SessionId::new_v7(),
    )?;
    assert!(
        binding
            .precondition_refs
            .contains(&format!("candidate-write:{}", candidate.write_id))
    );
    let mut different_revision = candidate.clone();
    different_revision.memory_revision = MemoryRevision::new(8);
    let changed = operator_candidate_lifecycle_binding(
        &different_revision,
        project_id,
        task_id,
        &exact,
        &exact,
        SessionId::new_v7(),
    )?;
    assert_ne!(binding.precondition_refs, changed.precondition_refs);
    Ok(())
}

#[test]
fn antigravity_live_status_reads_user_config_and_plugin_instead_of_cached_reports() -> Result<()> {
    let home = std::env::temp_dir().join(format!(
        "eliot-antigravity-live-status-{}",
        uuid::Uuid::new_v4()
    ));
    let config_dir = home.join(".gemini").join("config");
    let plugin_root = config_dir.join("plugins").join("eliot-antigravity");
    std::fs::create_dir_all(plugin_root.join("skills").join("eliot-governor"))?;
    std::fs::create_dir_all(plugin_root.join("agents").join("eliot-agent"))?;
    std::fs::create_dir_all(plugin_root.join("rules"))?;
    let executable = home.join("eliot-governor.exe");
    std::fs::write(&executable, b"test executable")?;
    std::fs::write(
        config_dir.join("mcp_config.json"),
        serde_json::to_vec_pretty(&json!({
            "mcpServers": {
                "eliot-governor": {
                    "command": executable,
                    "args": [
                        "mcp", "stdio", "--host", "antigravity",
                        "--instance", "default"
                    ]
                }
            }
        }))?,
    )?;
    std::fs::write(
        plugin_root.join("plugin.json"),
        serde_json::to_vec_pretty(&json!({
            "$schema": "https://antigravity.google/schemas/v1/plugin.json",
            "name": "eliot-antigravity"
        }))?,
    )?;
    std::fs::write(
        plugin_root
            .join("skills")
            .join("eliot-governor")
            .join("SKILL.md"),
        "# Eliot Governor\n",
    )?;
    std::fs::write(
        plugin_root
            .join("agents")
            .join("eliot-agent")
            .join("agent.md"),
        "# Eliot Agent\n",
    )?;
    std::fs::write(
        plugin_root.join("rules").join("ELIOT_TOOL_USAGE.md"),
        "# Rule\n",
    )?;

    let invocation = AntigravityMcpBoundaryService.invocation_receipt_with_audit(
        "external_auditor",
        "eliot_recall_l0",
        true,
        Some("reports/antigravity-mcp-invocations/events/test.json"),
        McpAccessProfile::ExternalAuditor.allows("eliot_recall_l0"),
    )?;
    let mcp = antigravity_mcp_live_status(&home, Some(&invocation));
    assert_eq!(mcp.get("registered").and_then(Value::as_bool), Some(true));
    assert_eq!(
        mcp.get("invocation_succeeded").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        mcp.get("source").and_then(Value::as_str),
        Some("live-user-config")
    );

    let plugin = antigravity_plugin_live_status(&home);
    assert_eq!(plugin.get("installed").and_then(Value::as_bool), Some(true));
    assert_eq!(
        plugin.get("skill_visible").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        plugin.get("agent_visible").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        plugin.get("rule_visible").and_then(Value::as_bool),
        Some(true)
    );

    std::fs::remove_dir_all(home)?;
    Ok(())
}

#[test]
fn project_identity_accepts_stable_labels_and_normalizes_windows_paths() -> Result<()> {
    let label = parse_project_id("eliot-governor")?;
    assert_eq!(label, parse_project_id("  ELIOT-GOVERNOR  ")?);

    let direct = parse_project_id(r"C:\Profiles\Fixture\repo\eliot-memory-os\")?;
    let extended = parse_project_id(r"\\?\c:\profiles\fixture\repo\eliot-memory-os")?;
    assert_eq!(direct, extended);

    let explicit = ProjectId::new_v7();
    assert_eq!(explicit, parse_project_id(&explicit.to_string())?);
    Ok(())
}

#[test]
fn external_auditor_initialize_instructions_make_memory_proactive() {
    let instructions = profile_instructions(McpAccessProfile::ExternalAuditor);
    assert!(instructions.contains("Context arrives by itself"));
    assert!(instructions.contains("ul_boot"));
    assert!(instructions.contains("frame_stub"));
    assert!(instructions.contains("matching negative memory"));
    assert!(instructions.contains("Host identity grants no controller"));
    assert!(instructions.contains("model writes remain evidence"));
}

#[test]
fn claude_desktop_profile_is_compact_and_role_neutral() -> Result<()> {
    let profile = McpAccessProfile::parse("claude_desktop")?;
    let tools = tool_definitions_for_profile(profile);
    for tool in &tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .context("Claude tool name")?;
        assert_eq!(
            tool.pointer("/inputSchema/type").and_then(Value::as_str),
            Some("object"),
            "Claude Code requires an object-root input schema for {name}"
        );
    }
    let names = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(names.len(), PART_E_WORKER_TOOLS.len());
    assert!(PART_E_WORKER_TOOLS.iter().all(|name| names.contains(name)));
    let instructions = profile_instructions(profile);
    assert!(instructions.contains("Host identity grants no controller"));
    assert!(instructions.contains("Context arrives by itself"));
    assert!(!instructions.contains("You are an external_auditor"));
    Ok(())
}

#[test]
fn claude_desktop_prompts_are_small_and_expand_on_request() -> Result<()> {
    let definitions = prompt_definitions();
    assert_eq!(definitions.len(), 4);
    let response = prompt_get(&json!({
        "name": "eliot-understand",
        "arguments": { "task": "repair packet admission" }
    }))?;
    let text = response
        .pointer("/messages/0/content/text")
        .and_then(Value::as_str)
        .context("prompt text")?;
    assert!(text.contains("repair packet admission"));
    assert!(text.contains("goal -> owner -> symbol or artifact -> observable -> verifier"));
    assert!(text.len() < 800);
    Ok(())
}

#[test]
fn semantic_duplicate_candidate_is_detected_without_requiring_identical_payload() {
    let task_id = TaskId::from_uuid(uuid::Uuid::from_u128(10));
    let claim = eliot_types::ClaimCard {
        claim_id: ClaimId::from_uuid(uuid::Uuid::from_u128(11)),
        statement: "QUARTZ requires a current revision fence.".to_owned(),
        status: EpistemicStatus::Candidate,
        payload: json!({
            "candidate_only": true,
            "task_id": task_id,
            "topic": "runtime handoff"
        }),
    };
    let claims = [claim];
    let duplicate = existing_candidate_with_same_topic_and_statement(
        &claims,
        task_id,
        " runtime   handoff ",
        "QUARTZ requires a current revision fence.",
    );
    assert!(duplicate.is_some());
}

fn completion_task_fixture() -> TaskContract {
    let project_id = ProjectId::from_uuid(uuid::Uuid::from_u128(1));
    let task_id = TaskId::from_uuid(uuid::Uuid::from_u128(2));
    let lease_id = ActionLeaseId::from_uuid(uuid::Uuid::from_u128(3));
    let verification_id = VerificationId::from_uuid(uuid::Uuid::from_u128(4));
    let artifact_path = "crates/eliot-app/src/mcp_stdio.rs".to_owned();
    TaskContract {
        task_id,
        project_id,
        title: "completion memory fixture".to_owned(),
        status: TaskContractStatus::Active,
        acceptance_items: vec![],
        action_lease_id: Some(lease_id),
        understanding_proof_hash: Some("understanding".to_owned()),
        action_provenance: Some(ActionProvenanceSet {
            provenance_set_id: "eliot/provenance-set/test".to_owned(),
            task_id,
            packet_id: "eliot/packet/test".to_owned(),
            packet_revision_fence: MemoryRevision::new(1),
            task_contract_ref: format!("eliot/task/{task_id}@1"),
            current_truth_refs: vec![format!("eliot/task/{task_id}@1")],
            exact_evidence_refs: vec!["receipt:test".to_owned()],
            negative_memory_check_ref: "eliot/negative-memory/test".to_owned(),
            planned_verifier_ref: RegisteredTaskVerifier::CargoWorkspaceCheck.reference(),
            source_scope: ActionSourceScope {
                kind: "git_worktree".to_owned(),
                worktree_ref: Some("C:/test/worktree".to_owned()),
                branch: Some("test-branch".to_owned()),
                baseline_commit: Some("base-commit".to_owned()),
                baseline_dirty_state_hash: Some("clean".to_owned()),
                artifact_paths: vec![artifact_path.clone()],
            },
            resolved_at: time::OffsetDateTime::UNIX_EPOCH,
            resolver_version: ACTION_PROVENANCE_RESOLVER_VERSION.to_owned(),
            hash: "provenance-hash".to_owned(),
        }),
        observation_ids: vec!["observation".to_owned()],
        verification_ids: vec![verification_id],
        verification_scopes: vec![VerifierArtifactScope {
            verification_id,
            verifier_id: CARGO_WORKSPACE_CHECK_VERIFIER_ID.to_owned(),
            verifier_version: VERIFIER_VERSION.to_owned(),
            config_hash: RegisteredTaskVerifier::CargoWorkspaceCheck.config_hash(),
            project_id,
            task_id,
            branch: "test-branch".to_owned(),
            commit: "candidate-commit".to_owned(),
            dirty_state_hash: "candidate-clean".to_owned(),
            worktree_ref: "C:/test/worktree".to_owned(),
            artifact_refs: vec![VerifierArtifactRef {
                resource_ref: artifact_path.clone(),
                content_hash: "artifact-hash".to_owned(),
            }],
            path_or_resource_scope: artifact_path,
            acceptance_item_ids: vec!["verification".to_owned()],
            observed_at: time::OffsetDateTime::UNIX_EPOCH,
            expires_or_invalidates_on: vec!["commit change".to_owned()],
            canonical_scope_hash: "scope-hash".to_owned(),
        }],
        completion_proof: None,
        completion_write_id: None,
        memory_revision: MemoryRevision::new(2),
        project_sequence: eliot_types::ProjectSequence::new(2),
        write_id: WriteId::from_uuid(lease_id.as_uuid()),
    }
}

fn bound_completion_proof_fixture() -> (TaskContract, CompletionProof) {
    let mut task = completion_task_fixture();
    let observation_id = task.observation_ids[0].clone();
    let verification_id = task.verification_ids[0];
    let scope = task.verification_scopes[0].clone();
    task.acceptance_items = vec![
        TaskAcceptanceItem {
            item_id: "observed".to_owned(),
            description: "canonical observation is bound".to_owned(),
            required_evidence: TaskAcceptanceEvidenceKind::Observation,
            satisfied: true,
            observation_id: Some(observation_id.clone()),
            verification_id: None,
            verification_scope_hash: None,
        },
        TaskAcceptanceItem {
            item_id: "verified".to_owned(),
            description: "canonical verifier is bound".to_owned(),
            required_evidence: TaskAcceptanceEvidenceKind::Verification,
            satisfied: true,
            observation_id: None,
            verification_id: Some(verification_id),
            verification_scope_hash: Some(scope.canonical_scope_hash.clone()),
        },
    ];
    task.verification_scopes[0].acceptance_item_ids = vec!["verified".to_owned()];

    let proof = CompletionProof {
        task_id: task.task_id.to_string(),
        project_id: task.project_id,
        goal: task.title.clone(),
        changed_files: task
            .action_provenance
            .as_ref()
            .map_or_else(Vec::new, |provenance| {
                provenance.source_scope.artifact_paths.clone()
            }),
        memory_refs_used: Vec::new(),
        checks_run: vec![scope.verifier_id.clone()],
        checks_not_run: Vec::new(),
        acceptance_items: vec![
            eliot_types::CompletionAcceptanceItem {
                item: "observed".to_owned(),
                status: "verified".to_owned(),
                evidence: observation_id.clone(),
                verifier: "canonical-observation".to_owned(),
                residual_uncertainty: "none".to_owned(),
            },
            eliot_types::CompletionAcceptanceItem {
                item: "verified".to_owned(),
                status: "verified".to_owned(),
                evidence: verification_id.to_string(),
                verifier: scope.verifier_id.clone(),
                residual_uncertainty: "none".to_owned(),
            },
        ],
        evidence: vec![
            observation_id,
            format!("verification:{verification_id}"),
            scope.canonical_scope_hash.clone(),
        ],
        skill_refs: Vec::new(),
        skill_execution_proof_refs: Vec::new(),
        residual_uncertainty: "none".to_owned(),
        known_risks: Vec::new(),
    };
    (task, proof)
}

#[test]
fn canonical_task_completion_proof_binds_exact_contract() {
    let (task, proof) = bound_completion_proof_fixture();
    assert!(task_completion_proof_gaps(&task, &proof).is_empty());
    assert_eq!(
        CompletionGate::decide(&proof).final_status,
        CompletionStatus::DoneVerified
    );
}

#[test]
fn canonical_task_completion_proof_rejects_goal_mismatch() {
    let (task, mut proof) = bound_completion_proof_fixture();
    proof.goal = "different goal".to_owned();
    assert!(
        task_completion_proof_gaps(&task, &proof)
            .contains(&"completion_proof:goal_mismatch".to_owned())
    );
}

#[test]
fn canonical_task_completion_proof_rejects_scope_mismatch() {
    let (task, mut proof) = bound_completion_proof_fixture();
    proof.task_id = TaskId::new_v7().to_string();
    assert!(
        task_completion_proof_gaps(&task, &proof)
            .contains(&"completion_proof:task_scope_mismatch".to_owned())
    );
}

#[test]
fn canonical_task_completion_proof_rejects_acceptance_mapping_mismatch() {
    let (task, mut proof) = bound_completion_proof_fixture();
    proof.acceptance_items[0].item = "unrelated-item".to_owned();
    assert!(
        task_completion_proof_gaps(&task, &proof)
            .iter()
            .any(|gap| gap == "completion_proof:acceptance_item:observed:not_exact")
    );
}

#[test]
fn canonical_task_completion_proof_rejects_verifier_mismatch() {
    let (task, mut proof) = bound_completion_proof_fixture();
    proof.acceptance_items[1].verifier = "unrelated-verifier".to_owned();
    assert!(
        task_completion_proof_gaps(&task, &proof)
            .iter()
            .any(|gap| gap == "completion_proof:acceptance_item:verified:verification_not_bound")
    );
}

#[test]
fn task_completion_input_requires_and_preserves_nested_proof() -> Result<()> {
    let (task, proof) = bound_completion_proof_fixture();
    let request = json!({
        "project_id": task.project_id,
        "task_id": task.task_id,
        "write_id": uuid::Uuid::from_u128(5),
        "expected_revision": task.memory_revision.value(),
        "completion_proof": proof,
        "acceptance_item_ids": ["observed", "verified"],
        "observation_ids": task.observation_ids,
        "verification_ids": task.verification_ids,
    });
    let parsed = serde_json::from_value::<TaskCompletionToolInput>(request.clone())?;
    assert_eq!(
        canonical_struct_hash(&parsed.completion_proof)?,
        canonical_struct_hash(&proof)?
    );
    let replay = serde_json::from_value::<TaskCompletionToolInput>(request.clone())?;
    assert_eq!(
        canonical_struct_hash(&parsed.completion_proof)?,
        canonical_struct_hash(&replay.completion_proof)?
    );

    let mut missing_proof = request;
    missing_proof
        .as_object_mut()
        .context("completion request must be an object")?
        .remove("completion_proof");
    assert!(serde_json::from_value::<TaskCompletionToolInput>(missing_proof).is_err());
    Ok(())
}

#[test]
fn completion_memory_rejects_caller_authored_scope() {
    let (task, proof) = bound_completion_proof_fixture();
    let parsed = serde_json::from_value::<TaskCompletionToolInput>(json!({
        "project_id": task.project_id,
        "task_id": task.task_id,
        "write_id": uuid::Uuid::from_u128(5),
        "expected_revision": 2,
        "completion_proof": proof,
        "acceptance_item_ids": ["observed", "verified"],
        "observation_ids": task.observation_ids,
        "verification_ids": task.verification_ids,
        "memory": {
            "outcome": "save_decision",
            "statement": "store this decision",
            "artifact_scope": ["caller/controlled.rs"]
        }
    }));
    assert!(parsed.is_err());
}

#[test]
fn completion_memory_records_explicit_nothing_to_save() -> Result<()> {
    let session_id = SessionId::from_uuid(uuid::Uuid::from_u128(6));
    let task = completion_task_fixture();
    let completion_write_id = WriteId::from_uuid(uuid::Uuid::from_u128(7));
    let command = derive_completion_agent_result_command(
        AuthenticatedRequestContext {
            session_id,
            bound_project_id: None,
            bound_task_id: None,
        },
        &task,
        completion_write_id,
        vec![ReceiptId::from_uuid(task.verification_ids[0].as_uuid())],
        Some(&CompletionMemoryRequest::NothingToSave),
    )?;
    assert!(matches!(
        command.memory,
        CompletionMemoryAdmission::NothingToSave
    ));
    let envelope = WriteAdmissionService.admit(&SemanticCommand::AgentResultRecord(command))?;
    assert_eq!(envelope.tool_observations.len(), 1);
    assert!(envelope.source_snapshots.is_empty());
    assert!(envelope.evidence_atoms.is_empty());
    assert!(envelope.claims.is_empty());
    assert!(envelope.relations.is_empty());
    Ok(())
}

#[test]
fn completion_memory_lineage_is_exactly_server_derived() -> Result<()> {
    let session_id = SessionId::from_uuid(uuid::Uuid::from_u128(8));
    let task = completion_task_fixture();
    let completion_write_id = WriteId::from_uuid(uuid::Uuid::from_u128(9));
    let verification_receipt = ReceiptId::from_uuid(task.verification_ids[0].as_uuid());
    let request = CompletionMemoryRequest::SaveDecision {
        statement: "Use AgentResultRecord for completion handoff lineage.".to_owned(),
    };
    let command = derive_completion_agent_result_command(
        AuthenticatedRequestContext {
            session_id,
            bound_project_id: None,
            bound_task_id: None,
        },
        &task,
        completion_write_id,
        vec![verification_receipt],
        Some(&request),
    )?;
    assert_eq!(command.lineage.child_session_id, session_id);
    assert_eq!(command.lineage.task_id, task.task_id);
    assert_eq!(command.lineage.base_commit, "base-commit");
    let provenance = task
        .action_provenance
        .as_ref()
        .context("fixture action provenance")?;
    assert_eq!(
        command.lineage.accepted_write_set,
        provenance.source_scope.artifact_paths
    );
    assert_eq!(command.lineage.verification_ids, task.verification_ids);
    assert_eq!(
        command.lineage.resulting_controller_commit,
        "candidate-commit"
    );
    assert_eq!(
        command.lineage.controller_receipt_id.as_uuid(),
        command.context.write_id.as_uuid()
    );
    let CompletionMemoryAdmission::SaveDecision { decision } = &command.memory else {
        anyhow::bail!("expected saved decision");
    };
    assert!(
        decision
            .where_applicable
            .contains(&"commit:candidate-commit".to_owned())
    );
    assert!(
        decision
            .where_not_applicable
            .iter()
            .any(|boundary| boundary.contains("outside the accepted ActionLease"))
    );
    assert!(
        decision
            .freshness_rule
            .contains(&task.verification_ids[0].to_string())
    );
    Ok(())
}

#[test]
fn completion_memory_replay_has_one_stable_semantic_write() -> Result<()> {
    let session_id = SessionId::from_uuid(uuid::Uuid::from_u128(10));
    let task = completion_task_fixture();
    let completion_write_id = WriteId::from_uuid(uuid::Uuid::from_u128(11));
    let verification_receipts = vec![ReceiptId::from_uuid(task.verification_ids[0].as_uuid())];
    let request = CompletionMemoryRequest::SaveDecision {
        statement: "Replay the same semantic write idempotently.".to_owned(),
    };
    let derive = || {
        derive_completion_agent_result_command(
            AuthenticatedRequestContext {
                session_id,
                bound_project_id: None,
                bound_task_id: None,
            },
            &task,
            completion_write_id,
            verification_receipts.clone(),
            Some(&request),
        )
    };
    let first = WriteAdmissionService.admit(&SemanticCommand::AgentResultRecord(derive()?))?;
    let replay = WriteAdmissionService.admit(&SemanticCommand::AgentResultRecord(derive()?))?;
    assert_eq!(first.write_id, replay.write_id);
    assert_eq!(first.input_hash, replay.input_hash);
    assert!(first.idempotency.allow_replay);
    assert_eq!(
        serde_json::to_value(&first.source_snapshots)?,
        serde_json::to_value(&replay.source_snapshots)?
    );
    assert_eq!(
        serde_json::to_value(&first.evidence_atoms)?,
        serde_json::to_value(&replay.evidence_atoms)?
    );
    assert_eq!(
        serde_json::to_value(&first.claims)?,
        serde_json::to_value(&replay.claims)?
    );
    assert_eq!(
        serde_json::to_value(&first.relations)?,
        serde_json::to_value(&replay.relations)?
    );
    Ok(())
}

#[test]
fn cargo_workspace_check_registry_contract_is_static() {
    let verifier = RegisteredTaskVerifier::CargoWorkspaceCheck;
    assert_eq!(verifier.id(), "cargo-workspace-check");
    assert_eq!(verifier.source_kind(), "git_worktree");
    assert_eq!(
        RegisteredTaskVerifier::from_reference(&verifier.reference()),
        Some(verifier)
    );
    assert_eq!(
        verifier
            .descriptor()
            .get("config_hash")
            .and_then(Value::as_str),
        Some(verifier.config_hash().as_str())
    );
}

#[tokio::test]
async fn cargo_workspace_check_registry_runs_fixed_offline_command() -> Result<()> {
    let root =
        std::env::temp_dir().join(format!("eliot-l4-workspace-check-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(root.join("src"))?;
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"eliot-l4-verifier-probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
    )?;
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn verified() -> bool { true }\n",
    )?;

    let result = run_cargo_workspace_check_verifier(&root).await;
    let cleanup = std::fs::remove_dir_all(&root);
    result?;
    cleanup?;
    Ok(())
}

#[test]
fn cognitive_reader_profiles_are_exact_and_control_is_empty() {
    let treatment = catalog::provider_mcp_tool_profile(McpAccessProfile::UnderstandingReader);
    assert_eq!(treatment.profile_id, "understanding_reader");
    assert_eq!(
        treatment.tool_names,
        vec![
            "eliot_current_state".to_owned(),
            "eliot_fetch_l2".to_owned(),
            "eliot_memory_influence_trace".to_owned(),
            "eliot_recall_l0".to_owned(),
        ]
    );
    assert!(treatment.hash_is_valid());

    let control = catalog::provider_mcp_tool_profile(McpAccessProfile::CognitiveControl);
    assert_eq!(control.profile_id, "cognitive_control");
    assert!(control.tool_names.is_empty());
    assert!(control.hash_is_valid());
}

#[test]
fn dynamic_agent_profile_is_host_neutral_and_proactive() -> Result<()> {
    let profile = McpAccessProfile::parse("dynamic_agent")?;
    assert_eq!(profile, McpAccessProfile::DynamicAgent);
    for tool in PART_E_WORKER_TOOLS {
        assert!(profile.allows(tool), "missing Part-E tool {tool}");
    }
    assert!(!profile.allows("eliot_host_session_status"));
    assert!(!profile.allows("eliot_project_identity"));
    assert!(!profile.allows("eliot_task_state"));
    assert!(!profile.allows("eliot_autonomy_run_status"));
    assert!(!profile.allows("eliot_autonomy_contract_write"));
    assert!(!profile.allows("eliot_autonomy_runtime_action"));
    assert!(!profile.allows("eliot_worktree_review"));
    assert!(!profile.allows("eliot_agent_result_finalize"));
    assert!(!profile.allows("eliot_task_meaning"));
    assert!(!profile.allows("eliot_experience_recall"));
    assert!(!profile.allows("eliot_experience_form"));
    let instructions = profile_instructions(profile);
    assert!(instructions.contains("Host identity grants no controller"));
    assert!(instructions.contains("Context arrives by itself"));
    assert!(instructions.contains("compile a packet"));
    assert!(instructions.contains("Save only novel lessons"));
    assert!(!instructions.contains("You are an external_auditor"));
    Ok(())
}

#[test]
fn bound_part_e_catalog_marks_server_defaulted_scope_fields_optional() -> Result<()> {
    for profile in [
        McpAccessProfile::DynamicAgent,
        McpAccessProfile::ClaudeGoverned,
        McpAccessProfile::CodexWorker,
        McpAccessProfile::UnderstandingReader,
        McpAccessProfile::ExternalAuditor,
    ] {
        let current_state = tool_definitions_for_profile(profile)
            .into_iter()
            .find(|tool| tool["name"] == "eliot_current_state")
            .context("bounded current_state tool")?;
        let required = current_state
            .pointer("/inputSchema/required")
            .and_then(Value::as_array)
            .context("bounded current_state required fields")?;
        assert!(!required.iter().any(|field| field == "project_id"));
        assert!(
            current_state
                .pointer("/inputSchema/properties/project_id")
                .is_some(),
            "the optional explicit project fence remains documented"
        );
    }

    let readonly_current_state = tool_definitions_for_profile(McpAccessProfile::HumanReadonly)
        .into_iter()
        .find(|tool| tool["name"] == "eliot_current_state")
        .context("unbound readonly current_state tool")?;
    assert!(
        readonly_current_state
            .pointer("/inputSchema/required")
            .and_then(Value::as_array)
            .is_some_and(|required| required.iter().any(|field| field == "project_id")),
        "unbound callers must still supply a project"
    );
    Ok(())
}

#[test]
fn default_antigravity_remains_dynamic_agent() -> Result<()> {
    assert_eq!(
        resolve_effective_profile("default", Some("antigravity"), false)?,
        McpAccessProfile::DynamicAgent
    );
    Ok(())
}

#[test]
fn installed_codex_profile_resolves_to_exact_worker_surface() -> Result<()> {
    let profile = resolve_effective_profile("codex_worker", Some("codex"), false)?;
    assert_eq!(profile, McpAccessProfile::CodexWorker);
    let names = tool_definitions_for_profile(profile)
        .into_iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        PART_E_WORKER_TOOLS
            .iter()
            .copied()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(names.len(), PART_E_WORKER_TOOLS.len());
    assert!(!profile.allows("eliot_operator_command"));
    assert!(!profile.allows("eliot_autonomy_runtime_action"));
    Ok(())
}

#[test]
fn c5_all_native_worker_hosts_share_exact_eight_tool_schemas() -> Result<()> {
    let expected_names = [
        "eliot_current_state",
        "eliot_recall_l0",
        "eliot_fetch_l2",
        "eliot_compile_packet_l3",
        "eliot_agent_candidate_submit",
        "eliot.observe",
        "eliot_memory_influence_trace",
        "eliot_write_cognitive_observation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(expected_names.len(), 8);
    assert!(expected_names.contains("eliot.observe"));
    assert_eq!(
        expected_names,
        PART_E_WORKER_TOOLS
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
        "the native worker expectation must track the canonical Part-E surface"
    );

    let mut canonical = None;
    for host in ["codex", "claude", "antigravity", "opencode"] {
        let profile = resolve_effective_profile("default", Some(host), false)?;
        let tools = tool_definitions_for_profile(profile);
        let names = tools
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
            .collect::<BTreeSet<_>>();
        assert_eq!(names, expected_names, "{host} worker semantics drifted");
        assert_eq!(
            tools.len(),
            expected_names.len(),
            "{host} must expose exactly the eight expected tools"
        );
        assert!(
            profile_instructions(profile).contains("Host identity grants no controller"),
            "{host} inferred authority from host identity"
        );
        if let Some(canonical) = &canonical {
            assert_eq!(
                &tools, canonical,
                "{host} tool names, field names, or schemas drifted"
            );
        } else {
            canonical = Some(tools);
        }
    }
    Ok(())
}

#[test]
fn explicit_antigravity_auditor_is_honored() -> Result<()> {
    assert_eq!(
        resolve_effective_profile("external_auditor", Some("antigravity"), false)?,
        McpAccessProfile::ExternalAuditor
    );
    assert_eq!(
        resolve_effective_profile("antigravity-auditor", Some("antigravity"), false)?,
        McpAccessProfile::ExternalAuditor
    );
    Ok(())
}

#[test]
fn scoped_antigravity_profile_override_is_explicit_and_fail_closed() -> Result<()> {
    assert_eq!(
        scoped_profile_override("default", Some("antigravity"), None, true, true)?,
        "default"
    );
    assert_eq!(
        scoped_profile_override(
            "default",
            Some("antigravity"),
            Some("external_auditor"),
            true,
            true,
        )?,
        "external_auditor"
    );
    for (host, has_session, has_role) in [
        (Some("claude"), true, true),
        (Some("antigravity"), false, true),
        (Some("antigravity"), true, false),
    ] {
        let error = scoped_profile_override(
            "default",
            host,
            Some("external_auditor"),
            has_session,
            has_role,
        )
        .err()
        .context("invalid scoped profile override must fail")?;
        assert!(
            error
                .to_string()
                .contains("UNSUPPORTED_SCOPED_PROFILE_OVERRIDE")
        );
    }
    Ok(())
}

#[test]
fn unsupported_pair_fails_closed() -> Result<()> {
    let error = resolve_effective_profile("codex_controller", Some("antigravity"), false)
        .err()
        .context("an explicit controller profile must not be inferred from host identity")?;
    assert!(error.to_string().contains("UNSUPPORTED_HOST_PROFILE_PAIR"));
    Ok(())
}

#[test]
fn bounded_catalog() {
    let profile = McpAccessProfile::ExternalAuditor;
    for allowed in [
        "eliot_recall_l0",
        "eliot_fetch_l2",
        "eliot_compile_packet_l3",
        "eliot_agent_candidate_submit",
        "eliot_memory_influence_trace",
    ] {
        assert!(profile.allows(allowed), "{allowed} must remain bounded");
    }
    for denied in [
        "eliot_patch_apply",
        "eliot_submit_completion_proof",
        "eliot_worktree_review",
        "eliot_autonomy_runtime_action",
    ] {
        assert!(!profile.allows(denied), "{denied} must remain unavailable");
    }
}

#[test]
fn provider_tool_profiles_are_catalog_derived_and_hash_stable() {
    let auditor = catalog::provider_mcp_tool_profile(McpAccessProfile::ExternalAuditor);
    let replay = catalog::provider_mcp_tool_profile(McpAccessProfile::ExternalAuditor);
    let child = catalog::provider_mcp_tool_profile(McpAccessProfile::CognitiveChild);
    assert_eq!(auditor, replay);
    assert!(auditor.hash_is_valid());
    assert!(child.hash_is_valid());
    assert_eq!(auditor.tool_names.len(), PART_E_WORKER_TOOLS.len());
    assert_ne!(auditor.profile_hash_blake3, child.profile_hash_blake3);
    assert!(
        auditor
            .tool_names
            .iter()
            .all(|name| McpAccessProfile::ExternalAuditor.allows(name))
    );
}

#[test]
fn scoped_authority_unchanged() -> Result<()> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = SessionId::new_v7();
    let agent_session_id = AgentSessionId::from_uuid(session_id.as_uuid());
    let mut broker = eliot_types::DelegationState::default();
    broker
        .agent_host_sessions
        .push(eliot_types::AgentSessionHostBinding {
            agent_session_id,
            host_identity: eliot_types::AgentHostIdentity {
                host_id: AgentHostId::Antigravity,
                implementation_name: "antigravity".to_owned(),
                client_instance_id: format!("client:{session_id}"),
            },
            capability_envelope: AgentCapabilityEnvelope::default(),
            bound_project_id: Some(project_id),
            bound_task_id: Some(task_id),
            task_role_lease_refs: vec!["role:missing".to_owned()],
            state: eliot_types::AgentSessionState::Active,
            generation: 1,
            owner_operation_id: None,
            disconnected_at: None,
            disconnect_reason: None,
        });
    let error = validate_canonical_host_scope(&broker, session_id, project_id, task_id)
        .err()
        .context("host identity without a TaskRoleLease must fail before dispatch")?;
    assert!(
        error
            .to_string()
            .contains("no active matching TaskRoleLease")
    );
    Ok(())
}

#[test]
fn agent_host_alias_cannot_encode_a_static_role() -> Result<()> {
    let profile = McpAccessProfile::parse("agent_host")?;
    assert_eq!(profile.as_str(), "dynamic_agent");
    assert!(
        tool_definitions_for_profile(profile).len()
            < tool_definitions_for_profile(McpAccessProfile::CodexController).len()
    );
    assert!(!profile.allows("eliot_autonomy_runtime_action"));
    assert!(!profile.allows("eliot_agent_result_finalize"));
    assert!(!McpAccessProfile::CodexWorker.allows("eliot_agent_result_finalize"));
    assert!(McpAccessProfile::CodexController.allows("eliot_agent_result_finalize"));
    for denied in [profile, McpAccessProfile::CodexWorker] {
        assert!(!tool_definitions_for_profile(denied).iter().any(|tool| {
            tool.get("name").and_then(Value::as_str) == Some("eliot_agent_result_finalize")
        }));
    }
    Ok(())
}

#[test]
fn human_operator_profile_exposes_only_typed_control_plane() -> Result<()> {
    let operator = McpAccessProfile::parse("human_operator")?;
    let names = tool_definitions_for_profile(operator)
        .into_iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(names.len(), OPERATOR_TOOLS.len());
    assert!(names.contains(&"eliot_operator_snapshot".to_owned()));
    assert!(names.contains(&"eliot_operator_query".to_owned()));
    assert!(names.contains(&"eliot_autonomy_run_status".to_owned()));
    assert!(names.contains(&"eliot_autonomy_runtime_action".to_owned()));
    assert!(names.contains(&"eliot_autonomy_approval_decide".to_owned()));
    assert!(names.contains(&"eliot_operator_command".to_owned()));
    assert!(names.contains(&"eliot_procedure_candidate_create".to_owned()));
    assert!(names.contains(&"eliot_procedure_candidate_disposition".to_owned()));
    assert!(names.contains(&"eliot_worktree_review".to_owned()));
    assert!(!names.contains(&"eliot_patch_apply".to_owned()));
    assert!(!names.contains(&"eliot_fetch_l2".to_owned()));
    let instructions = profile_instructions(operator);
    assert!(instructions.contains("typed operator commands"));
    assert!(!instructions.contains("call eliot_project_identity"));

    let readonly = McpAccessProfile::parse("human_readonly")?;
    assert!(readonly.allows("eliot_operator_snapshot"));
    assert!(readonly.allows("eliot_operator_query"));
    assert!(readonly.allows("eliot_autonomy_run_status"));
    assert!(readonly.allows("eliot_memory_corpus_profile"));
    assert!(readonly.allows("eliot_experience_recall"));
    assert!(readonly.allows("eliot_memory_lifecycle_vitality"));
    assert!(readonly.allows("eliot_memory_lifecycle_gravity"));
    assert!(!readonly.allows("eliot_memory_lifecycle_propose"));
    assert!(!readonly.allows("eliot_memory_lifecycle_influence"));
    assert!(!readonly.allows("eliot_operator_command"));
    assert!(!readonly.allows("eliot_procedure_candidate_create"));
    assert!(!readonly.allows("eliot_procedure_candidate_disposition"));
    assert!(!readonly.allows("eliot_autonomy_runtime_action"));
    assert!(!readonly.allows("eliot_experience_form"));
    let worker = McpAccessProfile::parse("codex_worker")?;
    assert!(!worker.allows("eliot_worktree_review"));
    assert!(!worker.allows("eliot_autonomy_contract_write"));
    assert!(!worker.allows("eliot_autonomy_approval_request"));
    assert!(!worker.allows("eliot_autonomy_approval_decide"));
    assert!(!worker.allows("eliot_autonomy_runtime_action"));
    Ok(())
}

#[test]
fn operator_contract_manifest_is_versioned_and_hash_pinned() -> Result<()> {
    let contract = dispatch_operator_contract()?;
    assert_eq!(
        contract.get("schema_version").and_then(Value::as_str),
        Some(OPERATOR_SCHEMA_VERSION)
    );
    assert_eq!(
        contract.get("ipc_protocol_version").and_then(Value::as_str),
        Some(named_pipe_ipc::IPC_PROTOCOL_VERSION)
    );
    assert_eq!(operator_contract_hash().len(), 64);
    assert!(OPERATOR_CONTRACT_MANIFEST.contains("ExperienceCase"));
    assert!(OPERATOR_CONTRACT_MANIFEST.contains("schema_families"));
    assert!(OPERATOR_CONTRACT_MANIFEST.contains("query_operations"));
    assert!(OPERATOR_CONTRACT_MANIFEST.contains("create_autonomy_run"));
    let commands = contract["manifest"]["commands"]
        .as_array()
        .context("operator contract manifest has no commands array")?;
    for required in [
        "refresh_packet",
        "request_revalidation",
        "disposition_agent_result",
        "contest_memory",
        "suppress_memory",
        "archive_memory",
        "restore_memory",
        "review_candidate",
    ] {
        assert!(commands.iter().any(|command| command == required));
    }
    Ok(())
}

#[test]
fn operator_query_contract_rejects_raw_sql_and_unissued_cursors() -> Result<()> {
    let raw_sql = serde_json::from_value::<OperatorQueryRequest>(json!({
        "projection": "memory_explorer",
        "page_size": 50,
        "raw_sql": "SELECT * FROM claim"
    }));
    assert!(raw_sql.is_err());
    let scope = blake3::hash(b"operator-query-scope").to_hex().to_string();
    let expected = OperatorCursorState {
        base_offset: 7,
        canonical_start: 280,
        matched_seen: 270,
    };
    let signing_key = [17_u8; 32];
    let cursor = operator_cursor(expected, &scope, &signing_key);
    assert_eq!(
        operator_cursor_state(None, &scope, &signing_key)?,
        OperatorCursorState::default()
    );
    assert_eq!(
        operator_cursor_state(Some(&cursor), &scope, &signing_key)?,
        expected
    );
    assert!(operator_cursor_state(Some(&cursor), &"0".repeat(64), &signing_key).is_err());
    assert!(operator_cursor_state(Some(&cursor), &scope, &[18_u8; 32]).is_err());
    assert!(operator_cursor_state(Some("offset:50"), &scope, &signing_key).is_err());
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn operator_memory_projection_exposes_rank_suppression_and_exact_resolution_fields() {
    let project_id = ProjectId::new_v7();
    let active_id = ClaimId::new_v7();
    let suppressed_id = ClaimId::new_v7();
    let active_handle = active_id.to_string();
    let suppressed_handle = suppressed_id.to_string();
    let l0 = RecallL0Response {
        project_id,
        at_revision: MemoryRevision::new(19),
        projection_revision: Some(MemoryRevision::new(19)),
        projection_state: eliot_types::CognitiveProjectionReadState::Published,
        handles: vec![eliot_types::MemoryHandlePreview {
            handle: active_handle.clone(),
            record_type: "claim_card".to_owned(),
            preview: "query-aware current candidate".to_owned(),
            lifecycle_state: Some(MemoryLifecycleState::Active),
            lifecycle_badge: None,
        }],
        memory_confidence: eliot_types::MemoryConfidence::Found,
        query_mode: "query_aware_semantic_lexical_relational_v2".to_owned(),
        rank_trace: eliot_types::L0RankTrace {
            query: "current candidate".to_owned(),
            normalized_query: "current candidate".to_owned(),
            candidates_considered: 2,
            candidates_returned: 1,
            feature_scores: vec![
                eliot_types::L0FeatureScore {
                    handle: active_handle.clone(),
                    exact_identifier: 0,
                    subject_identity: 0,
                    lexical_overlap: 140,
                    task_relation: 120,
                    scope_fit: 20,
                    lifecycle_fit: 20,
                    evidence_authority: 80,
                    prior_decision_delta: 0,
                    total: 380,
                    reasons: vec!["lexical_and_task_relation".to_owned()],
                    ..Default::default()
                },
                eliot_types::L0FeatureScore {
                    handle: suppressed_handle.clone(),
                    lifecycle_fit: -200,
                    total: -40,
                    reasons: vec!["inactive_lifecycle".to_owned()],
                    ..Default::default()
                },
            ],
            lifecycle_suppressions: vec![eliot_types::L0SuppressionTrace {
                handle: suppressed_handle.clone(),
                reason: "lifecycle_suppressed".to_owned(),
            }],
            scope_suppressions: Vec::new(),
            collapsed_duplicates: Vec::new(),
            no_useful_memory: false,
            query_mode: "query_aware_semantic_lexical_relational_v2".to_owned(),
        },
        truncation: eliot_types::TruncationInfo {
            truncated: false,
            limit: 50,
            returned: 1,
        },
    };
    let l0_records = operator_l0_rank_records(&l0);
    let Some(trace) = l0_records
        .iter()
        .find(|record| record.record_kind == "l0_rank_trace")
    else {
        panic!("rank trace record is absent");
    };
    assert!(trace.fields.iter().any(|field| {
        field.label == "query_mode" && field.value == "query_aware_semantic_lexical_relational_v2"
    }));
    let Some(suppressed) = l0_records
        .iter()
        .find(|record| record.record_ref == format!("l0-candidate:{suppressed_handle}"))
    else {
        panic!("suppressed candidate record is absent");
    };
    assert_eq!(suppressed.status, "suppressed");
    assert!(suppressed.summary.contains("lifecycle_suppressed"));
    assert!(
        suppressed
            .fields
            .iter()
            .any(|field| { field.label == "at_revision" && field.value == "19" })
    );

    let l2 = FetchAtomsL2Response {
        project_id,
        at_revision: MemoryRevision::new(23),
        evidence_atoms: Vec::new(),
        claims: vec![eliot_types::ClaimCard {
            claim_id: active_id,
            statement: "exact canonical claim".to_owned(),
            status: EpistemicStatus::Verified,
            payload: json!({ "receipt_ref": "receipt:exact" }),
        }],
        verification_runs: Vec::new(),
        tool_observations: Vec::new(),
        failure_fingerprints: Vec::new(),
        ul_artifacts: Vec::new(),
        canonical_memory_pages: Vec::new(),
        relations: Vec::new(),
        requested_handles: vec![format!("claim:{active_id}"), "claim:missing".to_owned()],
        returned_handles: vec![format!("claim:{active_id}")],
        missing_handles: vec!["claim:missing".to_owned()],
        forbidden_handles: vec!["claim:foreign".to_owned()],
        continuation: Some("bounded:next".to_owned()),
        truncation: eliot_types::TruncationInfo {
            truncated: true,
            limit: 64,
            returned: 1,
        },
    };
    let l2_records = operator_l2_exact_records(&l2);
    let resolution = &l2_records[0];
    assert_eq!(resolution.record_kind, "l2_exact_resolution");
    for required in [
        "requested_handles",
        "returned_handles",
        "missing_handles",
        "forbidden_handles",
        "continuation",
        "at_revision",
    ] {
        assert!(
            resolution
                .fields
                .iter()
                .any(|field| field.label == required)
        );
    }
    assert!(l2_records.iter().any(|record| {
        record.record_ref == format!("claim:{active_id}")
            && record
                .fields
                .iter()
                .any(|field| field.label == "payload_json" && field.value.contains("receipt:exact"))
    }));
}

#[test]
fn operator_memory_projection_surfaces_no_useful_memory() {
    let response = RecallL0Response {
        project_id: ProjectId::new_v7(),
        at_revision: MemoryRevision::new(7),
        projection_revision: Some(MemoryRevision::new(7)),
        projection_state: eliot_types::CognitiveProjectionReadState::Published,
        handles: Vec::new(),
        memory_confidence: eliot_types::MemoryConfidence::None,
        query_mode: "query_aware_semantic_lexical_relational_v2".to_owned(),
        rank_trace: eliot_types::L0RankTrace {
            query: "absent memory".to_owned(),
            normalized_query: "absent memory".to_owned(),
            no_useful_memory: true,
            query_mode: "query_aware_semantic_lexical_relational_v2".to_owned(),
            ..Default::default()
        },
        truncation: eliot_types::TruncationInfo {
            truncated: false,
            limit: 50,
            returned: 0,
        },
    };
    let records = operator_l0_rank_records(&response);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, "no_useful_memory");
    assert!(
        records[0]
            .fields
            .iter()
            .any(|field| { field.label == "no_useful_memory" && field.value == "true" })
    );
}

#[test]
fn operator_selected_graph_neighborhood_is_bounded_and_preserves_provenance() {
    let mut first = operator_record(
        "edge:1",
        "causal_edge",
        "claim:1 -> evidence:1",
        "supports",
        "observed",
        "task_packet",
        vec![
            operator_field("from", "claim:1", true),
            operator_field("to", "evidence:1", true),
        ],
    );
    first.relationships.push(OperatorRelationshipView {
        relation: "supports".to_owned(),
        target_ref: "evidence:1".to_owned(),
        evidence_ref: Some("receipt:1".to_owned()),
        observed_at: Some("2026-07-16T12:00:00Z".to_owned()),
    });
    let disconnected = operator_record(
        "edge:2",
        "causal_edge",
        "claim:2 -> evidence:2",
        "supports",
        "observed",
        "task_packet",
        vec![
            operator_field("from", "claim:2", true),
            operator_field("to", "evidence:2", true),
        ],
    );
    let selected = operator_selected_neighborhood(vec![first, disconnected], Some("claim:1"), 1);
    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected[0].relationships[0].evidence_ref.as_deref(),
        Some("receipt:1")
    );
    assert!(selected.len() <= 30);
}

#[test]
fn operator_cursor_pages_more_than_256_rows_without_gaps_or_duplicates() -> Result<()> {
    let scope = blake3::hash(b"three-page-operator-proof")
        .to_hex()
        .to_string();
    let source = (0_u64..311).collect::<Vec<_>>();
    let signing_key = [23_u8; 32];
    let mut cursor = None;
    let mut observed = Vec::<u64>::new();
    let mut page_count = 0;
    loop {
        let state = operator_cursor_state(cursor.as_deref(), &scope, &signing_key)?;
        let start = usize::try_from(state.canonical_start)?;
        let page = source
            .iter()
            .skip(start)
            .take(100)
            .copied()
            .collect::<Vec<_>>();
        if page.is_empty() {
            break;
        }
        page_count += 1;
        observed.extend(&page);
        let next = state.canonical_start + u64::try_from(page.len())?;
        cursor = (next < u64::try_from(source.len())?).then(|| {
            operator_cursor(
                OperatorCursorState {
                    base_offset: 0,
                    canonical_start: next,
                    matched_seen: u64::try_from(observed.len()).unwrap_or(u64::MAX),
                },
                &scope,
                &signing_key,
            )
        });
        if cursor.is_none() {
            break;
        }
    }
    assert!(page_count >= 3);
    assert_eq!(observed, source);
    assert_eq!(
        observed
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        source.len()
    );
    Ok(())
}

#[test]
fn operator_canonical_observation_preserves_typed_receipt_body_detail() {
    let record = operator_observation_record(
        eliot_types::ToolObservation {
            observation_id: "observation:1".to_owned(),
            tool_name: "eliot-governor-mcp".to_owned(),
            observation: "canonical autonomy_budget_ledger record".to_owned(),
            payload: json!({
                "receipt_kind": "autonomy_budget_ledger",
                "receipt_body": {
                    "autonomy_run_id": "run:1",
                    "tool_calls_used": 129,
                    "evidence_ref": "receipt:budget",
                    "created_at": "2026-07-16T12:00:00Z"
                }
            }),
            write_id: None,
        },
        "autonomy_budget_ledger",
    );
    assert!(record.fields.iter().any(|field| {
        field.label == "receipt_body_json" && field.value.contains("tool_calls_used")
    }));
    assert!(
        record
            .fields
            .iter()
            .any(|field| { field.label == "tool_calls_used" && field.value == "129" })
    );
    assert!(record.relationships.iter().any(|relationship| {
        relationship.target_ref == "run:1"
            && relationship.evidence_ref.as_deref() == Some("receipt:budget")
            && relationship.observed_at.is_some()
    }));
}

#[test]
fn durable_operator_requests_require_reason_evidence_or_exact_hash() {
    let task_id = TaskId::new_v7();
    assert!(
        validate_operator_command_payload(&OperatorCommand::ArchiveMemory {
            task_id,
            memory_handle: "memory:1".to_owned(),
            reason: String::new(),
        })
        .is_err()
    );
    assert!(
        validate_operator_command_payload(&OperatorCommand::RestoreMemory {
            task_id,
            memory_handle: "memory:1".to_owned(),
            evidence_refs: Vec::new(),
        })
        .is_err()
    );
    assert!(
        validate_operator_command_payload(&OperatorCommand::GrantApproval {
            approval_id: "approval:1".to_owned(),
            exact_action_hash: String::new(),
        })
        .is_err()
    );
}

fn complete_canonical_trace_input(task: &TaskContract) -> TraceCompletenessToolInput {
    let artifact = &task.verification_scopes[0].artifact_refs[0].resource_ref;
    TraceCompletenessToolInput {
        project_id: task.project_id.to_string(),
        task_id: task.task_id.to_string(),
        expected_task_revision: task.memory_revision.value(),
        idempotency_key: "trace-proof".to_owned(),
        trace_ref: "trace:canonical-proof".to_owned(),
        actual_observation_ref: format!("actual_observation:{}", task.observation_ids[0]),
        verifier_run_ref: format!("verifier_run:{}", task.verification_ids[0]),
        artifact_ref: format!("artifact_ref:{artifact}"),
        source_route: "codex-controller".to_owned(),
        source_tool: "eliot_trace_completeness".to_owned(),
        source_verifier: CARGO_WORKSPACE_CHECK_VERIFIER_ID.to_owned(),
        outcome: "verified".to_owned(),
        taint: TaintClass::LocalVerified,
    }
}

#[test]
fn canonical_trace_schema_requires_receiptable_sources_and_derives_ten_parts() -> Result<()> {
    let task = completion_task_fixture();
    let input = complete_canonical_trace_input(&task);
    assert_eq!(
        canonical_derived_trace_references(
            &task,
            trace_ref_value(&input.actual_observation_ref, "actual_observation")?,
            task.verification_ids[0],
            trace_ref_value(&input.artifact_ref, "artifact_ref")?,
            "codex_controller",
        )
        .len(),
        10
    );
    assert_eq!(CanonicalTraceEvidenceKind::ALL.len(), 13);
    let mut fabricated = input;
    fabricated.actual_observation_ref = "actual_observation:not-a-write-id".to_owned();
    assert!(
        WriteId::from_str(trace_ref_value(
            &fabricated.actual_observation_ref,
            "actual_observation"
        )?)
        .is_err()
    );
    Ok(())
}

#[test]
fn canonical_mutation_authority_is_controller_or_operator_only() {
    for tool in [
        "eliot_trace_completeness",
        "eliot_replay_run",
        "eliot_sleep_run",
        "eliot_meta_experiment_run",
        "eliot_meta_experiment_disposition",
    ] {
        assert!(McpAccessProfile::CodexController.allows(tool));
        assert!(McpAccessProfile::HumanOperator.allows(tool));
        assert!(!McpAccessProfile::CodexWorker.allows(tool));
        assert!(!McpAccessProfile::DynamicAgent.allows(tool));
        assert!(!McpAccessProfile::HumanReadonly.allows(tool));
    }
    assert!(!McpAccessProfile::CodexWorker.allows("eliot_canonical_status"));
    assert!(McpAccessProfile::HumanReadonly.allows("eliot_canonical_status"));
}

#[test]
fn canonical_replay_profile_hash_is_stable_and_exposed() -> Result<()> {
    let profile = ReplayRunnerService::deterministic_no_mutation_profile();
    let first = canonical_struct_hash(&profile)?;
    let second = canonical_struct_hash(&profile)?;
    assert_eq!(first, second);
    assert_eq!(profile.profile_id, "deterministic-no-mutation");
    assert!(profile.deterministic && profile.no_external_network && profile.no_mutation);
    Ok(())
}

#[test]
fn canonical_meta_isolation_rejects_protected_mutation() -> Result<()> {
    let base = json!({
        "project_id": ProjectId::new_v7(),
        "task_id": TaskId::new_v7(),
        "expected_task_revision": 1,
        "idempotency_key": "meta-isolation-proof",
        "eval_run_id": EvalRunId::new_v7(),
        "change_class": "verification_map",
        "changed_variables": ["decision_threshold"],
        "baseline_policy": {
            "schema_version": "1", "evaluator_version": "v1",
            "minimum_pass_basis_points": 9000, "maximum_counter_regressions": 0
        },
        "candidate_policy": {
            "schema_version": "1", "evaluator_version": "v1",
            "minimum_pass_basis_points": 10000, "maximum_counter_regressions": 0
        },
        "fixed_baseline_execution_id": "fixed-baseline",
        "fixed_candidate_execution_id": "fixed-candidate",
        "holdout_baseline_execution_id": "holdout-baseline",
        "holdout_candidate_execution_id": "holdout-candidate"
    });
    let sealed: MetaExperimentToolInput = serde_json::from_value(base.clone())?;
    assert!(sealed.attempted_fence.is_none());

    let mut mutated = base;
    mutated["attempted_fence"] = json!({
        "evaluator_version": "tampered",
        "evaluator_hash": "0".repeat(64),
        "threshold_version": "1",
        "threshold_hash": "0".repeat(64),
        "fixed_replay_set_hash": "0".repeat(64),
        "holdout_replay_set_hash": "0".repeat(64)
    });
    let mutated: MetaExperimentToolInput = serde_json::from_value(mutated)?;
    assert!(mutated.attempted_fence.is_some());
    Ok(())
}

#[test]
fn canonical_replay_rejects_one_case_and_caller_verdict_fields_are_absent() -> Result<()> {
    let input = ReplayRunToolInput {
        project_id: ProjectId::new_v7().to_string(),
        task_id: TaskId::new_v7().to_string(),
        expected_task_revision: 1,
        idempotency_key: "single-case".to_owned(),
        trace_refs: vec!["trace:only-one".to_owned()],
        set_name: "fixed-regression".to_owned(),
        set_role: "fixed".to_owned(),
        set_version: 1,
        case_kind: ReplayCaseKind::Regression,
        baseline_policy: ReplayThresholdPolicyV1 {
            schema_version: "1".to_owned(),
            evaluator_version: "v1".to_owned(),
            minimum_pass_basis_points: 9_000,
            maximum_counter_regressions: 0,
        },
        candidate_policy: ReplayThresholdPolicyV1 {
            schema_version: "1".to_owned(),
            evaluator_version: "v1".to_owned(),
            minimum_pass_basis_points: 10_000,
            maximum_counter_regressions: 0,
        },
        baseline_version: "v1".to_owned(),
        candidate_version: "v2".to_owned(),
        sealed_context_version: "context-v1".to_owned(),
        evaluator_version: "v1".to_owned(),
        mutation_attempt: None,
    };
    assert!(validate_canonical_replay_request(&input).is_err());

    let tools = replay_tool_definitions();
    let replay = tools
        .iter()
        .find(|tool| tool["name"] == "eliot_replay_run")
        .context("replay tool schema")?;
    let replay_properties = replay["inputSchema"]["properties"]
        .as_object()
        .context("replay properties")?;
    assert!(!replay_properties.contains_key("observation"));
    assert!(!replay_properties.contains_key("taint_preserved"));

    let meta = tools
        .iter()
        .find(|tool| tool["name"] == "eliot_meta_experiment_run")
        .context("meta tool schema")?;
    let meta_properties = meta["inputSchema"]["properties"]
        .as_object()
        .context("meta properties")?;
    assert!(!meta_properties.contains_key("primary_metrics"));
    assert!(!meta_properties.contains_key("counter_metrics"));
    assert!(!meta_properties.contains_key("candidate_ref"));
    Ok(())
}

#[test]
fn canonical_sleep_rejects_dangling_artifact_and_meta_classes_fail_closed() {
    let artifact = eliot_types::SleepCandidateArtifact {
        artifact_id: "replay-case-candidate:deadbeef".to_owned(),
        project_id: ProjectId::new_v7(),
        artifact_kind: SleepCandidateArtifactKind::ReplayCase,
        source_trace_ref: "trace:canonical".to_owned(),
        source_trace_contract_ref: String::new(),
        body: json!({"schema_version": 1}),
        candidate_only: true,
        taint: TaintClass::Unknown,
        prohibited_direct_effects: vec![eliot_types::ProhibitedDreamEffect::CurrentTruth],
        required_replay: eliot_types::SkillReplayRequirement {
            required: true,
            reason: "replay required".to_owned(),
            replay_marker: None,
            verifier_refs: vec!["deterministic-no-mutation".to_owned()],
        },
        created_at: time::OffsetDateTime::now_utc(),
    };
    assert!(validate_sleep_artifact(&artifact).is_err());
    assert!(meta_change_class_supported(
        MetaCandidateChangeClass::VerificationMap
    ));
    assert!(!meta_change_class_supported(
        MetaCandidateChangeClass::AdmissionRule
    ));
}

#[test]
fn canonical_exact_policy_authorization_rejects_missing_hash() {
    let input = MetaDispositionToolInput {
        project_id: ProjectId::new_v7().to_string(),
        task_id: TaskId::new_v7().to_string(),
        expected_task_revision: 1,
        idempotency_key: "promotion".to_owned(),
        experiment_id: "experiment".to_owned(),
        expected_experiment_revision: 1,
        decision: MetaExperimentDecision::Promoted,
        rollback_requested: false,
        operator_command_ref: "operator:command".to_owned(),
        expected_action_hash: "fabricated".to_owned(),
    };
    assert!(exact_meta_authorization(&input, &"a".repeat(64)).is_err());
    assert!(require_receipted_meta_rejection(true, false).is_err());
    assert!(require_receipted_meta_rejection(true, true).is_ok());
}

#[test]
fn canonical_tool_schemas_are_visible_to_operator_and_status_is_readonly() {
    let operator = tool_definitions_for_profile(McpAccessProfile::HumanOperator);
    let names = operator
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert!(names.contains(&"eliot_trace_completeness"));
    assert!(names.contains(&"eliot_meta_experiment_disposition"));
    assert!(names.contains(&"eliot_canonical_status"));

    let readonly = tool_definitions_for_profile(McpAccessProfile::HumanReadonly);
    let readonly_names = readonly
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert!(readonly_names.contains(&"eliot_canonical_status"));
    assert!(!readonly_names.contains(&"eliot_meta_experiment_disposition"));
}

fn m3_route(host: &str) -> eliot_types::ContourPreferredRoute {
    eliot_types::ContourPreferredRoute {
        host_id: host.to_owned(),
        model_route_optional: None,
        requested_role: "implementer".to_owned(),
        capability_requirements: vec!["rust".to_owned()],
    }
}

fn m3_contract(project_id: ProjectId, task_id: TaskId) -> AutonomyRunContract {
    AutonomyRunContract {
        autonomy_run_id: "m3-integrity-run".to_owned(),
        project_id,
        root_task_id: task_id,
        user_goal: "atomic integrity closure".to_owned(),
        acceptance_items: vec!["m3-acceptance".to_owned()],
        contour_route_policy_ref: "route:m3".to_owned(),
        allowed_projects: vec![project_id],
        max_work_items: 2,
        max_active_agents: 2,
        max_model_invocations: 4,
        max_tool_calls: 8,
        max_wall_time_seconds: 900,
        cost_or_token_budget: Some("10000 tokens".to_owned()),
        allowed_paths: vec!["crates/eliot-app".to_owned()],
        forbidden_paths: vec![".git".to_owned()],
        forbidden_effects: vec!["service_install".to_owned()],
        allowed_risk_tiers: vec!["R1".to_owned()],
        required_verifiers: vec!["cargo test".to_owned()],
        approval_boundaries: vec!["R3".to_owned()],
        pause_conditions: vec!["tripwire".to_owned()],
        stop_conditions: vec!["verified".to_owned()],
        fallback_routes: vec![m3_route("opencode"), m3_route("antigravity")],
        recovery_policy_ref: "recovery:m3".to_owned(),
        policy_snapshot_id: "policy:m3".to_owned(),
        created_by: "test-controller".to_owned(),
        state: AutonomyRunState::Draft,
        state_revision: 0,
        created_at: time::OffsetDateTime::now_utc(),
    }
}

fn m3_scope(path: &str) -> eliot_types::WorkScope {
    eliot_types::WorkScope {
        repo_root: ".".to_owned(),
        read_set: vec![path.to_owned()],
        write_set: vec![path.to_owned()],
        verifier_set: vec!["cargo test".to_owned()],
        authority: eliot_types::AuthorityProfile::bounded_write(),
        risk_tier: eliot_types::RiskTier::Low,
        max_files: 2,
        requires_active_work_lease: true,
    }
}

fn m3_transition(target: AutonomyRunState) -> AutonomyTransitionRequest {
    AutonomyTransitionRequest {
        target,
        reason: format!("advance {target:?}"),
        risk_tier: "R1".to_owned(),
        approval: None,
        verifier_refs: Vec::new(),
    }
}

fn m3_terminal_runtime() -> Result<(BoundedAutonomyRuntime, CompletionProof)> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut runtime = BoundedAutonomyRuntime::new(
        m3_contract(project_id, task_id),
        AutonomyTripwirePolicy::default(),
    )?;
    runtime.transition(&m3_transition(AutonomyRunState::Ready))?;
    runtime.transition(&m3_transition(AutonomyRunState::Running))?;
    let now = time::OffsetDateTime::now_utc();
    for index in 0..2 {
        let work_item_id = WorkItemId::new_v7();
        let holder = AgentId::new_v7();
        runtime.register_work_item(AutonomyWorkItem {
            work_item_id,
            project_id,
            dependencies: Vec::new(),
            status: WorkItemStatus::Open,
            required: true,
            required_verifiers: vec!["cargo test".to_owned()],
            verifier_refs: Vec::new(),
            assigned_agent: None,
            lease: None,
        })?;
        runtime.activate_work_item(
            work_item_id,
            AutonomyLeaseBinding {
                lease_ref: format!("work-lease:{}", WorkLeaseId::new_v7()),
                holder,
                project_id,
                scope: m3_scope(&format!("crates/eliot-app/src/m3-{index}.rs")),
                expires_at: now + time::Duration::hours(1),
            },
            now,
        )?;
        runtime.complete_work_item(
            work_item_id,
            &["cargo test".to_owned()],
            vec![format!("verification:{}", VerificationId::new_v7())],
            now,
        )?;
    }
    runtime.transition(&m3_transition(AutonomyRunState::Verifying))?;
    let proof = CompletionProof {
        task_id: task_id.to_string(),
        project_id,
        goal: "atomic integrity closure".to_owned(),
        changed_files: vec!["crates/eliot-app/src/m3-0.rs".to_owned()],
        memory_refs_used: Vec::new(),
        checks_run: vec!["cargo test".to_owned()],
        checks_not_run: Vec::new(),
        acceptance_items: vec![eliot_types::CompletionAcceptanceItem {
            item: "m3-acceptance".to_owned(),
            status: "verified".to_owned(),
            evidence: "verification:terminal".to_owned(),
            verifier: "cargo test".to_owned(),
            residual_uncertainty: String::new(),
        }],
        evidence: vec!["verification:terminal".to_owned()],
        skill_refs: Vec::new(),
        skill_execution_proof_refs: Vec::new(),
        residual_uncertainty: String::new(),
        known_risks: Vec::new(),
    };
    let mut done = m3_transition(AutonomyRunState::DoneVerified);
    done.verifier_refs = vec!["verification:terminal".to_owned()];
    runtime.complete_verified(&done, &proof)?;
    Ok((runtime, proof))
}

fn m3_aggregate_record(
    runtime: &BoundedAutonomyRuntime,
    proof: CompletionProof,
) -> Result<eliot_store::CanonicalRecord<Value>> {
    let write_id = WriteId::new_v7();
    let budget = AutonomyBudgetRecord {
        autonomy_run_id: runtime.contract.autonomy_run_id.clone(),
        runtime_revision: runtime.runtime_revision,
        ledger: runtime.ledger.clone(),
        usage_evidence_refs: Vec::new(),
    };
    let graph = AutonomyWorkGraphRecord {
        aggregate_schema_version: Some(AUTONOMY_ACTION_AGGREGATE_SCHEMA.to_owned()),
        authoritative_commit: Some(AutonomyActionCommit {
            aggregate_write_id: write_id.to_string(),
            idempotency_key: "m3-terminal".to_owned(),
            action: "complete_run".to_owned(),
            action_fingerprint: "fingerprint".to_owned(),
            committed_state: runtime.contract.state,
            committed_state_revision: runtime.contract.state_revision,
            committed_runtime_revision: runtime.runtime_revision,
            completion_proof_hash: Some(canonical_struct_hash(&proof)?),
        }),
        runtime_snapshot: Some(serde_json::to_value(runtime)?),
        transition_snapshots: runtime.transition_receipts.clone(),
        recovery_snapshots: runtime.recovery_receipts.clone(),
        secondary_transition_snapshots: runtime
            .transition_receipts
            .last()
            .cloned()
            .into_iter()
            .collect(),
        secondary_recovery_snapshots: Vec::new(),
        tripwire_snapshots: Vec::new(),
        budget_snapshot: Some(budget),
        action_result: json!({"status": "committed"}),
        host_result_chains: Vec::new(),
        approval_consumption: None,
        autonomy_run_id: runtime.contract.autonomy_run_id.clone(),
        runtime_revision: runtime.runtime_revision,
        action: "complete_run".to_owned(),
        action_fingerprint: "fingerprint".to_owned(),
        tripwire_policy: runtime.tripwire_policy.clone(),
        work_items: runtime.work_items.clone(),
        host_bindings: Vec::new(),
        transition_refs: runtime
            .transition_receipts
            .iter()
            .map(|item| item.transition_id.clone())
            .collect(),
        recovery_refs: Vec::new(),
        completion_proof: Some(proof),
    };
    Ok(eliot_store::CanonicalRecord {
        record_id: write_id.to_string(),
        receipt_kind: "autonomy_work_graph".to_owned(),
        project_id: runtime.contract.project_id,
        task_id: Some(runtime.contract.root_task_id),
        subject_ref: runtime.contract.autonomy_run_id.clone(),
        receipt_body: serde_json::to_value(graph)?,
        canonical_receipt: WriteReceiptRef {
            receipt_id: ReceiptId::new_v7(),
            write_id,
        },
        memory_revision: Some(MemoryRevision::new(10)),
        project_sequence: None,
    })
}

#[test]
fn m3_terminal_authority_is_one_atomic_proof_bound_aggregate() -> Result<()> {
    let (runtime, proof) = m3_terminal_runtime()?;
    let record = m3_aggregate_record(&runtime, proof)?;
    let decoded =
        decode_authoritative_autonomy_aggregate(&record)?.context("valid terminal aggregate")?;
    assert_eq!(decoded.1.contract.state, AutonomyRunState::DoneVerified);

    let reconnected: eliot_store::CanonicalRecord<Value> =
        serde_json::from_value(serde_json::to_value(&record)?)?;
    let rehydrated = decode_authoritative_autonomy_aggregate(&reconnected)?
        .context("aggregate survives canonical reconnect")?;
    let expected_write_id = record.canonical_receipt.write_id.to_string();
    assert_eq!(
        rehydrated
            .0
            .authoritative_commit
            .as_ref()
            .map(|commit| commit.aggregate_write_id.as_str()),
        Some(expected_write_id.as_str())
    );

    let mut interrupted_after_aggregate = record.clone();
    interrupted_after_aggregate.receipt_body["secondary_transition_snapshots"] = json!([]);
    assert!(decode_authoritative_autonomy_aggregate(&interrupted_after_aggregate)?.is_some());

    let mut missing_proof = record;
    missing_proof.receipt_body["completion_proof"] = Value::Null;
    assert!(decode_authoritative_autonomy_aggregate(&missing_proof)?.is_none());
    Ok(())
}

#[test]
fn m3_legacy_terminal_without_atomic_proof_fails_closed() -> Result<()> {
    let (runtime, _) = m3_terminal_runtime()?;
    let mut contract = runtime.contract.clone();
    contract.state = AutonomyRunState::Verifying;
    contract.state_revision = contract.state_revision.saturating_sub(1);
    let terminal = runtime
        .transition_receipts
        .last()
        .context("terminal transition")?;
    assert!(apply_legacy_autonomy_transitions_fail_closed(
        &mut contract,
        std::slice::from_ref(terminal)
    ));
    assert_ne!(contract.state, AutonomyRunState::DoneVerified);
    Ok(())
}

fn m3_verifier(id: VerificationId, name: &str) -> CanonicalAutonomyVerifierEvidence {
    CanonicalAutonomyVerifierEvidence {
        verification_id: id,
        canonical_ref: format!("verification:{id}"),
        registered_name: name.to_owned(),
        profile_ref: format!("profile:{name}"),
        command: format!("command:{name}"),
        version: "1".to_owned(),
        artifact_scope_hash: format!("scope:{name}"),
        artifact_refs: vec![format!("artifact:{name}")],
        acceptance_item_ids: vec!["m3-acceptance".to_owned()],
        commit_ref: format!("commit:{name}"),
        verifier_ref: format!("verifier:{name}"),
    }
}

#[test]
fn m3_unrelated_passed_verifier_cannot_relabel_required_verifier() {
    let required = m3_verifier(VerificationId::new_v7(), "cargo");
    let unrelated = m3_verifier(VerificationId::new_v7(), "receipt");
    assert!(
        require_exact_canonical_verifier_set(
            &["cargo".to_owned()],
            std::slice::from_ref(&required)
        )
        .is_ok()
    );
    assert!(
        require_exact_canonical_verifier_set(&["cargo".to_owned()], &[required, unrelated])
            .is_err()
    );
}

#[test]
fn m3_missing_host_chain_denial_has_no_receipt() -> Result<()> {
    let (runtime, proof) = m3_terminal_runtime()?;
    let record = m3_aggregate_record(&runtime, proof)?;
    let (graph, runtime) =
        decode_authoritative_autonomy_aggregate(&record)?.context("valid aggregate fixture")?;
    let loaded = LoadedAutonomyRuntime {
        runtime,
        graph,
        canonical: eliot_store::CanonicalAutonomyRunView::default(),
        integrity_status: "authoritative_atomic_aggregate".to_owned(),
    };
    let denied = autonomy_action_denied_response(&loaded, "assign_work", "missing chain");
    assert_eq!(denied.get("accepted").and_then(Value::as_bool), Some(false));
    assert_eq!(
        denied.get("authoritative_aggregate_receipt"),
        Some(&Value::Null)
    );
    assert_eq!(
        denied
            .get("canonical_receipts")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    Ok(())
}

#[test]
fn m3_complete_run_denies_pending_coordination_for_exact_scope() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let unrelated_task_id = TaskId::new_v7();
    let mut work = WorkState::default();
    let _ = MailboxService.send(
        &mut work,
        MailboxSendInput {
            message_id: None,
            project_id,
            task_id,
            sender_session_id: AgentSessionId::new_v7(),
            recipient: MailboxRecipient::Controller,
            kind: MailboxMessageKind::AckRequired,
            payload_ref: "coordination:pending".to_owned(),
            requires_ack: Some(true),
            expires_at: None,
        },
    );

    let Some(denial) = autonomy_stop_coordination_denial_reason(&work, project_id, task_id) else {
        panic!("the target task must be denied while acknowledgement is pending");
    };
    assert!(denial.contains("unacknowledged_control_messages"));
    assert!(
        autonomy_stop_coordination_denial_reason(&work, project_id, unrelated_task_id).is_none()
    );
}

#[tokio::test]
async fn m3_concurrent_distinct_keys_commit_exactly_one_authoritative_receipt() -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let revision = Arc::new(AtomicU64::new(0));
    let receipts = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
    let mut handles = Vec::new();
    for key in ["concurrent-a", "concurrent-b"] {
        let barrier = barrier.clone();
        let revision = revision.clone();
        let receipts = receipts.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let _guard = autonomy_commit_serializer().lock().await;
            let observed = revision.load(Ordering::SeqCst);
            tokio::task::yield_now().await;
            if observed != 0 {
                return json!({
                    "accepted": false,
                    "idempotency_key": key,
                    "authoritative_aggregate_receipt": Value::Null
                });
            }
            revision.store(1, Ordering::SeqCst);
            receipts.lock().await.push(key.to_owned());
            json!({
                "accepted": true,
                "idempotency_key": key,
                "authoritative_aggregate_receipt": format!("receipt:{key}")
            })
        }));
    }
    barrier.wait().await;
    let first = handles.remove(0).await?;
    let second = handles.remove(0).await?;
    let outcomes = [first, second];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome["accepted"] == json!(true))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                outcome["accepted"] == json!(false)
                    && outcome["authoritative_aggregate_receipt"].is_null()
            })
            .count(),
        1
    );
    assert_eq!(receipts.lock().await.len(), 1);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn append_m3_host_chain(
    broker: &mut eliot_types::DelegationState,
    work: &mut WorkState,
    project_id: ProjectId,
    task_id: TaskId,
    host_id: AgentHostId,
    path: &str,
) -> (WorkItemId, AutonomyLeaseBinding) {
    let now = time::OffsetDateTime::now_utc();
    let session_id = AgentSessionId::new_v7();
    let agent_id = AgentId::new_v7();
    let work_item_id = WorkItemId::new_v7();
    let work_lease_id = WorkLeaseId::new_v7();
    let worktree_lease_id = eliot_types::WorktreeLeaseId::new_v7();
    let diff_id = CandidateDiffId::new_v7();
    let role_lease_id = format!("role:{session_id}");
    let invocation_id = format!("invocation:{session_id}");
    let result_id = format!("result:{session_id}");
    let diff_ref = format!("diff:{diff_id}");
    let commit_ref = format!("commit:head-{session_id}");
    let scope = m3_scope(path);
    broker
        .agent_host_sessions
        .push(eliot_types::AgentSessionHostBinding {
            agent_session_id: session_id,
            host_identity: eliot_types::AgentHostIdentity {
                host_id,
                implementation_name: host_id.as_str().to_owned(),
                client_instance_id: format!("client:{session_id}"),
            },
            capability_envelope: AgentCapabilityEnvelope::default(),
            bound_project_id: Some(project_id),
            bound_task_id: Some(task_id),
            task_role_lease_refs: vec![role_lease_id.clone()],
            state: eliot_types::AgentSessionState::Active,
            generation: 1,
            owner_operation_id: None,
            disconnected_at: None,
            disconnect_reason: None,
        });
    broker.task_role_leases.push(eliot_types::TaskRoleLease {
        role_lease_id: role_lease_id.clone(),
        task_id,
        agent_session_id: session_id,
        role: AgentRole::Implementer,
        capability_scope: vec!["rust".to_owned()],
        expires_at: now + time::Duration::hours(1),
        epoch: 1,
        state: eliot_types::AuthorityLeaseState::Active,
        lifetime: eliot_types::AuthorityLeaseLifetime::Persistent,
        owner_operation_id: Some(invocation_id.clone()),
        seal_attempt_id: None,
        generation: 1,
        issued_at: Some(now),
        activated_at: Some(now),
        consumed_at: None,
        revoked_at: None,
        revoke_reason: None,
        superseded_by_epoch: None,
    });
    broker.agent_invocations.push(AgentInvocationRequest {
        invocation_id: invocation_id.clone(),
        project_id,
        task_id,
        work_item_id,
        requested_capabilities: vec!["rust".to_owned()],
        role_lease_id: role_lease_id.clone(),
        role_lease_epoch: 1,
        operation_generation: 1,
        runtime_contract_sha256: None,
        work_lease_id: Some(work_lease_id),
        packet_refs: vec!["packet:m3".to_owned()],
        expected_result_kind: "candidate_diff".to_owned(),
        verifier_ref: "verifier:m3".to_owned(),
        idempotency_key: format!("invoke:{session_id}"),
    });
    broker.operation_jobs.push(eliot_types::OperationJob {
        job_id: format!("job:{session_id}"),
        invocation_id: invocation_id.clone(),
        host_id,
        state: OperationJobState::Completed,
        attempt: 1,
        resume_session_id: None,
        result_ref: Some(result_id.clone()),
        idempotency_key: format!("job:{session_id}"),
        created_at: now,
        updated_at: now,
        generation: 1,
        phase: eliot_types::OperationPhase::Completed,
        phase_started_at: Some(now),
        last_progress_at: Some(now),
        phase_deadline_at: None,
        absolute_deadline_at: None,
        restart_count: 0,
        runtime_contract_sha256: None,
        role_lease_id: Some(role_lease_id),
        role_lease_epoch: Some(1),
    });
    broker.agent_results.push(AgentResultEnvelope {
        result_id: result_id.clone(),
        invocation_id: invocation_id.clone(),
        host_id,
        host_session_id: Some(format!("client:{session_id}")),
        status: AgentResultStatus::Succeeded,
        role_lease_epoch: 1,
        operation_generation: 1,
        summary: "verified host result".to_owned(),
        artifact_refs: vec![diff_ref.clone(), commit_ref],
        evidence_refs: vec!["evidence:m3".to_owned()],
        verifier_refs: vec![format!("verification:{}", VerificationId::new_v7())],
        candidate_only: true,
        exit_status: Some(0),
        token_or_cost_telemetry: None,
        unknown_outcome_evidence_refs: Vec::new(),
        supersedes_result_id: None,
        provider_output_hash: None,
        canonical_receipt: None,
    });
    broker
        .agent_result_dispositions
        .push(eliot_types::AgentResultDisposition {
            disposition_id: format!("disposition:{session_id}"),
            result_id,
            invocation_id,
            task_id,
            controller_session_id: AgentSessionId::new_v7(),
            kind: AgentResultDispositionKind::Accepted,
            reason: "accepted exact candidate".to_owned(),
            evidence_refs: vec![diff_ref.clone()],
            idempotency_key: format!("disposition:{session_id}"),
            created_at: now,
            canonical_receipt: None,
        });
    work.leases.push(WorkLease {
        work_lease_id,
        work_item_id,
        agent_session_id: session_id,
        agent_id,
        project_id,
        task_id,
        role: AgentRole::Implementer,
        state: WorkLeaseState::Granted,
        epoch: 1,
        scope: scope.clone(),
        decision: WorkLeaseDecision {
            kind: WorkLeaseDecisionKind::Granted,
            reason: WorkLeaseDecisionReason::NoConflict,
            message: "granted".to_owned(),
            work_lease_id: Some(work_lease_id),
            conflicting_lease_ids: Vec::new(),
            expires_at: Some(now + time::Duration::hours(1)),
        },
        conflict_refs: Vec::new(),
        granted_at: now,
        expires_at: now + time::Duration::hours(1),
        renewed_at: None,
        released_at: None,
        revoked_at: None,
        write_receipt: None,
    });
    work.worktree_leases.push(WorktreeLease {
        worktree_lease_id,
        project_id,
        task_id,
        work_item_id,
        work_lease_id,
        holder_session_id: session_id,
        repo_root: ".".to_owned(),
        worktree_path: format!("worktree:{session_id}"),
        branch_name: format!("branch-{session_id}"),
        base_commit: "base".to_owned(),
        allowed_read_set: vec![path.to_owned()],
        allowed_write_set: vec![path.to_owned()],
        state: eliot_types::WorktreeLeaseState::Captured,
        issued_at: now,
        expires_at: now + time::Duration::hours(1),
        cleaned_at: None,
        write_receipt: None,
    });
    work.candidate_diffs.push(CandidateDiff {
        candidate_diff_id: diff_id,
        worktree_lease_id,
        project_id,
        task_id,
        work_item_id,
        base_commit: "base".to_owned(),
        worktree_head: Some(format!("head-{session_id}")),
        diff_hash: format!("hash:{session_id}"),
        diff_ref,
        changed_files: vec![path.to_owned()],
        added_files: Vec::new(),
        modified_files: vec![path.to_owned()],
        deleted_files: Vec::new(),
        byte_len: 10,
        file_count: 1,
        capture_status: CandidateDiffStatus::AcceptedForPatchRunner,
        created_at: now,
        write_receipt: None,
    });
    work.candidate_reviews.push(CandidateReview {
        review_id: format!("review:{diff_id}"),
        candidate_diff_id: diff_id,
        reviewer_session_id: AgentSessionId::new_v7(),
        decision: CandidateReviewDecision::AcceptForPatchRunner,
        reasons: vec!["in-scope committed candidate".to_owned()],
        created_at: now,
        patch_request_id: None,
        write_receipt: None,
    });
    (
        work_item_id,
        AutonomyLeaseBinding {
            lease_ref: format!("work-lease:{work_lease_id}"),
            holder: agent_id,
            project_id,
            scope,
            expires_at: now + time::Duration::hours(1),
        },
    )
}

#[test]
fn m3_fake_host_is_denied_and_two_real_host_chains_are_accepted() -> Result<()> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let contract = m3_contract(project_id, task_id);
    let mut broker = eliot_types::DelegationState::default();
    let mut work = WorkState::default();
    let (open_item, open_lease) = append_m3_host_chain(
        &mut broker,
        &mut work,
        project_id,
        task_id,
        AgentHostId::OpenCode,
        "crates/eliot-app/src/opencode.rs",
    );
    assert!(
        require_real_autonomy_host_result_chain(
            &broker,
            &work,
            project_id,
            task_id,
            open_item,
            "codex",
            &open_lease
        )
        .is_err()
    );
    let open_invocation = broker
        .agent_results
        .iter()
        .find(|result| result.host_id == AgentHostId::OpenCode)
        .context("OpenCode result fixture")?
        .invocation_id
        .clone();
    let expected_result_ref = broker
        .agent_results
        .iter()
        .find(|result| result.invocation_id == open_invocation)
        .context("OpenCode result fixture")?
        .result_id
        .clone();
    let open_job = broker
        .operation_jobs
        .iter_mut()
        .find(|job| job.invocation_id == open_invocation)
        .context("OpenCode job fixture")?;
    open_job.result_ref = Some("result:malformed-restored-graph".to_owned());
    assert!(
        require_real_autonomy_host_result_chain(
            &broker,
            &work,
            project_id,
            task_id,
            open_item,
            "opencode",
            &open_lease
        )
        .is_err()
    );
    broker
        .operation_jobs
        .iter_mut()
        .find(|job| job.invocation_id == open_invocation)
        .context("OpenCode job fixture")?
        .result_ref = Some(expected_result_ref);
    let open_chain = require_real_autonomy_host_result_chain(
        &broker,
        &work,
        project_id,
        task_id,
        open_item,
        "opencode",
        &open_lease,
    )?;
    let (agy_item, agy_lease) = append_m3_host_chain(
        &mut broker,
        &mut work,
        project_id,
        task_id,
        AgentHostId::Antigravity,
        "crates/eliot-app/src/antigravity.rs",
    );
    let agy_chain = require_real_autonomy_host_result_chain(
        &broker,
        &work,
        project_id,
        task_id,
        agy_item,
        "antigravity",
        &agy_lease,
    )?;
    require_two_real_host_chains(&contract, &[open_chain, agy_chain])?;
    Ok(())
}

#[test]
fn l12_provider_free_one_drive_source_finalizes_only_in_local_app_data() -> Result<()> {
    let test_id = uuid::Uuid::new_v4().simple().to_string();
    let root = PathBuf::from(format!(r"C:\e12-{}", &test_id[..8]));
    let sync_root = root.join("OneDriveLike");
    let repo = sync_root.join("source-repo");
    let local_app_data = root.join("LocalAppDataLike");
    std::fs::create_dir_all(&repo)?;
    let git = |cwd: &Path, args: &[&str]| -> Result<std::process::Output> {
        Ok(std::process::Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(args)
            .output()?)
    };
    if !git(&repo, &["init"])?.status.success() {
        anyhow::bail!("git init failed");
    }
    std::fs::write(repo.join("fixture.txt"), "before\n")?;
    git(&repo, &["add", "fixture.txt"])?;
    let initial = std::process::Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args([
            "-c",
            "user.name=Eliot Test",
            "-c",
            "user.email=eliot-test@localhost",
            "commit",
            "-m",
            "initial",
        ])
        .output()?;
    if !initial.status.success() {
        anyhow::bail!("initial commit failed");
    }
    let worktree_lease_id = WorktreeLeaseId::new_v7();
    let authority_root = production_worktree_root_from(
        &repo,
        &local_app_data,
        std::slice::from_ref(&sync_root),
        ProjectId::new_v7(),
        TaskId::new_v7(),
        WorkLeaseId::new_v7(),
    )?;
    assert!(authority_root.starts_with(local_app_data.join("Eliot").join("worktrees")));
    assert!(!authority_root.starts_with(&sync_root));
    std::fs::create_dir_all(&authority_root)?;
    let worktree = authority_root.join(worktree_lease_id.to_string());
    let added = std::process::Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args([
            "worktree",
            "add",
            "-b",
            &format!("eliot-test-{worktree_lease_id}"),
        ])
        .arg(&worktree)
        .output()?;
    if !added.status.success() {
        anyhow::bail!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&added.stderr)
        );
    }
    std::fs::write(worktree.join("fixture.txt"), "after\n")?;
    let diff = git(&worktree, &["diff", "--binary", "--", "fixture.txt"])?.stdout;
    if diff.is_empty() {
        anyhow::bail!("provider-free fixture produced no diff");
    }
    let baseline = String::from_utf8(git(&worktree, &["rev-parse", "HEAD"])?.stdout)?
        .trim()
        .to_owned();
    let intent = finalization_intent("local-appdata-authority", baseline, &diff, "fixture.txt")?;
    git(&worktree, &["reset", "--hard", "HEAD"])?;
    let commit = ensure_managed_candidate_commit(&worktree, &intent, &diff)?;
    assert_eq!(
        String::from_utf8(git(&worktree, &["rev-parse", "HEAD"])?.stdout)?.trim(),
        commit
    );
    assert_eq!(
        std::fs::read_to_string(worktree.join("fixture.txt"))?.trim(),
        "after"
    );
    let _ = std::process::Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["worktree", "remove", "--force"])
        .arg(&worktree)
        .output();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn l13_curation_preview_classifies_only_explicit_reversible_findings() {
    fn record(
        project_id: ProjectId,
        task_id: TaskId,
        handle: &str,
        curation: &Value,
    ) -> CanonicalRecord<Value> {
        let write_id = WriteId::new_v7();
        CanonicalRecord {
            record_id: write_id.to_string(),
            receipt_kind: "claim_card".to_owned(),
            project_id,
            task_id: Some(task_id),
            subject_ref: handle.to_owned(),
            receipt_body: json!({"payload": {"curation": curation}}),
            canonical_receipt: WriteReceiptRef {
                receipt_id: ReceiptId::new_v7(),
                write_id,
            },
            memory_revision: Some(MemoryRevision::new(7)),
            project_sequence: None,
        }
    }

    assert!(READ_ONLY_TOOLS.contains(&"eliot_memory_curation_preview"));
    assert!(!McpAccessProfile::ExternalAuditor.allows("eliot_memory_curation_preview"));
    assert!(memory_lifecycle_tool_definitions().iter().any(|tool| {
        tool.get("name").and_then(Value::as_str) == Some("eliot_memory_curation_preview")
    }));

    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let records = vec![
        record(
            project_id,
            task_id,
            "memory:duplicate",
            &json!({"duplicate_of": "memory:current", "evidence_refs": ["evidence:1"]}),
        ),
        record(
            project_id,
            task_id,
            "memory:wrong-scope",
            &json!({"scope_match": false, "wrong_scope_for": ["scope:other"]}),
        ),
        record(
            project_id,
            task_id,
            "memory:low-utility",
            &json!({"utility_score": 10, "evidence_sufficient": false}),
        ),
        record(
            project_id,
            task_id,
            "memory:stale",
            &json!({"superseded_by": "memory:current"}),
        ),
        record(
            project_id,
            task_id,
            "memory:semantic-duplicate",
            &json!({
                "semantic_duplicate_of": "memory:current",
                "semantic_equivalence_verified": true
            }),
        ),
        record(
            project_id,
            task_id,
            "memory:zero-delta",
            &json!({
                "utility_delta": 0,
                "repeat_count": 3,
                "repeated_with": ["memory:cargo-1", "memory:cargo-2"]
            }),
        ),
        record(
            project_id,
            task_id,
            "memory:unsafe-instruction",
            &json!({
                "unsafe_instruction": true,
                "evidence_sufficient": true,
                "unsafe_evidence_refs": ["evidence:safety-verifier"]
            }),
        ),
        record(
            project_id,
            task_id,
            "memory:counterexample",
            &json!({"protected": true, "role": "counterexample"}),
        ),
        CanonicalRecord {
            receipt_body: json!({
                "status": "verified",
                "payload": {"curation": {"duplicate_of": "memory:older"}}
            }),
            ..record(
                project_id,
                task_id,
                "memory:current-verified",
                &json!({"duplicate_of": "memory:older"}),
            )
        },
        record(
            project_id,
            task_id,
            "memory:active-negative",
            &json!({
                "role": "failure_fingerprint",
                "reopen_condition_met": false,
                "utility_score": 0,
                "evidence_sufficient": false
            }),
        ),
        record(
            project_id,
            task_id,
            "memory:audit-history",
            &json!({
                "role": "audit_history",
                "audit_required": true,
                "utility_score": 0,
                "evidence_sufficient": false
            }),
        ),
        CanonicalRecord {
            receipt_kind: "minority_pressure_record".to_owned(),
            ..record(
                project_id,
                task_id,
                "memory:minority-pressure",
                &json!({"duplicate_of": "memory:current"}),
            )
        },
        record(
            project_id,
            task_id,
            "memory:globally-protected",
            &json!({"duplicate_of": "memory:current"}),
        ),
        CanonicalRecord {
            receipt_kind: "minority_pressure_record".to_owned(),
            ..record(
                project_id,
                task_id,
                "memory:globally-protected",
                &json!({"role": "minority"}),
            )
        },
        record(
            project_id,
            task_id,
            "memory:useful",
            &json!({"utility_score": 95, "evidence_sufficient": true}),
        ),
        CanonicalRecord {
            receipt_body: json!({
                "lifecycle_status": "active",
                "lifecycle_transitions": ["archived"],
                "payload": {"curation": {"duplicate_of": "memory:current"}}
            }),
            ..record(
                project_id,
                task_id,
                "memory:already-archived",
                &json!({"duplicate_of": "memory:current"}),
            )
        },
    ];
    let (mut candidates, mut protected, profile) = analyze_curation_records(&records, true);
    protected.sort();
    protected.dedup();
    remove_protected_curation_candidates(&mut candidates, &protected);
    assert_eq!(candidates.len(), 7);
    assert_eq!(protected.len(), 6);
    assert!(protected.iter().any(|item| item == "memory:counterexample"));
    assert!(
        protected
            .iter()
            .any(|item| item == "memory:current-verified")
    );
    assert!(
        protected
            .iter()
            .any(|item| item == "memory:active-negative")
    );
    assert!(protected.iter().any(|item| item == "memory:audit-history"));
    assert!(
        protected
            .iter()
            .any(|item| item == "memory:minority-pressure")
    );
    assert!(
        protected
            .iter()
            .any(|item| item == "memory:globally-protected")
    );
    assert_eq!(profile.scanned_records, 16);
    assert!(!profile.scan_truncated);
    assert!(candidates.iter().all(|candidate| {
        matches!(
            candidate.proposed_reversible_action.as_str(),
            "archive" | "suppress" | "propose_archive"
        )
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate.handle == "memory:stale"
            && candidate.proposed_reversible_action == "propose_archive"
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate.handle == "memory:low-utility"
            && candidate.proposed_reversible_action == "propose_archive"
    }));
    assert!(
        !candidates
            .iter()
            .any(|candidate| candidate.handle == "memory:useful")
    );
    assert!(
        !candidates
            .iter()
            .any(|candidate| candidate.handle == "memory:already-archived")
    );
    assert!(
        !candidates
            .iter()
            .any(|candidate| candidate.handle == "memory:globally-protected")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn l14_curation_corpus_meets_precision_recall_and_protection_gates() -> Result<()> {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../tests/cognitive/memory-curation/curation-corpus.json"
    ))?;
    let seeded = corpus["records"]
        .as_array()
        .context("memory-curation corpus records must be an array")?;
    assert_eq!(seeded.len(), 22);
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut records = Vec::new();
    let mut actionable = BTreeSet::new();
    let mut protected_expected = BTreeSet::new();
    let mut proposal_expected = BTreeSet::new();
    for seed in seeded {
        let handle = seed["seed_key"]
            .as_str()
            .context("curation seed has no seed_key")?
            .to_owned();
        match seed.pointer("/hidden/class").and_then(Value::as_str) {
            Some("actionable") => {
                actionable.insert(handle.clone());
            }
            Some("protected") => {
                protected_expected.insert(handle.clone());
            }
            Some("proposal_only") => {
                proposal_expected.insert(handle.clone());
            }
            _ => {}
        }
        let write_id = WriteId::new_v7();
        records.push(CanonicalRecord {
            record_id: write_id.to_string(),
            receipt_kind: "claim_card".to_owned(),
            project_id,
            task_id: Some(task_id),
            subject_ref: handle,
            receipt_body: json!({"payload": {"curation": seed["curation"].clone()}}),
            canonical_receipt: WriteReceiptRef {
                receipt_id: ReceiptId::new_v7(),
                write_id,
            },
            memory_revision: Some(MemoryRevision::new(7)),
            project_sequence: None,
        });
    }
    for writer_scored in ["action-low-utility", "action-zero-delta"] {
        assert!(actionable.remove(writer_scored));
        proposal_expected.insert(writer_scored.to_owned());
    }

    let (mut candidates, mut protected, profile) = analyze_curation_records(&records, true);
    protected.sort();
    protected.dedup();
    remove_protected_curation_candidates(&mut candidates, &protected);
    let applied = candidates
        .iter()
        .filter(|candidate| candidate.proposed_reversible_action != "propose_archive")
        .map(|candidate| candidate.handle.clone())
        .collect::<BTreeSet<_>>();
    let proposals = candidates
        .iter()
        .filter(|candidate| candidate.proposed_reversible_action == "propose_archive")
        .map(|candidate| candidate.handle.clone())
        .collect::<BTreeSet<_>>();
    let protected = protected.into_iter().collect::<BTreeSet<_>>();
    let true_positives = applied.intersection(&actionable).count();

    assert!(
        true_positives * 10 >= applied.len() * 9,
        "curation precision counts were {true_positives}/{}",
        applied.len()
    );
    assert!(
        true_positives * 5 >= actionable.len() * 4,
        "curation recall counts were {true_positives}/{}",
        actionable.len()
    );
    assert_eq!(applied, actionable);
    assert_eq!(proposals, proposal_expected);
    assert!(
        candidates
            .iter()
            .filter(|candidate| {
                matches!(
                    candidate.handle.as_str(),
                    "action-low-utility" | "action-zero-delta"
                )
            })
            .all(|candidate| {
                candidate.confidence == 40
                    && candidate.evidence_refs.iter().any(|evidence| {
                        evidence.contains("writer_utility")
                            && evidence.contains("not_canonical_evidence")
                    })
            })
    );
    assert_eq!(protected, protected_expected);
    assert!(candidates.iter().all(|candidate| {
        matches!(
            candidate.proposed_reversible_action.as_str(),
            "archive" | "suppress" | "propose_archive"
        )
    }));
    assert_eq!(profile.scanned_records, 22);
    assert!(!profile.scan_truncated);
    Ok(())
}

#[test]
fn c4_distillation_projection_preserves_exact_and_near_miss_boundaries() -> Result<()> {
    fn record(
        project_id: ProjectId,
        task_id: TaskId,
        handle: &str,
        body: Value,
    ) -> CanonicalRecord<Value> {
        let write_id = WriteId::new_v7();
        CanonicalRecord {
            record_id: write_id.to_string(),
            receipt_kind: "claim_card".to_owned(),
            project_id,
            task_id: Some(task_id),
            subject_ref: handle.to_owned(),
            receipt_body: body,
            canonical_receipt: WriteReceiptRef {
                receipt_id: ReceiptId::new_v7(),
                write_id,
            },
            memory_revision: Some(MemoryRevision::new(12)),
            project_sequence: None,
        }
    }

    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    for tool_name in [
        "eliot_memory_distillation_preview",
        "eliot_memory_distillation_schedule",
        "eliot_memory_distillation_apply",
    ] {
        assert!(
            memory_lifecycle_tool_definitions()
                .iter()
                .any(|tool| tool.get("name").and_then(Value::as_str) == Some(tool_name))
        );
    }
    assert!(READ_ONLY_TOOLS.contains(&"eliot_memory_distillation_preview"));
    assert!(READ_ONLY_TOOLS.contains(&"eliot_memory_distillation_schedule"));
    assert!(!READ_ONLY_TOOLS.contains(&"eliot_memory_distillation_apply"));
    assert!(McpAccessProfile::HumanOperator.allows("eliot_memory_distillation_apply"));
    assert!(!McpAccessProfile::CodexWorker.allows("eliot_memory_distillation_apply"));

    let shared = json!({
        "payload": {
            "curation": {
                "statement": "Use the canonical revision fence",
                "mechanism": "stable pagination",
                "scope": "project:alpha",
                "applies_when": ["canonical scan"],
                "does_not_apply_when": ["foreign project"],
                "verifier_refs": ["test:c4"],
                "utility_score": 999_999
            }
        }
    });
    let near = json!({
        "payload": {
            "curation": {
                "statement": "Use the canonical revision fence",
                "mechanism": "stable pagination",
                "scope": "project:alpha",
                "applies_when": ["canonical scan"],
                "does_not_apply_when": ["interactive write load"],
                "counterexamples": ["revision drift"],
                "verifier_refs": ["test:c4"]
            }
        }
    });
    let records = vec![
        record(project_id, task_id, "claim:physical-a", shared.clone()),
        record(project_id, task_id, "claim:physical-b", shared),
        record(project_id, task_id, "claim:near-miss", near),
    ];

    let items = canonical_distillation_items(&records)?;
    assert_eq!(items.len(), 3);
    assert_eq!(items[0].content_hash, items[1].content_hash);
    assert_ne!(items[0].content_hash, items[2].content_hash);
    assert_eq!(items[0].mechanism, "stable pagination");
    assert_eq!(items[2].counterexamples, ["revision drift"]);
    assert_eq!(items[2].does_not_apply_when, ["interactive write load"]);
    assert!(items.iter().all(|item| {
        item.evidence_refs
            .iter()
            .any(|evidence| evidence.starts_with("receipt:"))
    }));
    Ok(())
}
