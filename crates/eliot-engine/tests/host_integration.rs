#![allow(clippy::expect_used, clippy::too_many_lines)]

use eliot_engine::{
    HostBrokerService, HostEventService, HostLaunchContractService, SkillPackService, bundle_hash,
    host_profile_fingerprint,
};
use eliot_types::{
    AgentCapabilityEnvelope, AgentHostId, AgentHostIdentity, AgentHostRuntimeProfile,
    AgentInvocationRequest, AgentResultDispositionKind, AgentResultEnvelope, AgentResultStatus,
    AgentRole, AgentSessionHostBinding, AgentSessionId, AgentSessionState, AuthorityLeaseLifetime,
    AuthorityLeaseState, DelegationState, HostLaunchScope, HostMode, HostProfileStatus,
    HostProtocolSurfaces, OperationJob, OperationJobState, OperationPhase, ProjectId, TaskId,
    TaskRoleLease, WorkItemId,
};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("engine crate is inside the workspace")
        .to_path_buf()
}

fn profile(host_id: AgentHostId, status: HostProfileStatus) -> AgentHostRuntimeProfile {
    AgentHostRuntimeProfile {
        host_id,
        implementation_name: host_id.as_str().to_owned(),
        executable_path: format!("C:/fixture/{}.exe", host_id.as_str()),
        executable_hash: "blake3:fixture".to_owned(),
        version: "fixture-1".to_owned(),
        discovered_at: OffsetDateTime::now_utc(),
        supported_modes: vec![
            "interactive_client".to_owned(),
            "supervised_noninteractive".to_owned(),
        ],
        protocol_surfaces: HostProtocolSurfaces {
            mcp_stdio: true,
            skills: true,
            structured_output: true,
            ..HostProtocolSurfaces::default()
        },
        launch_capabilities: vec!["fixture".to_owned()],
        result_capture: vec!["structured".to_owned()],
        resume_contract: "recorded session only".to_owned(),
        timeout_and_unknown_outcome_contract: "reconcile before retry".to_owned(),
        known_version_constraints: Vec::new(),
        operator_configuration_refs: Vec::new(),
        capability_probe_receipt: "blake3:profile".to_owned(),
        status,
    }
}

#[test]
fn canonical_skill_pack_has_exact_host_parity_and_budget() {
    let report = SkillPackService
        .lint(&repo_root())
        .expect("lint skill pack");
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.skill_count, 4);
    assert!(report.listing_characters.div_ceil(4) <= 100);
    assert!(report.entries.iter().all(|entry| entry.opencode_parity
        && entry.claude_parity
        && entry.package_parity.get("codex") == Some(&true)
        && entry.package_parity.get("antigravity") == Some(&true)));
}

#[test]
fn opencode_bundle_hash_ignores_host_generated_dependency_cache() {
    let root = std::env::temp_dir().join(format!("eliot-l7-{}", TaskId::new_v7()));
    std::fs::create_dir_all(root.join("plugins")).expect("create fixture bundle");
    std::fs::write(root.join("opencode.json"), b"{}\n").expect("write canonical config");
    std::fs::write(root.join("plugins/eliot.js"), b"export const Eliot = {}\n")
        .expect("write canonical plugin");
    let canonical = bundle_hash(&root, AgentHostId::OpenCode).expect("hash canonical bundle");

    std::fs::create_dir_all(root.join("node_modules/generated")).expect("create cache");
    std::fs::write(root.join("node_modules/generated/cache.js"), b"generated\n")
        .expect("write cache");
    std::fs::write(root.join("package.json"), b"{\"generated\":true}\n")
        .expect("write generated manifest");
    let with_cache = bundle_hash(&root, AgentHostId::OpenCode).expect("hash cached bundle");

    assert_eq!(canonical, with_cache);
    std::fs::remove_dir_all(root).expect("remove fixture bundle");
}

#[test]
fn sealed_reader_is_direct_without_globally_disabling_opencode_subagents() {
    let config: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repo_root().join("integrations/opencode/opencode.json"))
            .expect("read managed OpenCode config"),
    )
    .expect("parse managed OpenCode config");
    assert!(config.get("subagent_depth").is_none());
    assert!(config.get("permission").is_none());

    let prompt = std::fs::read_to_string(
        repo_root().join("tests/cognitive/cognitive-contract/templates/sealed-host-prompt.txt"),
    )
    .expect("read sealed cognitive prompt");
    assert!(prompt.contains("Solve this sealed reader task directly"));
    assert!(prompt.contains("Do not delegate unless the host genuinely requires it"));
    assert!(prompt.contains("exact controller-selected host/model route"));
    assert!(prompt.contains("rejoin the result through this governed parent path"));
}

#[test]
fn host_identity_is_not_role_and_role_can_invert_per_task() {
    let open_session = AgentSessionId::new_v7();
    let claude_session = AgentSessionId::new_v7();
    let open_binding = AgentSessionHostBinding {
        agent_session_id: open_session,
        host_identity: AgentHostIdentity {
            host_id: AgentHostId::OpenCode,
            implementation_name: "OpenCode".to_owned(),
            client_instance_id: "fixture-open".to_owned(),
        },
        capability_envelope: AgentCapabilityEnvelope::default(),
        bound_project_id: None,
        bound_task_id: None,
        task_role_lease_refs: Vec::new(),
        state: AgentSessionState::Active,
        generation: 1,
        owner_operation_id: None,
        disconnected_at: None,
        disconnect_reason: None,
    };
    let serialized = serde_json::to_value(&open_binding).expect("serialize binding");
    assert!(serialized.get("role").is_none());
    assert!(serialized.get("authority").is_none());

    let task = TaskId::new_v7();
    let open_controller = TaskRoleLease {
        role_lease_id: "role:open-controller".to_owned(),
        task_id: task,
        agent_session_id: open_session,
        role: AgentRole::Controller,
        capability_scope: vec!["delegate".to_owned()],
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
        epoch: 1,
        state: AuthorityLeaseState::Active,
        lifetime: eliot_types::AuthorityLeaseLifetime::Persistent,
        owner_operation_id: None,
        seal_attempt_id: None,
        generation: 1,
        issued_at: None,
        activated_at: None,
        consumed_at: None,
        revoked_at: None,
        revoke_reason: None,
        superseded_by_epoch: None,
    };
    let claude_worker = TaskRoleLease {
        role_lease_id: "role:claude-worker".to_owned(),
        task_id: task,
        agent_session_id: claude_session,
        role: AgentRole::Implementer,
        capability_scope: vec!["review".to_owned()],
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
        epoch: 1,
        state: AuthorityLeaseState::Active,
        lifetime: eliot_types::AuthorityLeaseLifetime::Persistent,
        owner_operation_id: None,
        seal_attempt_id: None,
        generation: 1,
        issued_at: None,
        activated_at: None,
        consumed_at: None,
        revoked_at: None,
        revoke_reason: None,
        superseded_by_epoch: None,
    };
    assert_eq!(open_controller.role, AgentRole::Controller);
    assert_eq!(claude_worker.role, AgentRole::Implementer);
}

#[test]
fn launch_contract_has_stable_idempotency_and_immutable_hash() {
    let root = repo_root();
    let profile = profile(AgentHostId::OpenCode, HostProfileStatus::Current);
    let agent_session_id = AgentSessionId::new_v7();
    let scope = HostLaunchScope {
        agent_session_id: Some(agent_session_id),
        planned_verifier_ref: Some("eliot/verifier/fixture@v1#blake3:fixture-a".to_owned()),
        ..HostLaunchScope::default()
    };
    let first = HostLaunchContractService
        .render(
            &root,
            &profile,
            HostMode::Supervised,
            &root,
            Some("opencode/nemotron-3-ultra-free".to_owned()),
            None,
            &scope,
        )
        .expect("render first contract");
    let second = HostLaunchContractService
        .render(
            &root,
            &profile,
            HostMode::Supervised,
            &root,
            Some("opencode/nemotron-3-ultra-free".to_owned()),
            None,
            &scope,
        )
        .expect("render second contract");
    assert_eq!(first.idempotency_key, second.idempotency_key);
    assert_ne!(first.invocation_id, second.invocation_id);
    assert_eq!(first.agent_session_id, Some(agent_session_id));
    assert_eq!(first.planned_verifier_ref, scope.planned_verifier_ref);
    let changed_scope = HostLaunchScope {
        planned_verifier_ref: Some("eliot/verifier/fixture@v1#blake3:fixture-b".to_owned()),
        ..scope.clone()
    };
    let changed = HostLaunchContractService
        .render(
            &root,
            &profile,
            HostMode::Supervised,
            &root,
            Some("opencode/nemotron-3-ultra-free".to_owned()),
            None,
            &changed_scope,
        )
        .expect("render verifier-changed contract");
    assert_ne!(first.idempotency_key, changed.idempotency_key);
    assert_ne!(first.contract_hash, changed.contract_hash);
    assert!(
        first
            .environment_allowlist
            .iter()
            .any(|name| name == "ELIOT_AGENT_SESSION_ID")
    );
    assert!(
        first
            .environment_allowlist
            .iter()
            .any(|name| name == "ELIOT_GOVERNOR_CONFIG")
    );
    let mut unhashed = first.clone();
    let expected = unhashed.contract_hash.clone();
    unhashed.contract_hash.clear();
    assert_eq!(
        expected,
        blake3::hash(&serde_json::to_vec(&unhashed).expect("serialize contract"))
            .to_hex()
            .to_string()
    );
}

#[test]
fn stale_runtime_profile_cannot_render_supervised_launch() {
    let root = repo_root();
    let error = HostLaunchContractService
        .render(
            &root,
            &profile(AgentHostId::Claude, HostProfileStatus::Stale),
            HostMode::Supervised,
            &root,
            None,
            None,
            &HostLaunchScope::default(),
        )
        .expect_err("stale profile must be blocked");
    assert!(error.to_string().contains("run host inspect"));
}

#[test]
fn executable_or_parser_change_invalidates_runtime_profile() {
    let initial = host_profile_fingerprint("hash-a", "1.0", "--model --resume");
    assert_ne!(
        initial,
        host_profile_fingerprint("hash-b", "1.0", "--model --resume")
    );
    assert_ne!(
        initial,
        host_profile_fingerprint("hash-a", "1.1", "--model --resume")
    );
    assert_ne!(
        initial,
        host_profile_fingerprint("hash-a", "1.0", "--model --session")
    );
}

#[test]
fn connected_session_profile_does_not_require_a_local_cli() {
    let binding = AgentSessionHostBinding {
        agent_session_id: AgentSessionId::new_v7(),
        host_identity: AgentHostIdentity {
            host_id: AgentHostId::Codex,
            implementation_name: "Codex connected session".to_owned(),
            client_instance_id: "connected-codex".to_owned(),
        },
        capability_envelope: AgentCapabilityEnvelope {
            capabilities: vec!["verify".to_owned()],
            structured_output: true,
            interactive: true,
            ..AgentCapabilityEnvelope::default()
        },
        bound_project_id: None,
        bound_task_id: None,
        task_role_lease_refs: Vec::new(),
        state: AgentSessionState::Active,
        generation: 1,
        owner_operation_id: None,
        disconnected_at: None,
        disconnect_reason: None,
    };
    let profile = eliot_engine::HostProfileService.connected(&binding);
    assert_eq!(profile.status, HostProfileStatus::Current);
    assert_eq!(profile.supported_modes, ["connected_session"]);
    assert!(
        profile
            .executable_path
            .starts_with("connected-session://codex/")
    );
}

#[test]
fn host_broker_operation_bound_authority_adopts_one_exact_job() {
    let mut state = DelegationState::default();
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = AgentSessionId::new_v7();
    let operation_id = "operation:authority-lifecycle-fixture";
    HostBrokerService
        .register_session_generation(
            &mut state,
            session_id,
            AgentHostId::Claude,
            "claude-fixture".to_owned(),
            operation_id.to_owned(),
            AgentCapabilityEnvelope {
                capabilities: vec!["emit_candidate_observation".to_owned()],
                structured_output: true,
                resumable: true,
                interactive: false,
                supervised: true,
            },
            7,
            Some(operation_id.to_owned()),
        )
        .expect("register operation owner");
    HostBrokerService
        .bind_session_scope(&mut state, session_id, project_id, task_id)
        .expect("bind operation owner");
    let mut grant = HostBrokerService
        .prepare_role_grant(
            &state,
            task_id,
            session_id,
            AgentRole::Auditor,
            vec!["emit_candidate_observation".to_owned()],
            5,
            Some(operation_id.to_owned()),
        )
        .expect("prepare operation role");
    grant.role_lease_id = "operation-role-lease:fixture".to_owned();
    let now = OffsetDateTime::now_utc();
    state.operation_jobs.push(OperationJob {
        job_id: operation_id.to_owned(),
        invocation_id: operation_id.to_owned(),
        host_id: AgentHostId::Claude,
        state: OperationJobState::Queued,
        attempt: 0,
        resume_session_id: None,
        result_ref: None,
        idempotency_key: "operation-authority-fixture".to_owned(),
        created_at: now,
        updated_at: now,
        generation: 7,
        phase: OperationPhase::Prepared,
        phase_started_at: Some(now),
        last_progress_at: Some(now),
        phase_deadline_at: Some(grant.expires_at),
        absolute_deadline_at: Some(grant.expires_at),
        restart_count: 0,
        runtime_contract_sha256: None,
        role_lease_id: Some(grant.role_lease_id.clone()),
        role_lease_epoch: Some(grant.epoch),
    });
    let lease = HostBrokerService
        .activate_role_grants(
            &mut state,
            &[grant],
            AuthorityLeaseLifetime::OperationBound,
            None,
            7,
        )
        .expect("activate operation-bound role")
        .pop()
        .expect("one activated lease");
    HostBrokerService
        .transition(
            &mut state.operation_jobs[0],
            OperationJobState::Running,
            None,
        )
        .expect("start owner job");
    let request = AgentInvocationRequest {
        invocation_id: operation_id.to_owned(),
        project_id,
        task_id,
        work_item_id: WorkItemId::new_v7(),
        requested_capabilities: vec!["emit_candidate_observation".to_owned()],
        role_lease_id: lease.role_lease_id,
        role_lease_epoch: lease.epoch,
        operation_generation: 7,
        runtime_contract_sha256: Some("b".repeat(64)),
        work_lease_id: None,
        packet_refs: Vec::new(),
        expected_result_kind: "provider_execution_evidence".to_owned(),
        verifier_ref: "fixture-verifier".to_owned(),
        idempotency_key: "operation-authority-fixture".to_owned(),
    };
    let adopted = HostBrokerService
        .enqueue(
            &mut state,
            &request,
            &profile(AgentHostId::Claude, HostProfileStatus::Current),
            true,
        )
        .expect("adopt operation owner job");
    assert_eq!(adopted.job_id, operation_id);
    assert_eq!(state.operation_jobs.len(), 1);
    assert_eq!(state.agent_invocations, vec![request]);
    assert_eq!(
        state.operation_jobs[0].runtime_contract_sha256,
        Some("b".repeat(64))
    );
}

#[test]
fn lifecycle_normalization_stores_hash_and_decision_fields_not_raw_payload() {
    let raw = br#"{"event_kind":"tool.execute.after","tool":"edit","path":"src/lib.rs","secret":"must-not-persist"}"#;
    let event = HostEventService
        .normalize(AgentHostId::OpenCode, "event", raw)
        .expect("normalize event");
    let value = serde_json::to_string(&event).expect("serialize normalized event");
    assert_eq!(event.tool_or_command.as_deref(), Some("edit"));
    assert_eq!(event.changed_path_refs, ["src/lib.rs"]);
    assert!(event.raw_event_ref.is_none());
    assert!(!value.contains("must-not-persist"));
    assert!(!value.contains("secret"));
}

#[test]
fn reconnect_reuses_exact_agent_session_binding_and_role_refs() {
    let mut state = DelegationState::default();
    let session = AgentSessionId::new_v7();
    HostBrokerService
        .register_session(
            &mut state,
            session,
            AgentHostId::Codex,
            "Codex registered session".to_owned(),
            "codex-controller".to_owned(),
            AgentCapabilityEnvelope::default(),
        )
        .expect("register Codex session");
    let (role, _) = HostBrokerService
        .grant_role(
            &mut state,
            TaskId::new_v7(),
            session,
            AgentRole::Verifier,
            vec!["verify".to_owned()],
            30,
        )
        .expect("grant verifier role");

    let reconnected = HostBrokerService
        .register_session(
            &mut state,
            session,
            AgentHostId::Codex,
            "Codex MCP reconnect".to_owned(),
            session.to_string(),
            AgentCapabilityEnvelope {
                capabilities: vec!["mcp_stdio".to_owned()],
                ..AgentCapabilityEnvelope::default()
            },
        )
        .expect("reuse exact Codex session");

    assert_eq!(state.agent_host_sessions.len(), 1);
    assert_eq!(reconnected.task_role_lease_refs, [role.role_lease_id]);
    assert!(
        HostBrokerService
            .register_session(
                &mut state,
                session,
                AgentHostId::Claude,
                "Claude".to_owned(),
                "claude-collision".to_owned(),
                AgentCapabilityEnvelope::default(),
            )
            .is_err()
    );
}

#[test]
fn registered_host_session_has_one_immutable_governor_project_task_scope() {
    let mut state = DelegationState::default();
    let session = AgentSessionId::new_v7();
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    HostBrokerService
        .register_session(
            &mut state,
            session,
            AgentHostId::OpenCode,
            "OpenCode".to_owned(),
            "scope-binding-fixture".to_owned(),
            AgentCapabilityEnvelope::default(),
        )
        .expect("register session");

    let bound = HostBrokerService
        .bind_session_scope(&mut state, session, project_id, task_id)
        .expect("bind canonical scope");
    assert_eq!(bound.bound_project_id, Some(project_id));
    assert_eq!(bound.bound_task_id, Some(task_id));
    let replay = HostBrokerService
        .bind_session_scope(&mut state, session, project_id, task_id)
        .expect("same scope is idempotent");
    assert_eq!(replay, bound);

    let project_error = HostBrokerService
        .bind_session_scope(&mut state, session, ProjectId::new_v7(), task_id)
        .expect_err("project rebind must fail");
    assert!(project_error.to_string().contains("different project"));
    let task_error = HostBrokerService
        .bind_session_scope(&mut state, session, project_id, TaskId::new_v7())
        .expect_err("task rebind must fail");
    assert!(task_error.to_string().contains("different task"));
    assert_eq!(state.agent_host_sessions[0], bound);
}

#[test]
fn shared_broker_supports_role_inversion_idempotency_and_candidate_results() {
    let mut state = DelegationState::default();
    let open_session = AgentSessionId::new_v7();
    let claude_session = AgentSessionId::new_v7();
    for (session, host) in [
        (open_session, AgentHostId::OpenCode),
        (claude_session, AgentHostId::Claude),
    ] {
        HostBrokerService
            .register_session(
                &mut state,
                session,
                host,
                host.as_str().to_owned(),
                format!("fixture-{}", host.as_str()),
                AgentCapabilityEnvelope {
                    capabilities: vec!["delegate".to_owned(), "review".to_owned()],
                    structured_output: true,
                    resumable: true,
                    interactive: true,
                    supervised: true,
                },
            )
            .expect("register host session");
    }

    let first_task = TaskId::new_v7();
    let (_open_controller, controller) = HostBrokerService
        .grant_role(
            &mut state,
            first_task,
            open_session,
            AgentRole::Controller,
            vec!["delegate".to_owned()],
            30,
        )
        .expect("grant OpenCode controller role");
    assert!(controller.is_some());
    assert!(
        HostBrokerService
            .grant_role(
                &mut state,
                first_task,
                claude_session,
                AgentRole::Controller,
                vec!["delegate".to_owned()],
                30,
            )
            .is_err()
    );
    let (claude_worker, _) = HostBrokerService
        .grant_role(
            &mut state,
            first_task,
            claude_session,
            AgentRole::Implementer,
            vec!["review".to_owned()],
            30,
        )
        .expect("grant Claude target role");

    let second_task = TaskId::new_v7();
    let (claude_controller, _) = HostBrokerService
        .grant_role(
            &mut state,
            second_task,
            claude_session,
            AgentRole::Controller,
            vec!["delegate".to_owned()],
            30,
        )
        .expect("grant Claude controller role on another task");
    assert_eq!(claude_controller.role, AgentRole::Controller);

    let request = AgentInvocationRequest {
        invocation_id: "invocation:fixture".to_owned(),
        project_id: ProjectId::new_v7(),
        task_id: first_task,
        work_item_id: WorkItemId::new_v7(),
        requested_capabilities: vec!["review".to_owned()],
        role_lease_id: claude_worker.role_lease_id.clone(),
        role_lease_epoch: claude_worker.epoch,
        operation_generation: claude_worker.generation,
        runtime_contract_sha256: Some("a".repeat(64)),
        work_lease_id: None,
        packet_refs: vec!["packet:fixture".to_owned()],
        expected_result_kind: "agent_result_envelope".to_owned(),
        verifier_ref: "cargo:test".to_owned(),
        idempotency_key: "idempotency:fixture".to_owned(),
    };
    let runtime_profile = profile(AgentHostId::Claude, HostProfileStatus::Current);
    let job = HostBrokerService
        .enqueue(&mut state, &request, &runtime_profile, true)
        .expect("enqueue operation");
    let replay = HostBrokerService
        .enqueue(&mut state, &request, &runtime_profile, true)
        .expect("idempotent replay");
    assert_eq!(job.job_id, replay.job_id);
    HostBrokerService
        .transition(
            &mut state.operation_jobs[0],
            OperationJobState::Running,
            Some("host-session:fixture".to_owned()),
        )
        .expect("start operation");
    assert_eq!(state.operation_jobs[0].attempt, 1);

    let mut result = AgentResultEnvelope {
        result_id: "result:fixture".to_owned(),
        invocation_id: request.invocation_id,
        host_id: AgentHostId::Claude,
        host_session_id: Some("host-session:fixture".to_owned()),
        status: AgentResultStatus::Succeeded,
        role_lease_epoch: claude_worker.epoch,
        operation_generation: claude_worker.generation,
        summary: "bounded candidate".to_owned(),
        artifact_refs: Vec::new(),
        evidence_refs: vec!["evidence:fixture".to_owned()],
        verifier_refs: vec!["cargo:test".to_owned()],
        candidate_only: true,
        exit_status: Some(0),
        token_or_cost_telemetry: None,
        unknown_outcome_evidence_refs: Vec::new(),
        supersedes_result_id: None,
        provider_output_hash: None,
        canonical_receipt: None,
    };
    let mut stale_result = result.clone();
    stale_result.result_id = "result:old-epoch".to_owned();
    let next_epoch = claude_worker.epoch.saturating_add(1);
    let next_generation = claude_worker.generation.saturating_add(1);
    let current_lease = state
        .task_role_leases
        .iter_mut()
        .find(|lease| lease.role_lease_id == claude_worker.role_lease_id)
        .expect("current worker lease");
    current_lease.epoch = next_epoch;
    current_lease.generation = next_generation;
    state
        .agent_host_sessions
        .iter_mut()
        .find(|session| session.agent_session_id == claude_session)
        .expect("current worker session")
        .generation = next_generation;
    state.agent_invocations[0].role_lease_epoch = next_epoch;
    state.agent_invocations[0].operation_generation = next_generation;
    state.operation_jobs[0].role_lease_epoch = Some(next_epoch);
    state.operation_jobs[0].generation = next_generation;
    let stale_admission = HostBrokerService
        .record_result(&mut state, stale_result)
        .expect("preserve stale generation result as evidence");
    assert!(matches!(
        stale_admission,
        eliot_engine::AgentResultAdmission::StaleEvidencePreserved(_)
    ));
    assert_eq!(state.operation_jobs[0].state, OperationJobState::Running);
    assert!(state.operation_jobs[0].result_ref.is_none());
    result.role_lease_epoch = next_epoch;
    result.operation_generation = next_generation;
    let recorded = HostBrokerService
        .record_result(&mut state, result.clone())
        .expect("record candidate result");
    let replay = HostBrokerService
        .record_result(&mut state, result)
        .expect("replay identical result");
    assert_eq!(recorded, replay);
    assert!(matches!(
        recorded,
        eliot_engine::AgentResultAdmission::Accepted(_)
    ));
    assert_eq!(state.agent_results.len(), 2);
    assert_eq!(state.operation_jobs[0].state, OperationJobState::Completed);
    let disposition = HostBrokerService
        .disposition_result(
            &mut state,
            open_session,
            "result:fixture",
            AgentResultDispositionKind::Accepted,
            "exact verifier evidence is attached".to_owned(),
            vec!["evidence:fixture".to_owned()],
            "disposition-idempotency:fixture".to_owned(),
        )
        .expect("controller dispositions candidate result");
    assert_eq!(disposition.controller_session_id, open_session);
    assert_eq!(state.agent_result_dispositions.len(), 1);
    let operator_session = AgentSessionId::new_v7();
    assert!(
        HostBrokerService
            .disposition_result_as_human_operator(
                &mut state,
                operator_session,
                "result:fixture",
                AgentResultDispositionKind::Accepted,
                "operator cannot accept".to_owned(),
                Vec::new(),
                "operator-accept-denied".to_owned(),
            )
            .is_err()
    );
    let operator_rejection = HostBrokerService
        .disposition_result_as_human_operator(
            &mut state,
            operator_session,
            "result:fixture",
            AgentResultDispositionKind::Rejected,
            "operator rejected the candidate".to_owned(),
            vec!["evidence:operator-review".to_owned()],
            "operator-reject-result".to_owned(),
        )
        .expect("HumanOperator can reject a candidate without gaining completion authority");
    assert_eq!(operator_rejection.controller_session_id, operator_session);
    assert_eq!(
        operator_rejection.kind,
        AgentResultDispositionKind::Rejected
    );
    assert_eq!(state.agent_result_dispositions.len(), 2);
}
