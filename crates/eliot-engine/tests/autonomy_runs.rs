use eliot_engine::EngineError;
use eliot_engine::control_plane::{
    AutonomyLeaseBinding, AutonomyRecoveryAction, AutonomyRunService, AutonomyStepIntent,
    AutonomyTransitionRequest, AutonomyTripwireKind, AutonomyTripwirePolicy, AutonomyWorkItem,
    BoundedAutonomyRuntime, CanonicalR3ApprovalAuthorization,
};
use eliot_types::{
    AgentId, AuthorityProfile, AutonomyRunContract, AutonomyRunState, CompletionAcceptanceItem,
    CompletionProof, ContourPreferredRoute, ProjectId, ReceiptId, RiskTier, SessionId, TaskId,
    WorkItemId, WorkItemStatus, WorkScope, WriteId, WriteReceiptRef,
};
use time::{Duration, OffsetDateTime};

fn route(host: &str) -> ContourPreferredRoute {
    ContourPreferredRoute {
        host_id: host.to_owned(),
        model_route_optional: None,
        requested_role: "worker".to_owned(),
        capability_requirements: vec!["rust".to_owned()],
    }
}

fn contract(project_id: ProjectId, task_id: TaskId) -> AutonomyRunContract {
    AutonomyRunContract {
        autonomy_run_id: "l12-test-run".to_owned(),
        project_id,
        root_task_id: task_id,
        user_goal: "bounded autonomy closure".to_owned(),
        acceptance_items: vec!["focused tests pass".to_owned()],
        contour_route_policy_ref: "route-policy:l12".to_owned(),
        allowed_projects: vec![project_id],
        max_work_items: 2,
        max_active_agents: 2,
        max_model_invocations: 4,
        max_tool_calls: 4,
        max_wall_time_seconds: 900,
        cost_or_token_budget: Some("10000 tokens".to_owned()),
        allowed_paths: vec!["crates/eliot-engine".to_owned()],
        forbidden_paths: vec![".git".to_owned(), "crates/eliot-engine/secret".to_owned()],
        forbidden_effects: vec!["service_install".to_owned(), "network_write".to_owned()],
        allowed_risk_tiers: vec![
            "R0".to_owned(),
            "R1".to_owned(),
            "R2".to_owned(),
            "R3".to_owned(),
        ],
        required_verifiers: vec!["cargo test".to_owned()],
        approval_boundaries: vec!["R3".to_owned()],
        pause_conditions: vec!["tripwire".to_owned()],
        stop_conditions: vec!["acceptance verified".to_owned()],
        fallback_routes: vec![route("codex")],
        recovery_policy_ref: "recovery-policy:l12".to_owned(),
        policy_snapshot_id: "policy-snapshot:l12".to_owned(),
        created_by: "operator".to_owned(),
        state: AutonomyRunState::Draft,
        state_revision: 0,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn request(
    target: AutonomyRunState,
    risk_tier: &str,
    approval: Option<CanonicalR3ApprovalAuthorization>,
) -> AutonomyTransitionRequest {
    AutonomyTransitionRequest {
        target,
        reason: format!("advance to {target:?}"),
        risk_tier: risk_tier.to_owned(),
        approval,
        verifier_refs: Vec::new(),
    }
}

fn approval(
    exact_action_hash: &str,
    expires_at: OffsetDateTime,
) -> CanonicalR3ApprovalAuthorization {
    CanonicalR3ApprovalAuthorization {
        approval_id: format!("autonomy-approval:{}", WriteId::new_v7()),
        exact_action_hash: exact_action_hash.to_owned(),
        decision_receipt: WriteReceiptRef {
            receipt_id: ReceiptId::new_v7(),
            write_id: WriteId::new_v7(),
        },
        approved_by: SessionId::new_v7(),
        expires_at,
    }
}

fn running_runtime(
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<BoundedAutonomyRuntime, EngineError> {
    let mut runtime = BoundedAutonomyRuntime::new(
        contract(project_id, task_id),
        AutonomyTripwirePolicy::default(),
    )?;
    runtime.transition(&request(AutonomyRunState::Ready, "R1", None))?;
    runtime.transition(&request(AutonomyRunState::Running, "R1", None))?;
    Ok(runtime)
}

fn work_item(project_id: ProjectId, dependencies: Vec<WorkItemId>) -> AutonomyWorkItem {
    AutonomyWorkItem {
        work_item_id: WorkItemId::new_v7(),
        project_id,
        dependencies,
        status: WorkItemStatus::Open,
        required: true,
        required_verifiers: vec!["cargo test".to_owned()],
        verifier_refs: Vec::new(),
        assigned_agent: None,
        lease: None,
    }
}

fn scope(path: &str) -> WorkScope {
    WorkScope {
        repo_root: ".".to_owned(),
        read_set: vec![path.to_owned()],
        write_set: vec![path.to_owned()],
        verifier_set: vec!["cargo test".to_owned()],
        authority: AuthorityProfile::bounded_write(),
        risk_tier: RiskTier::Low,
        max_files: 2,
        requires_active_work_lease: true,
    }
}

fn lease(project_id: ProjectId, holder: AgentId, path: &str) -> AutonomyLeaseBinding {
    AutonomyLeaseBinding {
        lease_ref: format!("work-lease:{holder}"),
        holder,
        project_id,
        scope: scope(path),
        expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
    }
}

fn step(project_id: ProjectId, failure_signature: Option<&str>) -> AutonomyStepIntent {
    AutonomyStepIntent {
        project_id,
        paths: vec!["crates/eliot-engine/src/control_plane.rs".to_owned()],
        effect: Some("source_edit".to_owned()),
        model_invocations: 1,
        tool_calls: 1,
        wall_time_seconds: 10,
        cost_or_token_units: 100,
        work_items_started: 0,
        active_agents: 1,
        novelty_observed: false,
        failure_signature: failure_signature.map(str::to_owned),
    }
}

#[test]
fn contract_and_budget_gate_forbidden_effects_and_tripwires() -> Result<(), EngineError> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut bad = contract(project_id, task_id);
    bad.max_tool_calls = 0;
    assert!(AutonomyRunService::validate_contract(&bad).is_err());

    let mut bounded = contract(project_id, task_id);
    bounded.max_tool_calls = 2;
    let mut runtime = BoundedAutonomyRuntime::new(
        bounded,
        AutonomyTripwirePolicy {
            repeated_failure_threshold: 2,
            no_novelty_tool_call_threshold: 2,
        },
    )?;
    runtime.transition(&request(AutonomyRunState::Ready, "R1", None))?;
    runtime.transition(&request(AutonomyRunState::Running, "R1", None))?;

    let mut forbidden = step(project_id, None);
    forbidden.effect = Some("service_install".to_owned());
    let denied = runtime.record_step(&forbidden)?;
    assert!(!denied.accepted);
    assert_eq!(runtime.ledger.tool_calls, 0);
    assert_eq!(
        denied.tripwires[0].kind,
        AutonomyTripwireKind::PolicyViolation
    );

    assert!(
        runtime
            .record_step(&step(project_id, Some("same-failure")))?
            .accepted
    );
    let threshold = runtime.record_step(&step(project_id, Some("same-failure")))?;
    assert!(threshold.accepted);
    assert!(
        threshold
            .tripwires
            .iter()
            .any(|tripwire| tripwire.kind == AutonomyTripwireKind::NoNovelty)
    );
    assert!(
        threshold
            .tripwires
            .iter()
            .any(|tripwire| tripwire.kind == AutonomyTripwireKind::RepeatedFailedAction)
    );

    let exhausted = runtime.record_step(&step(project_id, None))?;
    assert!(!exhausted.accepted);
    assert_eq!(runtime.ledger.tool_calls, 2);
    assert!(
        exhausted
            .tripwires
            .iter()
            .any(|tripwire| tripwire.kind == AutonomyTripwireKind::BudgetExhaustion)
    );
    Ok(())
}

#[test]
fn dependency_progression_and_reassignment_never_widen_lease() -> Result<(), EngineError> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut runtime = running_runtime(project_id, task_id)?;
    let first = work_item(project_id, Vec::new());
    let first_id = first.work_item_id;
    runtime.register_work_item(first)?;
    let second = work_item(project_id, vec![first_id]);
    let second_id = second.work_item_id;
    runtime.register_work_item(second)?;

    let now = OffsetDateTime::now_utc();
    assert!(
        runtime
            .activate_work_item(
                second_id,
                lease(project_id, AgentId::new_v7(), "crates/eliot-engine"),
                now,
            )
            .is_err()
    );
    runtime.activate_work_item(
        first_id,
        lease(project_id, AgentId::new_v7(), "crates/eliot-engine"),
        now,
    )?;
    runtime.complete_work_item(
        first_id,
        &["cargo test".to_owned()],
        vec!["verifier:first".to_owned()],
        now,
    )?;
    assert_eq!(runtime.ready_work_items(), vec![second_id]);

    runtime.activate_work_item(
        second_id,
        lease(project_id, AgentId::new_v7(), "crates/eliot-engine"),
        now,
    )?;
    let narrowed = lease(
        project_id,
        AgentId::new_v7(),
        "crates/eliot-engine/src/control_plane.rs",
    );
    let receipt = runtime.reassign_work_item(second_id, narrowed, "fallback route", now)?;
    assert_eq!(receipt.action, AutonomyRecoveryAction::Reassign);
    assert!(receipt.previous_agent.is_some());
    assert!(receipt.next_agent.is_some());

    let widened = lease(project_id, AgentId::new_v7(), "crates/eliot-engine");
    assert!(
        runtime
            .reassign_work_item(second_id, widened, "must not widen", now)
            .is_err()
    );
    Ok(())
}

#[test]
fn r3_transition_requires_unexpired_canonical_authorization() -> Result<(), EngineError> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut missing_boundary = contract(project_id, task_id);
    missing_boundary.approval_boundaries.clear();
    assert!(AutonomyRunService::validate_contract(&missing_boundary).is_err());
    let mut runtime = BoundedAutonomyRuntime::new(
        contract(project_id, task_id),
        AutonomyTripwirePolicy::default(),
    )?;
    runtime.transition(&request(AutonomyRunState::Ready, "R1", None))?;
    assert!(
        runtime
            .transition(&request(AutonomyRunState::Running, "R3", None,))
            .is_err()
    );
    assert!(
        runtime
            .transition(&request(
                AutonomyRunState::Running,
                "R3",
                Some(approval(
                    "exact-action",
                    OffsetDateTime::now_utc() - Duration::seconds(1)
                )),
            ))
            .is_err()
    );
    runtime.transition(&request(
        AutonomyRunState::Running,
        "R3",
        Some(approval(
            "exact-action",
            OffsetDateTime::now_utc() + Duration::hours(1),
        )),
    ))?;
    assert_eq!(runtime.contract.state, AutonomyRunState::Running);
    Ok(())
}

#[test]
fn done_requires_completion_proof_required_work_and_verifier_refs() -> Result<(), EngineError> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut runtime = running_runtime(project_id, task_id)?;
    let now = OffsetDateTime::now_utc();
    let first = work_item(project_id, Vec::new());
    let first_id = first.work_item_id;
    runtime.register_work_item(first)?;
    runtime.activate_work_item(
        first_id,
        lease(project_id, AgentId::new_v7(), "crates/eliot-engine"),
        now,
    )?;
    runtime.complete_work_item(
        first_id,
        &["cargo test".to_owned()],
        vec!["verifier:first".to_owned()],
        now,
    )?;
    let second = work_item(project_id, vec![first_id]);
    let second_id = second.work_item_id;
    runtime.register_work_item(second)?;
    runtime.activate_work_item(
        second_id,
        lease(project_id, AgentId::new_v7(), "crates/eliot-engine"),
        now,
    )?;
    runtime.complete_work_item(
        second_id,
        &["cargo test".to_owned()],
        vec!["verifier:second".to_owned()],
        now,
    )?;
    runtime.transition(&request(AutonomyRunState::Verifying, "R1", None))?;

    let mut done = request(AutonomyRunState::DoneVerified, "R1", None);
    done.verifier_refs = vec!["verification:canonical".to_owned()];
    assert!(runtime.transition(&done).is_err());

    let mut proof = completion_proof(project_id, task_id);
    proof.acceptance_items.clear();
    assert!(runtime.complete_verified(&done, &proof).is_err());

    let proof = completion_proof(project_id, task_id);
    runtime.complete_verified(&done, &proof)?;
    assert_eq!(runtime.contract.state, AutonomyRunState::DoneVerified);
    Ok(())
}

#[test]
fn serialized_pause_and_recovery_resume_without_restarting_completed_work()
-> Result<(), EngineError> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut runtime = running_runtime(project_id, task_id)?;
    let item = work_item(project_id, Vec::new());
    let item_id = item.work_item_id;
    runtime.register_work_item(item)?;
    runtime.activate_work_item(
        item_id,
        lease(project_id, AgentId::new_v7(), "crates/eliot-engine"),
        OffsetDateTime::now_utc(),
    )?;
    runtime.record_step(&step(project_id, None))?;
    let tripwire = runtime.record_external_tripwire(
        AutonomyTripwireKind::ProviderRuntimeFailure,
        Some("provider-timeout".to_owned()),
        "provider became unavailable",
    );
    runtime.pause_for_recovery(item_id, tripwire.tripwire_id, "preserve branch state")?;
    let revision_before = runtime.runtime_revision;
    let mut cyclic = runtime.clone();
    cyclic.work_items[0].dependencies.push(item_id);
    assert!(BoundedAutonomyRuntime::from_json(&cyclic.to_json()?).is_err());
    let restored = BoundedAutonomyRuntime::from_json(&runtime.to_json()?)?;
    assert_eq!(restored.contract.state, AutonomyRunState::PausedByOperator);
    assert_eq!(restored.ledger.tool_calls, 1);
    assert_eq!(restored.work_items[0].status, WorkItemStatus::Active);
    assert_eq!(restored.runtime_revision, revision_before);

    let mut resumed = restored;
    resumed.resume_after_recovery(item_id, "fallback route is healthy")?;
    assert_eq!(resumed.contract.state, AutonomyRunState::Running);
    assert_eq!(resumed.work_items[0].status, WorkItemStatus::Active);
    assert!(resumed.runtime_revision > revision_before);
    Ok(())
}

fn completion_proof(project_id: ProjectId, task_id: TaskId) -> CompletionProof {
    CompletionProof {
        task_id: task_id.to_string(),
        project_id,
        goal: "bounded autonomy closure".to_owned(),
        changed_files: vec!["crates/eliot-engine/src/control_plane.rs".to_owned()],
        memory_refs_used: Vec::new(),
        checks_run: vec!["cargo test".to_owned()],
        checks_not_run: Vec::new(),
        acceptance_items: vec![CompletionAcceptanceItem {
            item: "focused tests pass".to_owned(),
            status: "verified".to_owned(),
            evidence: "autonomy_runs".to_owned(),
            verifier: "cargo test".to_owned(),
            residual_uncertainty: String::new(),
        }],
        evidence: vec!["verification:canonical".to_owned()],
        skill_refs: Vec::new(),
        skill_execution_proof_refs: Vec::new(),
        residual_uncertainty: String::new(),
        known_risks: Vec::new(),
    }
}
