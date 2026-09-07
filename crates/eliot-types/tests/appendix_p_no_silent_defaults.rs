#![allow(clippy::expect_used)]

use eliot_types::{
    AntigravityRun, AntigravitySafetyReceipt, AutonomyRunContract, CognitiveFieldProviderCallPlan,
    CognitiveFieldProviderEvidenceReceipt, CognitiveFieldProviderPlan,
    CognitiveFieldProviderProjection, ForgettingPolicy, MemoryStateTransition, ProviderCallLedger,
    WorkLease,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn without(mut value: Value, field: &str) -> Value {
    value
        .as_object_mut()
        .expect("fixture must be an object")
        .remove(field);
    value
}

fn rejects_missing<T: DeserializeOwned + std::fmt::Debug>(value: Value, field: &str) {
    assert!(
        serde_json::from_value::<T>(without(value, field)).is_err(),
        "missing {field} must be rejected"
    );
}

fn work_lease_wire() -> Value {
    json!({
        "work_lease_id": "00000000-0000-7000-8000-000000000001",
        "work_item_id": "00000000-0000-7000-8000-000000000002",
        "agent_session_id": "00000000-0000-7000-8000-000000000003",
        "agent_id": "00000000-0000-7000-8000-000000000004",
        "project_id": "00000000-0000-7000-8000-000000000005",
        "task_id": "00000000-0000-7000-8000-000000000006",
        "role": "implementer",
        "state": "granted",
        "epoch": 0,
        "scope": {
            "repo_root": "C:/repo",
            "read_set": [],
            "write_set": ["crates/eliot-types/src/memory.rs"],
            "verifier_set": ["cargo test"],
            "authority": {"permissions": ["read", "write"]},
            "risk_tier": "low",
            "max_files": 1,
            "requires_active_work_lease": true
        },
        "decision": {
            "kind": "granted",
            "reason": "no_conflict",
            "message": "accepted",
            "work_lease_id": null,
            "conflicting_lease_ids": [],
            "expires_at": null
        },
        "conflict_refs": [],
        "granted_at": "2026-09-07T12:00:00Z",
        "expires_at": "2026-09-07T13:00:00Z",
        "renewed_at": null,
        "released_at": null,
        "revoked_at": null,
        "write_receipt": null
    })
}

#[test]
fn work_lease_requires_explicit_epoch_but_accepts_zero() {
    let wire = work_lease_wire();
    let lease: WorkLease = serde_json::from_value(wire.clone()).expect("complete lease wire");
    assert_eq!(lease.epoch, 0);
    rejects_missing::<WorkLease>(wire, "epoch");
}

#[test]
fn provider_call_ledger_requires_explicit_containers() {
    let wire = json!({
        "budgets": [],
        "reservations": []
    });
    rejects_missing::<ProviderCallLedger>(wire.clone(), "budgets");
    rejects_missing::<ProviderCallLedger>(wire.clone(), "reservations");
    let ledger: ProviderCallLedger =
        serde_json::from_value(wire).expect("explicit empty ledger is valid");
    assert!(ledger.budgets.is_empty());
    assert!(ledger.reservations.is_empty());
}

fn provider_call_plan_wire() -> Value {
    json!({
        "call_number": 1,
        "call_id": "call-1",
        "role": "codex_worker",
        "host": "codex",
        "requested_model": "gpt-test",
        "expected_provider_executable_sha256": "exec-sha",
        "prompt_ref": "prompt-1",
        "prompt_sha256": "prompt-sha",
        "canonical_schema_sha256": "schema-sha",
        "provider_schema_sha256": "provider-schema-sha",
        "provider_smoke": true,
        "counts_against_cap": true,
        "executions": [],
        "runtime_contract_ref": "runtime-contract-1",
        "runtime_contract_sha256": "runtime-sha",
        "adapter_id": "adapter-1",
        "adapter_version": "1",
        "execution_request_ref": "request-1",
        "execution_request_sha256": "request-sha"
    })
}

#[test]
fn cognitive_provider_call_requires_execution_binding_fields() {
    let wire = provider_call_plan_wire();
    let _: CognitiveFieldProviderCallPlan =
        serde_json::from_value(wire.clone()).expect("complete provider call plan");
    for field in [
        "runtime_contract_ref",
        "runtime_contract_sha256",
        "adapter_id",
        "adapter_version",
        "execution_request_ref",
        "execution_request_sha256",
    ] {
        rejects_missing::<CognitiveFieldProviderCallPlan>(wire.clone(), field);
    }

    let evidence = json!({
        "schema_version": "cognitive-provider-evidence-v1",
        "run_id": "run-1",
        "contract_hash": "contract-sha",
        "provider_plan_hash": "plan-sha",
        "source_commit": "commit-sha",
        "call_id": "call-1",
        "role": "codex_worker",
        "host": "codex",
        "requested_model": "gpt-test",
        "resolved_model": "gpt-test",
        "provider_session_id": "session-1",
        "provider_receipt_ref": "receipt-1",
        "provider_executable": "provider.exe",
        "provider_executable_sha256": "exec-sha",
        "prompt_path": "prompt.txt",
        "prompt_sha256": "prompt-sha",
        "raw_stdout_path": "stdout.txt",
        "raw_stdout_sha256": "stdout-sha",
        "raw_stderr_path": "stderr.txt",
        "raw_stderr_sha256": "stderr-sha",
        "outputs": [],
        "provider_calls": 1,
        "exit_code": 0,
        "elapsed_ms": 1,
        "timed_out": false,
        "unknown_outcome": false,
        "controller_substitution": false,
        "oracle_exposed": false,
        "worker_transcript_exposed": false,
        "read_only": true,
        "runtime_contract_sha256": "runtime-sha",
        "observed_mcp_server_names": [],
        "observed_mcp_tool_names": []
    });
    let _: CognitiveFieldProviderEvidenceReceipt =
        serde_json::from_value(evidence.clone()).expect("complete provider evidence");
    for field in [
        "runtime_contract_sha256",
        "observed_mcp_server_names",
        "observed_mcp_tool_names",
    ] {
        rejects_missing::<CognitiveFieldProviderEvidenceReceipt>(evidence.clone(), field);
    }

    let projection = json!({
        "schema_version": "cognitive-provider-projection-v1",
        "run_id": "run-1",
        "contract_hash": "contract-sha",
        "provider_plan_hash": "plan-sha",
        "source_commit": "commit-sha",
        "call_id": "call-1",
        "role": "codex_worker",
        "host": "codex",
        "requested_model": "gpt-test",
        "resolved_model": "gpt-test",
        "provider_session_id": "session-1",
        "provider_receipt_ref": "receipt-1",
        "provider_executable_sha256": "exec-sha",
        "prompt_sha256": "prompt-sha",
        "raw_stdout_sha256": "stdout-sha",
        "raw_stderr_sha256": "stderr-sha",
        "outputs": [],
        "provider_smoke": true,
        "counts_against_cap": true,
        "elapsed_ms": 1,
        "runtime_contract_sha256": "runtime-sha",
        "recorded_at": "2026-09-07T12:00:00Z"
    });
    let _: CognitiveFieldProviderProjection =
        serde_json::from_value(projection.clone()).expect("complete provider projection");
    rejects_missing::<CognitiveFieldProviderProjection>(projection, "runtime_contract_sha256");
}

#[test]
fn cognitive_provider_plan_requires_explicit_reuse_and_seal_generation() {
    let wire = json!({
        "schema_version": "cognitive-provider-plan-v1",
        "run_id": "run-1",
        "contract_hash": "contract-sha",
        "calls": [provider_call_plan_wire()],
        "planned_provider_calls": 1,
        "planned_smoke_calls": 1,
        "planned_reused_roles": 0,
        "role_evidence_plan_hash": null,
        "seal_attempt_id": null,
        "seal_generation": 0,
        "authority_activation_ref": null,
        "runtime_manifest_sha256": null,
        "artifact_manifest_sha256": null,
        "plan_hash": "plan-sha",
        "sealed_at": "2026-09-07T12:00:00Z"
    });
    let _: CognitiveFieldProviderPlan =
        serde_json::from_value(wire.clone()).expect("complete plan");
    for field in ["planned_reused_roles", "seal_generation"] {
        rejects_missing::<CognitiveFieldProviderPlan>(wire.clone(), field);
    }
}

fn safety_receipt_wire() -> Value {
    json!({
        "typed_argv": ["agy", "--json"],
        "prompt_hash_blake3": "prompt-sha",
        "shell_false": true,
        "stdin_devnull": true,
        "process_group_kill_on_timeout": true,
        "timeout_ms": 1000,
        "max_output_bytes": 1024,
        "effective_cwd": "C:/repo",
        "env_fixed_vars": [],
        "env_dropped_names": [],
        "model_observation": null
    })
}

#[test]
fn antigravity_safety_and_response_receipts_cannot_be_silently_fabricated() {
    let safety = safety_receipt_wire();
    let _: AntigravitySafetyReceipt =
        serde_json::from_value(safety.clone()).expect("complete safety receipt");
    rejects_missing::<AntigravitySafetyReceipt>(safety, "prompt_hash_blake3");

    let run = json!({
        "run_id": "run-1",
        "request_id": "request-1",
        "state": "succeeded",
        "provider_state": "ready_enabled",
        "dry_run": false,
        "fixture_runner": false,
        "binary_path": null,
        "effective_cwd": "C:/repo",
        "stdout_blob_ref": null,
        "stderr_blob_ref": null,
        "log_blob_ref": null,
        "stdout_excerpt": "",
        "stderr_excerpt": "",
        "safety_receipt": safety_receipt_wire(),
        "redaction_receipt": {
            "redacted": false,
            "redacted_markers": [],
            "original_bytes": 0,
            "retained_bytes": 0
        },
        "response_protocol_receipt": {
            "structured_single_turn": true,
            "expected_smoke_marker_seen": true,
            "mcp_call_marker_seen": true,
            "candidate_final_line_exact": true
        },
        "normalized_result": null,
        "message": "ok",
        "created_at": "2026-09-07T12:00:00Z",
        "completed_at": "2026-09-07T12:00:01Z"
    });
    let _: AntigravityRun = serde_json::from_value(run.clone()).expect("complete antigravity run");
    rejects_missing::<AntigravityRun>(run, "response_protocol_receipt");
}

#[test]
#[allow(clippy::too_many_lines)]
fn autonomy_and_lifecycle_contracts_require_explicit_policy_fields() {
    let wire = json!({
        "autonomy_run_id": "run-1",
        "project_id": "00000000-0000-7000-8000-000000000001",
        "root_task_id": "00000000-0000-7000-8000-000000000002",
        "user_goal": "goal",
        "acceptance_items": [],
        "contour_route_policy_ref": "route-policy",
        "allowed_projects": [],
        "max_work_items": 1,
        "max_active_agents": 1,
        "max_model_invocations": 1,
        "max_tool_calls": 1,
        "max_wall_time_seconds": 60,
        "cost_or_token_budget": null,
        "allowed_paths": [],
        "forbidden_paths": [],
        "forbidden_effects": [],
        "allowed_risk_tiers": ["low"],
        "required_verifiers": [],
        "approval_boundaries": [],
        "pause_conditions": [],
        "stop_conditions": [],
        "fallback_routes": [],
        "recovery_policy_ref": "recovery-policy",
        "policy_snapshot_id": "policy-1",
        "created_by": "principal-1",
        "state": "DRAFT",
        "state_revision": 0,
        "created_at": "2026-09-07T12:00:00Z"
    });
    let _: AutonomyRunContract =
        serde_json::from_value(wire.clone()).expect("complete autonomy contract");
    for field in [
        "allowed_projects",
        "forbidden_effects",
        "max_tool_calls",
        "recovery_policy_ref",
    ] {
        rejects_missing::<AutonomyRunContract>(wire.clone(), field);
    }

    let forgetting_policy = json!({
        "policy_id": "policy-1",
        "project_id": "00000000-0000-7000-8000-000000000001",
        "target_ref": "memory-1",
        "reason": "stale",
        "operator": "suppress",
        "evidence_refs": ["evidence-1"],
        "rollback_or_tombstone_ref": null,
        "reactivation_condition": null,
        "expected_current_state": "active",
        "observed_epistemic_status": "observed",
        "scope": [],
        "precondition_refs": [],
        "effective_at": null,
        "expires_at": null,
        "expected_admission_effect": "KEEP_HOT",
        "reversible": true,
        "requires_admin_approval": false,
        "approval_ref": null,
        "created_at": "2026-09-07T12:00:00Z"
    });
    let _: ForgettingPolicy =
        serde_json::from_value(forgetting_policy.clone()).expect("complete forgetting policy");
    for field in [
        "expected_current_state",
        "observed_epistemic_status",
        "scope",
        "precondition_refs",
        "expected_admission_effect",
        "reversible",
        "requires_admin_approval",
    ] {
        rejects_missing::<ForgettingPolicy>(forgetting_policy.clone(), field);
    }

    let transition = json!({
        "transition_id": "transition-1",
        "project_id": "00000000-0000-7000-8000-000000000001",
        "target_ref": "memory-1",
        "from_state": "active",
        "to_state": "suppressed",
        "operator": "suppress",
        "reason": "stale",
        "policy_ref": "policy-1",
        "evidence_refs": ["evidence-1"],
        "precondition_refs": [],
        "expected_admission_effect": "SUPPRESS",
        "reactivation_condition": null,
        "reversible": true,
        "approval_ref": null,
        "performed_by": "principal-1",
        "created_at": "2026-09-07T12:00:00Z",
        "write_receipt": null
    });
    let _: MemoryStateTransition =
        serde_json::from_value(transition.clone()).expect("complete lifecycle transition");
    for field in [
        "precondition_refs",
        "expected_admission_effect",
        "reversible",
    ] {
        rejects_missing::<MemoryStateTransition>(transition.clone(), field);
    }
}
