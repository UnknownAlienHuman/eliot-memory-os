use eliot_engine::{WriteAdmissionService, WriterActor, WriterConfig};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    AgentHostId, AgentId, AgentInvocationRequest, AgentResultEnvelope, AgentResultStatus,
    AgentRole, AgentSession, AgentSessionId, AgentSessionStatus, AgentTransport, CommandContext,
    ControlWalConfig, LifecycleStatus, OperationJob, OperationJobState, OperatorControlRequest,
    ProjectId, SemanticCommand, SessionId, TaintClass, TaskId, ToolObservationRecordCommand,
    Visibility, WorkItemId, WorkLeaseId, WriteId, WriteReceiptRef,
};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Barrier};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn host_role_grant_uses_the_live_daemon_writer() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let mut daemon_owner = McpClient::start()?;
    let _created = create_m3_task_fixture(&mut daemon_owner, &project_id, &task_id)?;
    let session_id = daemon_owner.agent_session_id.clone();

    let role_lease_id = m3_grant_task_role(
        "codex",
        &session_id,
        &task_id,
        "controller",
        "delegate,review,verify",
    )?;
    assert!(!role_lease_id.is_empty());

    let broker = run_json(&["host", "broker-status"])?;
    assert!(broker["task_role_leases"].as_array().is_some_and(|leases| {
        leases
            .iter()
            .any(|lease| lease["role_lease_id"] == role_lease_id && lease["task_id"] == task_id)
    }));

    let mut scoped = McpClient::connect_scoped_controller(
        &daemon_owner.workspace,
        &session_id,
        &role_lease_id,
        &task_id,
    )?;
    let status = scoped.tool_call(40, "eliot_host_session_status", &json!({}))?;
    assert_eq!(status["scope_status"], "governor_bound_scope_active");
    assert_eq!(status["bound_project_id"], project_id);
    assert_eq!(status["bound_task_id"], task_id);

    let identity = scoped.tool_call(41, "eliot_project_identity", &json!({}))?;
    assert_eq!(identity["project_id"], project_id);
    assert_eq!(identity["bound_task_id"], task_id);
    assert_eq!(identity["scope_authority"], "canonical_host_binding");

    let task = scoped.tool_call(42, "eliot_task_state", &json!({}))?;
    assert_eq!(task["task_contract"]["project_id"], project_id);
    assert_eq!(task["task_contract"]["task_id"], task_id);
    let skills = scoped.tool_call(43, "eliot_skill_list", &json!({}))?;
    assert_eq!(skills["component"], "skill_list");

    assert!(
        scoped
            .tool_call(
                44,
                "eliot_task_state",
                &json!({"project_id": uuid::Uuid::new_v4().to_string()}),
            )
            .is_err()
    );
    assert!(
        scoped
            .tool_call(
                45,
                "eliot_task_state",
                &json!({"task_id": uuid::Uuid::new_v4().to_string()}),
            )
            .is_err()
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn concurrent_host_role_grants_preserve_both_broker_mutations() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let mut daemon_owner = McpClient::start()?;
    let _created = create_m3_task_fixture(&mut daemon_owner, &project_id, &task_id)?;
    let first_session = uuid::Uuid::new_v4().to_string();
    let second_session = uuid::Uuid::new_v4().to_string();
    for (host, session) in [
        ("opencode", first_session.as_str()),
        ("antigravity", second_session.as_str()),
    ] {
        let registered = run_json(&[
            "host",
            "session-register",
            "--host",
            host,
            "--session",
            session,
            "--client-instance",
            session,
        ])?;
        assert_eq!(registered["binding"]["agent_session_id"], session);
    }

    let barrier = Arc::new(Barrier::new(2));
    let mut grants = Vec::new();
    for session in [first_session.clone(), second_session.clone()] {
        let barrier = Arc::clone(&barrier);
        let task_id = task_id.clone();
        grants.push(thread::spawn(move || -> TestResult<Value> {
            barrier.wait();
            let output = Command::new(binary())
                .args([
                    "host",
                    "role-grant",
                    "--task",
                    &task_id,
                    "--session",
                    &session,
                    "--role",
                    "implementer",
                    "--capability",
                    "run_json",
                    "--ttl-minutes",
                    "60",
                ])
                .output()?;
            if !output.status.success() {
                return Err(std::io::Error::other(format!(
                    "concurrent role grant failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))
                .into());
            }
            Ok(serde_json::from_slice(&output.stdout)?)
        }));
    }
    let granted = grants
        .into_iter()
        .map(|grant| {
            grant
                .join()
                .map_err(|_| std::io::Error::other("grant panicked"))?
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert!(granted.iter().all(|grant| {
        grant["canonical_authority_receipt"].is_object()
            && grant["canonical_host_binding_receipt"].is_object()
    }));

    let broker = run_json(&["host", "broker-status"])?;
    for session in [&first_session, &second_session] {
        assert!(
            broker["task_role_leases"]
                .as_array()
                .is_some_and(|leases| leases.iter().any(|lease| {
                    lease["agent_session_id"] == *session && lease["task_id"] == task_id
                }))
        );
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn operator_lifecycle_write_is_query_visible_idempotent_and_reconnect_safe() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = "10000000-0000-0000-0000-000000000041";
    let task_id = "20000000-0000-0000-0000-000000000041";
    let create_write_id = "30000000-0000-0000-0000-000000000041";
    let idempotency_key = "operator-response-loss-replay-41";

    let revision = {
        let mut controller = McpClient::start()?;
        let created = controller.tool_call(
            1,
            "eliot_task_contract_create",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "write_id": create_write_id,
                "title": "M4 operator lifecycle integration",
                "acceptance_items": [
                    {
                        "item_id": "observed",
                        "description": "typed operator action is persisted",
                        "required_evidence": "observation"
                    },
                    {
                        "item_id": "verified",
                        "description": "canonical query survives reconnect",
                        "required_evidence": "verification"
                    }
                ]
            }),
        )?;
        created["task_contract"]["memory_revision"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("created task has no memory revision"))?
    };

    let command = json!({
        "project_id": project_id,
        "task_id": task_id,
        "expected_revision": revision,
        "idempotency_key": idempotency_key,
        "command": {
            "command": "suppress_memory",
            "task_id": task_id,
            "memory_handle": "memory:operator-runtime-proof",
            "reason": "bounded integration proof"
        }
    });
    let first_receipt = {
        let mut operator = McpClient::start_with_profile("human_operator")?;
        let first = operator.tool_call(2, "eliot_operator_command", &command)?;
        assert_eq!(first["accepted"], true);
        let first_receipt = first["canonical_receipt"].clone();
        assert!(first_receipt.is_object());

        // This is the server-side equivalent of retry after response loss: the exact
        // client key is replayed and must resolve to the original receipt.
        let replay = operator.tool_call(3, "eliot_operator_command", &command)?;
        assert_eq!(replay["accepted"], true);
        assert_eq!(replay["canonical_receipt"], first_receipt);
        assert!(
            operator
                .tool_call(
                    4,
                    "eliot_operator_command",
                    &json!({
                        "project_id": project_id,
                        "task_id": task_id,
                        "expected_revision": revision,
                        "idempotency_key": idempotency_key,
                        "command": {
                            "command": "archive_memory",
                            "task_id": task_id,
                            "memory_handle": "memory:operator-runtime-proof",
                            "reason": "conflicting reuse must fail"
                        }
                    }),
                )
                .is_err()
        );

        assert!(
            operator
                .tool_call(
                    5,
                    "eliot_operator_command",
                    &json!({
                        "project_id": project_id,
                        "task_id": task_id,
                        "expected_revision": revision,
                        "idempotency_key": "unknown-review-41",
                        "command": {
                            "command": "review_candidate",
                            "task_id": task_id,
                            "candidate_ref": "candidate:41",
                            "disposition": "archive",
                            "evidence_refs": ["verification:41"]
                        }
                    }),
                )
                .is_err()
        );

        let page = operator.tool_call(
            6,
            "eliot_operator_query",
            &json!({
                "projection": "memory_explorer",
                "project_id": project_id,
                "task_id": task_id,
                "filter": {"record_kind": "memory_state_transition"},
                "page_size": 20
            }),
        )?;
        assert_eq!(page["total_matching"], 1);
        assert_eq!(page["records"][0]["status"], "suppressed");
        first_receipt
    };

    {
        let mut reconnected = McpClient::start_with_profile("human_operator")?;
        let page = reconnected.tool_call(
            7,
            "eliot_operator_query",
            &json!({
                "projection": "memory_explorer",
                "project_id": project_id,
                "task_id": task_id,
                "filter": {"record_kind": "memory_state_transition"},
                "page_size": 20
            }),
        )?;
        assert_eq!(page["total_matching"], 1);
        let receipt_id = first_receipt["receipt_id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("canonical receipt id missing"))?;
        assert!(
            page["records"][0]["fields"]
                .as_array()
                .is_some_and(|fields| fields.iter().any(|field| {
                    field["label"] == "receipt_id" && field["value"] == receipt_id
                }))
        );
    }

    let mut readonly = McpClient::start_with_profile("human_readonly")?;
    assert!(
        readonly
            .tool_call(8, "eliot_operator_command", &command)
            .is_err()
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn operator_revalidation_request_uses_receipted_executor() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let revision = {
        let mut controller = McpClient::start()?;
        let created = controller.tool_call(
            9,
            "eliot_task_contract_create",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "write_id": uuid::Uuid::new_v4().to_string(),
                "title": "Receipted memory revalidation request",
                "acceptance_items": [
                    {
                        "item_id": "revalidation",
                        "description": "revalidation request is persisted through the Governor",
                        "required_evidence": "verification"
                    },
                    {
                        "item_id": "replay",
                        "description": "reconnect replays the canonical receipt",
                        "required_evidence": "observation"
                    }
                ]
            }),
        )?;
        required_test_u64(&created, "/task_contract/memory_revision")?
    };
    let command = json!({
        "project_id": project_id,
        "task_id": task_id,
        "expected_revision": revision,
        "idempotency_key": "operator-revalidation-replay",
        "command": {
            "command": "request_revalidation",
            "task_id": task_id,
            "memory_handle": "memory:l10-revalidation-proof"
        }
    });

    let first = {
        let mut operator = McpClient::start_with_profile("human_operator")?;
        operator.tool_call(10, "eliot_operator_command", &command)?
    };
    assert_eq!(first["accepted"], true);
    assert_eq!(first["executed"], true);
    assert_eq!(first["outcome"], "revalidation_request_recorded");
    assert!(first["canonical_receipt"].is_object());

    let mut reconnected = McpClient::start_with_profile("human_operator")?;
    let replay = reconnected.tool_call(11, "eliot_operator_command", &command)?;
    assert_eq!(replay["accepted"], true);
    assert_eq!(replay["executed"], true);
    assert_eq!(replay["canonical_receipt"], first["canonical_receipt"]);
    let mut conflicting = command;
    conflicting["command"]["memory_handle"] = json!("memory:different-target");
    assert!(
        reconnected
            .tool_call(12, "eliot_operator_command", &conflicting)
            .is_err()
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn procedure_candidate_disposition_is_canonical_idempotent_and_never_activates() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let pattern_id = format!("experience-pattern-{}", uuid::Uuid::new_v4());
    let pattern_ref = format!("experience-pattern:{pattern_id}");
    let skill_id = uuid::Uuid::new_v4().to_string();

    let (revision, holdout) = {
        let mut controller = McpClient::start()?;
        seed_m3_verified_task(&mut controller, &project_id, &task_id)?;
        drop(controller);
        let mut readonly = McpClient::start_with_profile("human_readonly")?;
        let snapshot = readonly.tool_call(
            13,
            "eliot_operator_snapshot",
            &json!({"project_id": project_id, "task_id": task_id}),
        )?;
        let task = &snapshot["task_cognition"][0]["task_contract"];
        (
            required_test_u64(task, "/memory_revision")?,
            task["verification_scopes"][0]["artifact_refs"][0].clone(),
        )
    };

    let candidate = json!({
        "skill_id": skill_id,
        "name": "Canonical complete procedure candidate",
        "purpose": "Prove generic task evidence cannot directly activate a procedure",
        "level": "procedure",
        "lifecycle_state": "candidate",
        "applies_when": [{
            "rule_id": "applies", "description": "ambiguous provider outcome",
            "positive_examples": ["unknown response"], "negative_examples": [],
            "required_evidence_refs": ["local-probe:provider-status"]
        }],
        "does_not_apply_when": [{
            "rule_id": "not-applies", "description": "known terminal response",
            "positive_examples": ["terminal receipt"], "negative_examples": [],
            "required_evidence_refs": []
        }],
        "required_inputs": [{
            "name": "provider_status", "description": "current provider status",
            "required": true, "source": "current_state"
        }],
        "ordered_steps": [{
            "step_id": "probe", "order": 1, "instruction": "probe provider status",
            "expected_observation": "bounded status", "required_tool_or_capability": null,
            "stop_if_fails": true
        }],
        "required_tools_and_capabilities": [],
        "expected_outputs": [{
            "name": "status", "description": "bounded provider status",
            "evidence_required": true, "verifier_required": true
        }],
        "verification_plan": {
            "required": [{
                "name": "manual-provider-check", "command_kind": "manual_review",
                "command_display": "verify provider status", "scope": [],
                "required_for_done": true, "expected_signal": "bounded status"
            }],
            "optional": [], "acceptance_items": ["verified"]
        },
        "stop_conditions": ["provider status remains unknown"],
        "known_failure_modes": [],
        "rollback_or_recovery": "keep the candidate inactive",
        "source_trace_refs": ["experience-case:one", "experience-case:two"],
        "replay_result_refs": [],
        "success_count": 0, "failure_count": 0, "last_verified_at": null,
        "version": "candidate-v1", "owner": "mcp_protocol",
        "created_at": "2026-07-16T00:00:00Z",
        "updated_at": "2026-07-16T00:00:00Z"
    });
    let create = json!({
        "project_id": project_id,
        "task_id": task_id,
        "expected_revision": revision,
        "idempotency_key": "procedure-candidate-create-primary",
        "pattern_ref": pattern_ref,
        "candidate_skill": candidate
    });

    let pattern = json!({
        "pattern_id": pattern_id,
        "project_id": project_id,
        "member_case_refs": ["experience-case:one", "experience-case:two"],
        "invariant_core": ["ambiguous provider outcome needs a bounded probe"],
        "varying_surface_features": [],
        "success_conditions": ["provider status becomes bounded"],
        "failure_conditions": ["provider status remains unknown"],
        "counterexamples": [],
        "applicability_classifier_features": ["provider status unknown"],
        "required_local_probe": "local-probe:provider-status",
        "maturity": {
            "state": "TRANSFER_VALIDATED", "support_count": 2, "contrast_count": 1,
            "cross_host_transfer_count": 1, "negative_transfer_count": 0
        },
        "transfer_evidence": ["transfer:independent-host"],
        "authority": {
            "current_truth": false, "candidate_only": true,
            "exact_source_refs": ["experience-case:one", "experience-case:two"],
            "reasoning_job_ref": null, "review_refs": [], "canonical_receipt": null
        },
        "formed_at": "2026-07-16T00:00:00Z"
    });
    // A same-project pattern under a different task must not satisfy the exact
    // task-scoped resolver.
    managed_test_canonical_write(
        project_id.parse()?,
        Some(TaskId::new_v7()),
        AgentId::new_v7(),
        WriteId::new_v7(),
        "procedure-pattern-wrong-task",
        "experience_pattern",
        &pattern,
    )?;
    {
        let mut operator = McpClient::start_with_profile("human_operator")?;
        assert!(
            operator
                .tool_call(14, "eliot_procedure_candidate_create", &create)
                .is_err()
        );
    }
    let mut earlier_pattern = pattern.clone();
    earlier_pattern["maturity"]["state"] = json!("PATTERN_CANDIDATE");
    earlier_pattern["maturity"]["cross_host_transfer_count"] = json!(0);
    earlier_pattern["transfer_evidence"] = json!([]);
    managed_test_canonical_write(
        project_id.parse()?,
        Some(task_id.parse()?),
        AgentId::new_v7(),
        WriteId::new_v7(),
        "procedure-pattern-task_scoped-earlier-revision",
        "experience_pattern",
        &earlier_pattern,
    )?;
    let latest_pattern_receipt = managed_test_canonical_write(
        project_id.parse()?,
        Some(task_id.parse()?),
        AgentId::new_v7(),
        WriteId::new_v7(),
        "procedure-pattern-task_scoped-latest-revision",
        "experience_pattern",
        &pattern,
    )?;
    {
        let mut readonly = McpClient::start_with_profile("human_readonly")?;
        let page = readonly.tool_call(
            140,
            "eliot_operator_query",
            &json!({
                "projection": "experience_skills",
                "project_id": project_id,
                "task_id": task_id,
                "filter": {"record_kind": "experience_pattern"},
                "page_size": 20
            }),
        )?;
        let pattern_record = page["records"]
            .as_array()
            .and_then(|records| {
                records
                    .iter()
                    .find(|record| record["record_ref"] == pattern_ref)
            })
            .ok_or_else(|| std::io::Error::other("experience pattern projection missing"))?;
        assert!(
            pattern_record["actions"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
    }

    let (candidate_ref, candidate_receipt) = {
        let mut operator = McpClient::start_with_profile("human_operator")?;
        let created = operator.tool_call(15, "eliot_procedure_candidate_create", &create)?;
        assert_eq!(created["candidate"]["candidate_only"], true);
        assert_eq!(created["candidate"]["activation_applied"], false);
        assert_eq!(
            created["candidate"]["pattern_receipt"],
            serde_json::to_value(&latest_pattern_receipt)?
        );
        assert_eq!(
            created["candidate"]["pattern_observation_ref"],
            latest_pattern_receipt.write_id.to_string()
        );
        (
            required_test_string(&created, "/candidate/candidate_ref")?,
            created["canonical_receipt"].clone(),
        )
    };

    let mut reconnected = McpClient::start_with_profile("human_operator")?;
    let replay = reconnected.tool_call(16, "eliot_procedure_candidate_create", &create)?;
    assert_eq!(replay["canonical_receipt"], candidate_receipt);
    let mut alternate_key = create.clone();
    alternate_key["idempotency_key"] = json!("procedure-candidate-create-alternate-key");
    let alternate_replay =
        reconnected.tool_call(17, "eliot_procedure_candidate_create", &alternate_key)?;
    assert_eq!(alternate_replay["canonical_receipt"], candidate_receipt);
    let mut conflicting_skill = alternate_key;
    conflicting_skill["candidate_skill"]["name"] = json!("conflicting same SkillId body");
    assert!(
        reconnected
            .tool_call(18, "eliot_procedure_candidate_create", &conflicting_skill)
            .is_err()
    );

    let disposition = json!({
        "project_id": project_id,
        "task_id": task_id,
        "expected_revision": revision,
        "idempotency_key": "procedure-disposition-primary",
        "pattern_ref": pattern_ref,
        "candidate_ref": candidate_ref,
        "holdout_evidence": [],
        "negative_transfer_refs": []
    });
    let first = reconnected.tool_call(19, "eliot_procedure_candidate_disposition", &disposition)?;
    assert_eq!(
        first["disposition"]["promotion_outcome"],
        "NOT_READY_FOR_PROCEDURE"
    );
    assert_eq!(
        first["disposition"]["pattern_disposition"],
        "kept_transfer_validated"
    );
    assert_eq!(first["disposition"]["activation_applied"], false);
    assert!(
        first["disposition"]["not_ready_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons
                .iter()
                .any(|reason| { reason == "missing_independent_procedure_holdout" }))
    );
    let disposition_receipt = first["canonical_receipt"].clone();

    drop(reconnected);
    let mut after_reconnect = McpClient::start_with_profile("human_operator")?;
    let replay =
        after_reconnect.tool_call(20, "eliot_procedure_candidate_disposition", &disposition)?;
    assert_eq!(replay["canonical_receipt"], disposition_receipt);

    let mut unresolved_negative = disposition.clone();
    unresolved_negative["idempotency_key"] = json!("procedure-disposition-negative-prewrite");
    unresolved_negative["negative_transfer_refs"] =
        json!(["negative-transfer:missing-current-task_record"]);
    assert!(
        after_reconnect
            .tool_call(
                24,
                "eliot_procedure_candidate_disposition",
                &unresolved_negative
            )
            .is_err()
    );
    unresolved_negative["negative_transfer_refs"] = json!([]);
    let after_rejection = after_reconnect.tool_call(
        25,
        "eliot_procedure_candidate_disposition",
        &unresolved_negative,
    )?;
    assert!(after_rejection["canonical_receipt"].is_object());

    let mut wrong_hash = disposition.clone();
    wrong_hash["idempotency_key"] = json!("procedure-disposition-wrong-hash");
    wrong_hash["holdout_evidence"] = json!([{
        "resource_ref": holdout["resource_ref"],
        "content_hash": "f".repeat(64)
    }]);
    assert!(
        after_reconnect
            .tool_call(21, "eliot_procedure_candidate_disposition", &wrong_hash)
            .is_err()
    );
    let mut unscoped = wrong_hash;
    unscoped["idempotency_key"] = json!("procedure-disposition-unscoped");
    unscoped["holdout_evidence"] = json!([{
        "resource_ref": "artifact:not-current-task",
        "content_hash": "a".repeat(64)
    }]);
    assert!(
        after_reconnect
            .tool_call(22, "eliot_procedure_candidate_disposition", &unscoped)
            .is_err()
    );

    let mut generic_artifact = disposition;
    generic_artifact["idempotency_key"] = json!("procedure-disposition-generic-artifact");
    generic_artifact["holdout_evidence"] = json!([holdout]);
    let generic = after_reconnect.tool_call(
        23,
        "eliot_procedure_candidate_disposition",
        &generic_artifact,
    )?;
    assert_eq!(
        generic["disposition"]["promotion_outcome"],
        "NOT_READY_FOR_PROCEDURE"
    );
    assert_eq!(generic["disposition"]["activation_applied"], false);
    assert!(
        generic["disposition"]["not_ready_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.iter().any(|reason| {
                reason == "generic_task_verifier_artifact_is_not_procedure_holdout_authority"
            }))
    );

    // A fresh MCP process must read both exact canonical records back from the
    // store, including their candidate subject and original receipts.
    drop(after_reconnect);
    let mut cold_readonly = McpClient::start_with_profile("human_readonly")?;
    for (request_id, projection) in [(26, "experience_skills"), (27, "sleep_meta")] {
        for (record_kind, expected_receipt) in [
            ("procedure_skill_candidate", &candidate_receipt),
            ("procedure_promotion_disposition", &disposition_receipt),
        ] {
            let page = cold_readonly.tool_call(
                request_id,
                "eliot_operator_query",
                &json!({
                    "projection": projection,
                    "project_id": project_id,
                    "task_id": task_id,
                    "selected_ref": candidate_ref,
                    "filter": {"record_kind": record_kind},
                    "page_size": 20
                }),
            )?;
            let records = page["records"]
                .as_array()
                .ok_or_else(|| std::io::Error::other("operator records missing"))?;
            let exact = records
                .iter()
                .find(|record| {
                    record["record_kind"] == record_kind
                        && record["title"] == candidate_ref
                        && record["fields"].as_array().is_some_and(|fields| {
                            fields.iter().any(|field| {
                                field["label"] == "receipt_id"
                                    && field["value"] == expected_receipt["receipt_id"]
                            }) && fields.iter().any(|field| {
                                field["label"] == "write_id"
                                    && field["value"] == expected_receipt["write_id"]
                            }) && fields.iter().any(|field| {
                                field["label"] == "subject_ref" && field["value"] == candidate_ref
                            })
                        })
                })
                .ok_or_else(|| {
                    std::io::Error::other(format!(
                        "{record_kind} exact subject/receipt readback missing from {projection}"
                    ))
                })?;
            assert_eq!(exact["actions"], json!([]));
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn operator_cursor_survives_physical_daemon_restart_and_rejects_tampering() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    {
        let mut controller = McpClient::start()?;
        controller.tool_call(
            9,
            "eliot_task_contract_create",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "write_id": uuid::Uuid::new_v4().to_string(),
                "title": "M4 restart-stable signed operator pagination",
                "acceptance_items": [
                    {
                        "item_id": "restart",
                        "description": "signed continuation survives physical daemon restart",
                        "required_evidence": "observation"
                    },
                    {
                        "item_id": "tamper",
                        "description": "tampered continuation fails closed",
                        "required_evidence": "verification"
                    }
                ]
            }),
        )?;
        seed_operator_cursor_records(&project_id, &task_id, 129)?;
    }

    let query = json!({
        "projection": "timeline_operations",
        "project_id": project_id,
        "task_id": task_id,
        "filter": {"record_kind": "operator_control_request"},
        "page_size": 50
    });
    let secret_path = test_runtime_root()
        .join("runtime")
        .join("secrets")
        .join("operator-cursor-signing.key");
    let (first_refs, cursor, key_before) = {
        let mut operator = McpClient::start_with_profile("human_operator")?;
        let page = operator.tool_call(10, "eliot_operator_query", &query)?;
        let key = fs::read(&secret_path)?;
        assert_eq!(key.len(), 32);
        let key_hex = key
            .iter()
            .fold(String::with_capacity(key.len() * 2), |mut output, byte| {
                if std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}")).is_err() {
                    return String::new();
                }
                output
            });
        let serialized = serde_json::to_string(&page)?;
        assert!(!serialized.contains(&key_hex));
        assert!(!serialized.contains("operator-cursor-signing.key"));
        (
            operator_record_refs(&page)?,
            required_test_string(&page, "/next_cursor")?,
            key,
        )
    };

    let mut operator = McpClient::start_with_profile("human_operator")?;
    let key_after = fs::read(&secret_path)?;
    assert_eq!(key_after, key_before);
    let mut continuation = query.clone();
    continuation["cursor"] = json!(cursor);
    let second = operator.tool_call(11, "eliot_operator_query", &continuation)?;
    let second_refs = operator_record_refs(&second)?;
    let expected = (0..129)
        .map(|index| format!("canonical:operator-cursor-record-{index:03}"))
        .collect::<Vec<_>>();
    assert_eq!(first_refs, expected[..50]);
    assert_eq!(second_refs, expected[50..100]);
    assert!(
        first_refs
            .iter()
            .all(|record| !second_refs.contains(record))
    );

    let mut tampered = continuation;
    let cursor = tampered["cursor"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("continuation cursor missing"))?;
    let mut bytes = cursor.as_bytes().to_vec();
    let last = bytes
        .last_mut()
        .ok_or_else(|| std::io::Error::other("continuation cursor empty"))?;
    *last = if *last == b'a' { b'b' } else { b'a' };
    tampered["cursor"] = json!(String::from_utf8(bytes)?);
    assert!(
        operator
            .tool_call(12, "eliot_operator_query", &tampered)
            .is_err()
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn operator_candidate_review_promotes_or_rejects_through_governed_writer() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let promoted_candidate_id = uuid::Uuid::new_v4().to_string();
    let rejected_candidate_id = uuid::Uuid::new_v4().to_string();
    let source_evidence = vec![
        "native-health:passed".to_owned(),
        "host-namespace:init-channel-closed".to_owned(),
    ];

    let (task_revision, rejected_revision) = {
        let mut controller = McpClient::start()?;
        let created = controller.tool_call(
            20,
            "eliot_task_contract_create",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "write_id": uuid::Uuid::new_v4().to_string(),
                "title": "M6 reciprocal source candidate disposition",
                "acceptance_items": [
                    {
                        "item_id": "source-evidence",
                        "description": "source evidence remains bound to the candidate",
                        "required_evidence": "observation"
                    },
                    {
                        "item_id": "operator-review",
                        "description": "typed operator review emits the governed receipt",
                        "required_evidence": "verification"
                    }
                ]
            }),
        )?;
        let task_revision = required_test_u64(&created, "/task_contract/memory_revision")?;
        let candidate_without_task = json!({
            "project_id": project_id,
            "write_id": uuid::Uuid::new_v4().to_string(),
            "topic": "unscoped candidate",
            "statement": "project-only candidates require an explicit curation path",
            "provenance_refs": source_evidence.clone(),
            "freshness_rule": "never silently adopt into an operator-selected task"
        });
        assert!(
            controller
                .tool_call(18, "eliot_agent_candidate_submit", &candidate_without_task)
                .is_err()
        );
        let mut candidate_for_wrong_task = candidate_without_task;
        candidate_for_wrong_task["task_id"] = json!(uuid::Uuid::new_v4().to_string());
        candidate_for_wrong_task["write_id"] = json!(uuid::Uuid::new_v4().to_string());
        assert!(
            controller
                .tool_call(
                    19,
                    "eliot_agent_candidate_submit",
                    &candidate_for_wrong_task
                )
                .is_err()
        );
        for (id, write_id, statement) in [
            (
                21,
                promoted_candidate_id.as_str(),
                "provider source experience that passed reciprocal evidence review",
            ),
            (
                22,
                rejected_candidate_id.as_str(),
                "provider source experience contradicted by the current verifier",
            ),
        ] {
            let submitted = controller.tool_call(
                id,
                "eliot_agent_candidate_submit",
                &json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "write_id": write_id,
                    "topic": "reciprocal provider source write",
                    "statement": statement,
                    "where_applicable": ["same project and verified task scope"],
                    "where_not_applicable": ["different project or stale verifier"],
                    "negative_constraints": ["candidate never self-promotes"],
                    "provenance_refs": source_evidence.clone(),
                    "freshness_rule": "revalidate against the current task verifier before admission"
                }),
            )?;
            assert_eq!(submitted["status"], "candidate_committed");
            assert_eq!(submitted["candidate_only"], true);
        }

        let before = controller.tool_call(
            23,
            "eliot_current_state",
            &json!({"project_id": project_id}),
        )?;
        assert!(
            before["weak_or_candidate"]
                .as_array()
                .is_some_and(|claims| {
                    claims.iter().any(|claim| {
                        claim["claim_id"] == promoted_candidate_id && claim["status"] == "candidate"
                    })
                })
        );
        assert!(!before["verified_now"].as_array().is_some_and(|claims| {
            claims
                .iter()
                .any(|claim| claim["claim_id"] == promoted_candidate_id)
        }));
        let rejected_revision = before["weak_or_candidate"]
            .as_array()
            .and_then(|claims| {
                claims
                    .iter()
                    .find(|claim| claim["claim_id"] == rejected_candidate_id)
            })
            .and_then(|claim| claim["memory_revision"].as_u64())
            .ok_or_else(|| std::io::Error::other("candidate revision missing before review"))?;
        let fetched = controller.tool_call(
            24,
            "eliot_fetch_l2",
            &json!({
                "project_id": project_id,
                "handles": [promoted_candidate_id],
                "at_least_revision": null
            }),
        )?;
        assert_eq!(fetched["claims"][0]["status"], "candidate");
        assert_eq!(fetched["claims"][0]["payload"]["candidate_only"], true);
        (task_revision, rejected_revision)
    };
    let promote_command = json!({
        "project_id": project_id,
        "task_id": task_id,
        "expected_revision": task_revision,
        "idempotency_key": "operator-candidate-promote-1",
        "command": {
            "command": "review_candidate",
            "task_id": task_id,
            "candidate_ref": format!("claim:{promoted_candidate_id}"),
            "disposition": "promote",
            "evidence_refs": source_evidence.clone()
        }
    });
    let (promote_receipt, promote_role_lease_id) = {
        let mut operator = McpClient::start_with_profile("human_operator")?;
        let role_lease_id = m3_grant_task_role(
            "codex",
            &operator.agent_session_id,
            &task_id,
            "reviewer",
            "review_candidate",
        )?;
        let promoted = operator.tool_call(25, "eliot_operator_command", &promote_command)?;
        assert_eq!(promoted["accepted"], true);
        assert_eq!(promoted["executed"], true);
        assert_eq!(promoted["outcome"], "candidate_promoted_verified");
        assert!(promoted["canonical_receipt"].is_object());

        let replay = operator.tool_call(26, "eliot_operator_command", &promote_command)?;
        assert_eq!(replay["accepted"], true);
        assert_eq!(replay["canonical_receipt"], promoted["canonical_receipt"]);
        assert_eq!(replay["revision"], promoted["revision"]);

        for (id, command) in [
            (
                27,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "expected_revision": task_revision,
                    "idempotency_key": "operator-candidate-wrong-ref",
                    "command": {
                        "command": "review_candidate",
                        "task_id": task_id,
                        "candidate_ref": format!("claim:{}", uuid::Uuid::new_v4()),
                        "disposition": "promote",
                        "evidence_refs": source_evidence.clone()
                    }
                }),
            ),
            (
                28,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "expected_revision": task_revision,
                    "idempotency_key": "operator-candidate-wrong-evidence",
                    "command": {
                        "command": "review_candidate",
                        "task_id": task_id,
                        "candidate_ref": format!("claim:{promoted_candidate_id}"),
                        "disposition": "promote",
                        "evidence_refs": ["unrelated-verifier:passed"]
                    }
                }),
            ),
            (
                29,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "expected_revision": task_revision,
                    "idempotency_key": "operator-candidate-wrong-task",
                    "command": {
                        "command": "review_candidate",
                        "task_id": uuid::Uuid::new_v4().to_string(),
                        "candidate_ref": format!("claim:{promoted_candidate_id}"),
                        "disposition": "promote",
                        "evidence_refs": source_evidence.clone()
                    }
                }),
            ),
        ] {
            assert!(
                operator
                    .tool_call(id, "eliot_operator_command", &command)
                    .is_err()
            );
        }
        (promoted["canonical_receipt"].clone(), role_lease_id)
    };

    let reject_command = json!({
        "project_id": project_id,
        "task_id": task_id,
        "expected_revision": task_revision,
        "idempotency_key": "operator-candidate-reject-1",
        "command": {
            "command": "review_candidate",
            "task_id": task_id,
            "candidate_ref": format!("claim:{rejected_candidate_id}"),
            "disposition": "reject",
            "evidence_refs": source_evidence.clone()
        }
    });
    let reject_operator_session_id = {
        let mut operator = McpClient::start_with_profile("human_operator")?;
        let operator_session_id = operator.agent_session_id.clone();
        let _role_lease_id = m3_grant_task_role(
            "codex",
            &operator_session_id,
            &task_id,
            "reviewer",
            "review_candidate",
        )?;
        let rejected = operator.tool_call(30, "eliot_operator_command", &reject_command)?;
        assert_eq!(rejected["accepted"], true);
        assert_eq!(rejected["executed"], true);
        assert_eq!(rejected["outcome"], "candidate_rejected");
        assert!(rejected["canonical_receipt"].is_object());
        let replay = operator.tool_call(31, "eliot_operator_command", &reject_command)?;
        assert_eq!(replay["canonical_receipt"], rejected["canonical_receipt"]);
        assert_eq!(replay["revision"], rejected["revision"]);
        let mut changed_evidence = reject_command.clone();
        changed_evidence["command"]["evidence_refs"] = json!([
            "native-health:passed",
            "host-namespace:init-channel-closed",
            "extra-evidence:must-change-policy-fingerprint"
        ]);
        assert!(
            operator
                .tool_call(32, "eliot_operator_command", &changed_evidence)
                .is_err()
        );
        operator_session_id
    };

    let promotion_verification_id = promote_receipt["write_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("promotion receipt has no write_id"))?
        .to_owned();
    let mut controller = McpClient::start()?;
    let after = controller.tool_call(
        33,
        "eliot_current_state",
        &json!({"project_id": project_id}),
    )?;
    assert!(after["verified_now"].as_array().is_some_and(|claims| {
        claims.iter().any(|claim| {
            claim["claim_id"] == promoted_candidate_id && claim["status"] == "verified"
        })
    }));
    assert!(!after["verified_now"].as_array().is_some_and(|claims| {
        claims
            .iter()
            .any(|claim| claim["claim_id"] == rejected_candidate_id)
    }));
    let fetched = controller.tool_call(
        34,
        "eliot_fetch_l2",
        &json!({
            "project_id": project_id,
            "handles": [
                promoted_candidate_id,
                rejected_candidate_id,
                promotion_verification_id
            ],
            "at_least_revision": null
        }),
    )?;
    assert!(fetched["claims"].as_array().is_some_and(|claims| {
        claims.iter().any(|claim| {
            claim["claim_id"] == promoted_candidate_id
                && claim["status"] == "verified"
                && claim["payload"]["candidate_only"] == false
                && claim["payload"]["operator_candidate_disposition"]["disposition"] == "promote"
                && claim["payload"]["operator_candidate_disposition"]["source_write_id"]
                    == promoted_candidate_id
                && claim["payload"]["operator_candidate_disposition"]["actor_role_lease_id"]
                    == promote_role_lease_id
        })
    }));
    assert!(fetched["verification_runs"].as_array().is_some_and(|runs| {
        runs.iter().any(|run| {
            run["verification_id"] == promotion_verification_id
                && run["result"] == "passed"
                && run["payload"]["candidate_original_write_id"] == promoted_candidate_id
                && run["payload"]["project_id"] == project_id
                && run["payload"]["task_id"] == task_id
                && run["payload"]["idempotency_key"] == "operator-candidate-promote-1"
                && run["payload"]["source_provenance_refs"] == json!(source_evidence)
                && run["payload"]["operator_session_id"].is_string()
                && run["payload"]["actor_role_lease_id"] == promote_role_lease_id
        })
    }));
    assert!(fetched["claims"].as_array().is_some_and(|claims| {
        claims.iter().any(|claim| {
            claim["claim_id"] == rejected_candidate_id && claim["status"] == "candidate"
        })
    }));
    drop(controller);
    let mut operator = McpClient::start_with_profile("human_operator")?;
    let lifecycle = operator.tool_call(
        35,
        "eliot_operator_query",
        &json!({
            "projection": "memory_explorer",
            "project_id": project_id,
            "task_id": task_id,
            "filter": {"record_kind": "memory_state_transition"},
            "page_size": 20
        }),
    )?;
    let transition = lifecycle["records"]
        .as_array()
        .and_then(|records| records.first())
        .ok_or_else(|| std::io::Error::other("candidate lifecycle transition missing"))?;
    let transition_body = transition["fields"]
        .as_array()
        .and_then(|fields| {
            fields
                .iter()
                .find(|field| field["label"] == "receipt_body_json")
        })
        .and_then(|field| field["value"].as_str())
        .ok_or_else(|| std::io::Error::other("candidate transition body missing"))?;
    let transition_body: Value = serde_json::from_str(transition_body)?;
    let preconditions = transition_body["precondition_refs"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("candidate transition preconditions missing"))?;
    for expected in [
        format!("candidate-claim:{rejected_candidate_id}"),
        format!("candidate-write:{rejected_candidate_id}"),
        format!("candidate-revision:{rejected_revision}"),
        format!("candidate-project:{project_id}"),
        format!("candidate-task:{task_id}"),
    ] {
        assert!(preconditions.iter().any(|value| value == &expected));
    }
    let provenance_hash = blake3::hash(&serde_json::to_vec(&source_evidence)?)
        .to_hex()
        .to_string();
    assert!(
        preconditions
            .iter()
            .any(|value| { value == &format!("candidate-provenance-blake3:{provenance_hash}") })
    );
    assert_eq!(
        transition_body["approval_ref"],
        format!("operator-session:{reject_operator_session_id}")
    );
    drop(operator);
    let mut controller = McpClient::start()?;
    let recall = controller.tool_call(
        36,
        "eliot_recall_l0",
        &json!({
            "project_id": project_id,
            "query": "reciprocal provider source write",
            "scope": null,
            "limit": 50
        }),
    )?;
    assert!(recall["handles"].as_array().is_some_and(|handles| {
        handles
            .iter()
            .any(|handle| handle["handle"] == promoted_candidate_id)
    }));
    assert!(!recall["handles"].as_array().is_some_and(|handles| {
        handles
            .iter()
            .any(|handle| handle["handle"] == rejected_candidate_id)
    }));
    assert_eq!(promote_receipt["write_id"], promotion_verification_id);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn canonical_m2_runtime_is_receipted_sealed_exact_and_restart_safe() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let baseline_policy = json!({
        "schema_version": "1",
        "evaluator_version": "canonical-replay-evaluator-v1",
        "minimum_pass_basis_points": 9000,
        "maximum_counter_regressions": 1
    });
    let candidate_policy = json!({
        "schema_version": "1",
        "evaluator_version": "canonical-replay-evaluator-v1",
        "minimum_pass_basis_points": 10000,
        "maximum_counter_regressions": 0
    });

    {
        let mut controller = McpClient::start()?;
        let verification_id = seed_m3_verified_task(&mut controller, &project_id, &task_id)?;
        let task_state = controller.tool_call(
            201,
            "eliot_task_state",
            &json!({"project_id": project_id, "task_id": task_id}),
        )?;
        let task_revision = required_test_u64(&task_state, "/task_contract/memory_revision")?;
        let observation_id = required_test_string(&task_state, "/task_contract/observation_ids/0")?;
        let artifact_ref = required_test_string(
            &task_state,
            "/task_contract/verification_scopes/0/artifact_refs/0/resource_ref",
        )?;

        assert!(
            controller
                .tool_call(
                    202,
                    "eliot_trace_completeness",
                    &json!({
                        "project_id": project_id,
                        "task_id": task_id,
                        "expected_task_revision": task_revision,
                        "idempotency_key": "m2-fabricated-trace",
                        "trace_ref": "trace:fabricated",
                        "actual_observation_ref": format!("actual_observation:{}", uuid::Uuid::new_v4()),
                        "verifier_run_ref": format!("verifier_run:{verification_id}"),
                        "artifact_ref": format!("artifact_ref:{artifact_ref}"),
                        "source_route": "controller",
                        "source_tool": "m2-runtime-test",
                        "source_verifier": "daemon-receipt-resolution",
                        "outcome": "passed",
                        "taint": "local_verified"
                    }),
                )
                .is_err()
        );

        let trace_refs = ["trace:m2-runtime-a", "trace:m2-runtime-b"];
        for (index, trace_ref) in trace_refs.iter().enumerate() {
            let trace = controller.tool_call(
                203 + u64::try_from(index)?,
                "eliot_trace_completeness",
                &json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "expected_task_revision": task_revision,
                    "idempotency_key": format!("m2-trace-{index}"),
                    "trace_ref": trace_ref,
                    "actual_observation_ref": format!("actual_observation:{observation_id}"),
                    "verifier_run_ref": format!("verifier_run:{verification_id}"),
                    "artifact_ref": format!("artifact_ref:{artifact_ref}"),
                    "source_route": "controller",
                    "source_tool": "m2-runtime-test",
                    "source_verifier": "daemon-receipt-resolution",
                    "outcome": "passed",
                    "taint": "local_verified"
                }),
            )?;
            assert_eq!(trace["accepted"], true);
            assert_eq!(trace["trace"]["trace_ref"], *trace_ref);
            assert_eq!(
                trace["trace"]["evidence"].as_array().map(Vec::len),
                Some(13)
            );
            assert!(trace["canonical_receipt"].is_object());
        }

        for (id, conflicting_trace_ref) in [(1203, trace_refs[1]), (1204, "trace:m2-runtime-third")]
        {
            assert!(
                controller
                    .tool_call(
                        id,
                        "eliot_trace_completeness",
                        &json!({
                            "project_id": project_id,
                            "task_id": task_id,
                            "expected_task_revision": task_revision,
                            "idempotency_key": "m2-trace-0",
                            "trace_ref": conflicting_trace_ref,
                            "actual_observation_ref": format!("actual_observation:{observation_id}"),
                            "verifier_run_ref": format!("verifier_run:{verification_id}"),
                            "artifact_ref": format!("artifact_ref:{artifact_ref}"),
                            "source_route": "controller",
                            "source_tool": "m2-runtime-test",
                            "source_verifier": "daemon-receipt-resolution",
                            "outcome": "passed",
                            "taint": "local_verified"
                        }),
                    )
                    .is_err(),
                "same write identity must reject a different trace_ref even when evidence is identical"
            );
        }

        assert!(
            controller
                .tool_call(
                    205,
                    "eliot_replay_run",
                    &json!({
                        "project_id": project_id,
                        "task_id": task_id,
                        "expected_task_revision": task_revision,
                        "idempotency_key": "m2-one-case",
                        "trace_refs": [trace_refs[0]],
                        "set_name": "invalid-single-case",
                        "set_role": "fixed",
                        "set_version": 1,
                        "case_kind": "regression",
                        "baseline_policy": baseline_policy,
                        "candidate_policy": candidate_policy,
                        "baseline_version": "baseline-v1",
                        "candidate_version": "candidate-v1",
                        "sealed_context_version": "context-v1",
                        "evaluator_version": "canonical-replay-evaluator-v1"
                    }),
                )
                .is_err()
        );

        let fixed = controller.tool_call(
            206,
            "eliot_replay_run",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "expected_task_revision": task_revision,
                "idempotency_key": "m2-fixed-set",
                "trace_refs": trace_refs,
                "set_name": "m2-fixed-regression",
                "set_role": "fixed",
                "set_version": 1,
                "case_kind": "regression",
                "baseline_policy": baseline_policy,
                "candidate_policy": candidate_policy,
                "baseline_version": "baseline-v1",
                "candidate_version": "candidate-v1",
                "sealed_context_version": "context-v1",
                "evaluator_version": "canonical-replay-evaluator-v1"
            }),
        )?;
        let holdout = controller.tool_call(
            207,
            "eliot_replay_run",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "expected_task_revision": task_revision,
                "idempotency_key": "m2-holdout-set",
                "trace_refs": trace_refs,
                "set_name": "m2-holdout-regression",
                "set_role": "holdout",
                "set_version": 1,
                "case_kind": "regression",
                "baseline_policy": baseline_policy,
                "candidate_policy": candidate_policy,
                "baseline_version": "baseline-v1",
                "candidate_version": "candidate-v1",
                "sealed_context_version": "context-v1",
                "evaluator_version": "canonical-replay-evaluator-v1"
            }),
        )?;
        assert_eq!(fixed["sealed_set"]["role"], "fixed");
        assert_eq!(holdout["sealed_set"]["role"], "holdout");
        assert_eq!(fixed["cases"].as_array().map(Vec::len), Some(2));
        assert_eq!(fixed["snapshots"].as_array().map(Vec::len), Some(2));

        let sleep = controller.tool_call(
            208,
            "eliot_sleep_run",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "expected_task_revision": task_revision,
                "idempotency_key": "m2-sleep",
                "trigger": "post_task",
                "dry_run": true,
                "trace_refs": trace_refs
            }),
        )?;
        assert_eq!(sleep["artifacts"].as_array().map(Vec::len), Some(5));
        assert_eq!(sleep["artifact_receipts"].as_array().map(Vec::len), Some(5));
        assert!(
            sleep["artifact_receipts"]
                .as_array()
                .is_some_and(|receipts| receipts.iter().all(|record| {
                    record["canonical_receipt"].is_object()
                        && record["artifact"]["candidate_only"] == true
                }))
        );

        let fixed_baseline = required_test_string(&fixed, "/baseline_execution/execution_id")?;
        let fixed_candidate = required_test_string(&fixed, "/candidate_execution/execution_id")?;
        let holdout_baseline = required_test_string(&holdout, "/baseline_execution/execution_id")?;
        let holdout_candidate =
            required_test_string(&holdout, "/candidate_execution/execution_id")?;
        let meta = controller.tool_call(
            209,
            "eliot_meta_experiment_run",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "expected_task_revision": task_revision,
                "idempotency_key": "m2-meta-safe",
                "eval_run_id": uuid::Uuid::new_v4().to_string(),
                "change_class": "verification_map",
                "changed_variables": ["minimum_pass_basis_points"],
                "baseline_policy": baseline_policy,
                "candidate_policy": candidate_policy,
                "fixed_baseline_execution_id": fixed_baseline,
                "fixed_candidate_execution_id": fixed_candidate,
                "holdout_baseline_execution_id": holdout_baseline,
                "holdout_candidate_execution_id": holdout_candidate
            }),
        )?;
        assert_eq!(meta["accepted"], true);
        assert_eq!(meta["assessment"]["eligible_for_promotion"], true);
        assert_eq!(meta["metric_receipts"].as_array().map(Vec::len), Some(2));
        assert!(meta["isolation_rejection_receipt"].is_null());
        let experiment_id =
            required_test_string(&meta, "/experiment/harness_experiment_record_id")?;
        let experiment_revision = required_test_u64(&meta, "/experiment_revision")?;
        let promotion_hash =
            required_test_string(&meta, "/policy_candidate/promotion_action_hash")?;

        assert!(
            controller
                .tool_call(
                    210,
                    "eliot_meta_experiment_disposition",
                    &json!({
                        "project_id": project_id,
                        "task_id": task_id,
                        "expected_task_revision": task_revision,
                        "idempotency_key": "m2-promote-wrong-hash",
                        "experiment_id": experiment_id,
                        "expected_experiment_revision": experiment_revision,
                        "decision": "PROMOTED",
                        "operator_command_ref": "operator:m2-runtime",
                        "expected_action_hash": "fabricated"
                    }),
                )
                .is_err()
        );
        let promote_request = |key: &str| {
            json!({
                "project_id": project_id,
                "task_id": task_id,
                "expected_task_revision": task_revision,
                "idempotency_key": key,
                "experiment_id": experiment_id,
                "expected_experiment_revision": experiment_revision,
                "decision": "PROMOTED",
                "operator_command_ref": "operator:m2-runtime",
                "expected_action_hash": promotion_hash
            })
        };
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for key in ["m2-promote-a", "m2-promote-b"] {
            let mut concurrent = McpClient::connect_to_running()?;
            let barrier = barrier.clone();
            let request = promote_request(key);
            handles.push(thread::spawn(move || {
                barrier.wait();
                (
                    key,
                    concurrent.tool_call(211, "eliot_meta_experiment_disposition", &request),
                )
            }));
        }
        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| std::io::Error::other("meta thread panicked"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        let (winning_key, promoted) = outcomes
            .into_iter()
            .find_map(|(key, result)| result.ok().map(|value| (key, value)))
            .ok_or_else(|| std::io::Error::other("no meta promotion won CAS"))?;
        assert_eq!(promoted["action"], "promote");
        assert_eq!(promoted["policy_candidate"]["state"], "promoted");
        let promote_replay = controller.tool_call(
            212,
            "eliot_meta_experiment_disposition",
            &promote_request(winning_key),
        )?;
        assert_eq!(promote_replay["accepted"], true);
        assert_eq!(promote_replay["replayed"], true);
        assert_eq!(promote_replay["promotion"], promoted["promotion"]);
        assert_eq!(
            promote_replay["canonical_receipts"]["promotion"],
            promoted["canonical_receipts"]["promotion"]
        );
        let rollback_hash = required_test_string(&promoted, "/rollback_action_hash")?;
        let rolled_back = controller.tool_call(
            213,
            "eliot_meta_experiment_disposition",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "expected_task_revision": task_revision,
                "idempotency_key": "m2-rollback",
                "experiment_id": experiment_id,
                "expected_experiment_revision": experiment_revision,
                "decision": "PROMOTED",
                "rollback_requested": true,
                "operator_command_ref": "operator:m2-runtime",
                "expected_action_hash": rollback_hash
            }),
        )?;
        assert_eq!(rolled_back["action"], "rollback");
        assert_eq!(rolled_back["policy_candidate"]["state"], "rolled_back");
        let rollback_replay = controller.tool_call(
            214,
            "eliot_meta_experiment_disposition",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "expected_task_revision": task_revision,
                "idempotency_key": "m2-rollback",
                "experiment_id": experiment_id,
                "expected_experiment_revision": experiment_revision,
                "decision": "PROMOTED",
                "rollback_requested": true,
                "operator_command_ref": "operator:m2-runtime",
                "expected_action_hash": rollback_hash
            }),
        )?;
        assert_eq!(rollback_replay["replayed"], true);
        assert_eq!(rollback_replay["rollback"], rolled_back["rollback"]);
        assert_eq!(
            rollback_replay["canonical_receipts"]["rollback"],
            rolled_back["canonical_receipts"]["rollback"]
        );
        assert!(
            controller
                .tool_call(
                    215,
                    "eliot_meta_experiment_disposition",
                    &json!({
                        "project_id": project_id,
                        "task_id": task_id,
                        "expected_task_revision": task_revision,
                        "idempotency_key": "m2-rollback-distinct-repeat",
                        "experiment_id": experiment_id,
                        "expected_experiment_revision": experiment_revision,
                        "decision": "PROMOTED",
                        "rollback_requested": true,
                        "operator_command_ref": "operator:m2-runtime",
                        "expected_action_hash": rollback_hash
                    }),
                )
                .is_err()
        );

        assert!(
            controller
                .tool_call(
                    216,
                    "eliot_meta_experiment_run",
                    &json!({
                        "project_id": project_id,
                        "task_id": task_id,
                        "expected_task_revision": task_revision,
                        "idempotency_key": "m2-unsupported-class",
                        "eval_run_id": uuid::Uuid::new_v4().to_string(),
                        "change_class": "admission_rule",
                        "changed_variables": ["admission_rule"],
                        "baseline_policy": baseline_policy,
                        "candidate_policy": candidate_policy,
                        "fixed_baseline_execution_id": fixed_baseline,
                        "fixed_candidate_execution_id": fixed_candidate,
                        "holdout_baseline_execution_id": holdout_baseline,
                        "holdout_candidate_execution_id": holdout_candidate
                    }),
                )
                .is_err()
        );
        let rejection_request = json!({
            "project_id": project_id,
            "task_id": task_id,
            "expected_task_revision": task_revision,
            "idempotency_key": "m2-isolation-rejection",
            "eval_run_id": uuid::Uuid::new_v4().to_string(),
            "change_class": "verification_map",
            "changed_variables": ["evaluator_version"],
            "baseline_policy": baseline_policy,
            "candidate_policy": candidate_policy,
            "fixed_baseline_execution_id": fixed_baseline,
            "fixed_candidate_execution_id": fixed_candidate,
            "holdout_baseline_execution_id": holdout_baseline,
            "holdout_candidate_execution_id": holdout_candidate,
            "attempted_fence": {
                "evaluator_version": "fabricated",
                "evaluator_hash": "fabricated",
                "threshold_version": "fabricated",
                "threshold_hash": "fabricated",
                "fixed_replay_set_hash": "fabricated",
                "holdout_replay_set_hash": "fabricated"
            }
        });
        let rejected =
            controller.tool_call(217, "eliot_meta_experiment_run", &rejection_request)?;
        assert_eq!(rejected["accepted"], false);
        assert!(rejected["isolation_rejection_receipt"].is_array());
        assert!(rejected["assessment"]["records"]["isolation_rejection"].is_object());
        let rejection_replay =
            controller.tool_call(218, "eliot_meta_experiment_run", &rejection_request)?;
        assert_eq!(rejection_replay["accepted"], false);
        assert_eq!(rejection_replay["replayed"], true);
        assert_eq!(
            rejection_replay["isolation_rejection_receipt"],
            rejected["isolation_rejection_receipt"]
        );
    }

    {
        let mut reconnected = McpClient::start()?;
        let status = reconnected.tool_call(
            216,
            "eliot_l11_status",
            &json!({"project_id": project_id, "task_id": task_id}),
        )?;
        assert_eq!(
            status["registered_traces"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            status["candidate_artifacts"].as_array().map(Vec::len),
            Some(5)
        );
        assert_eq!(
            status["sealed_replay_sets"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            status["sealed_replay_executions"].as_array().map(Vec::len),
            Some(4)
        );
        assert!(
            status["meta_metric_evidence"]
                .as_array()
                .is_some_and(|records| records.len() >= 4)
        );
        assert_eq!(
            status["meta_isolation_rejections"].as_array().map(Vec::len),
            Some(1)
        );
        assert!(
            status["policy_execution_receipts"]
                .as_array()
                .is_some_and(|records| records.len() >= 2)
        );
    }
    let mut operator = McpClient::start_with_profile("human_operator")?;
    let projection = operator.tool_call(
        217,
        "eliot_operator_query",
        &json!({
            "projection": "sleep_meta",
            "project_id": project_id,
            "task_id": task_id,
            "filter": {},
            "page_size": 100
        }),
    )?;
    let kinds = projection["records"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("sleep/meta projection records missing"))?
        .iter()
        .filter_map(|record| record["record_kind"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "trace_completeness_contract",
        "replay_set",
        "sealed_replay_run",
        "sleep_consolidation_bundle",
        "meta_metric_evidence",
        "meta_isolation_rejection",
        "experimental_policy_candidate",
        "meta_policy_promotion",
        "meta_policy_rollback",
    ] {
        assert!(
            kinds.contains(&expected),
            "missing operator record {expected}"
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn canonical_m2_stale_trace_fails_closed_after_task_revision_advances() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let mut client = McpClient::start()?;
    let fixture = seed_m2_trace_fixture(&mut client, &project_id, &task_id, 400)?;
    let completed = client.tool_call(
        403,
        "eliot_submit_completion_proof",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": uuid::Uuid::new_v4().to_string(),
            "expected_revision": fixture.task_revision,
            "completion_proof": completion_proof_for_task_contract(&fixture.task_contract)?,
            "acceptance_item_ids": ["observed", "verified"],
            "observation_ids": [fixture.observation_id],
            "verification_ids": [fixture.verification_id]
        }),
    )?;
    assert_eq!(completed["decision"], "DONE_VERIFIED");
    let advanced_revision = required_test_u64(&completed, "/task_contract/memory_revision")?;
    let (baseline_policy, candidate_policy) = m2_replay_policies();
    assert!(
        client
            .tool_call(
                404,
                "eliot_replay_run",
                &json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "expected_task_revision": advanced_revision,
                    "idempotency_key": "m2-stale-trace-replay",
                    "trace_refs": fixture.trace_refs,
                    "set_name": "stale-trace-must-fail",
                    "set_role": "fixed",
                    "set_version": 1,
                    "case_kind": "regression",
                    "baseline_policy": baseline_policy,
                    "candidate_policy": candidate_policy,
                    "baseline_version": "baseline-v1",
                    "candidate_version": "candidate-v1",
                    "sealed_context_version": "context-v1",
                    "evaluator_version": "canonical-replay-evaluator-v1"
                }),
            )
            .is_err()
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn canonical_sleep_aggregate_heals_partial_secondaries_after_restart() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let (fixture, request) = {
        let mut failing = McpClient::start_with_sleep_failure_after(2)?;
        let fixture = seed_m2_trace_fixture(&mut failing, &project_id, &task_id, 500)?;
        let request = json!({
            "project_id": project_id,
            "task_id": task_id,
            "expected_task_revision": fixture.task_revision,
            "idempotency_key": "m2-sleep-restart-heal",
            "trigger": "post_task",
            "dry_run": true,
            "trace_refs": fixture.trace_refs
        });
        assert!(failing.tool_call(503, "eliot_sleep_run", &request).is_err());
        (fixture, request)
    };
    let mut reconnected = McpClient::start()?;
    let healed = reconnected.tool_call(504, "eliot_sleep_run", &request)?;
    assert_eq!(healed["accepted"], true);
    assert_eq!(healed["replayed"], true);
    assert_eq!(healed["artifacts"].as_array().map(Vec::len), Some(5));
    assert_eq!(
        healed["artifact_receipts"].as_array().map(Vec::len),
        Some(5)
    );
    let status = reconnected.tool_call(
        505,
        "eliot_l11_status",
        &json!({"project_id": project_id, "task_id": task_id}),
    )?;
    assert_eq!(status["sleep_runs"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        status["candidate_artifacts"].as_array().map(Vec::len),
        Some(5)
    );
    assert_eq!(fixture.trace_refs.len(), 2);
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn canonical_m2_interrupted_aggregates_heal_exactly_after_restart() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let fixture = {
        let mut controller = McpClient::start()?;
        seed_m2_meta_replay_fixture(&mut controller, &project_id, &task_id, 600)?
    };
    let context = M2InterruptedContext {
        project_id: &project_id,
        task_id: &task_id,
        fixture: &fixture,
    };
    assert_interrupted_replay_heals(&context)?;
    let action = assert_interrupted_safe_meta_heals(&context)?;
    let rollback_hash = assert_interrupted_promotion_heals(&context, &action)?;
    assert_interrupted_rollback_heals(&context, &action, &rollback_hash)?;
    assert_interrupted_rejected_meta_heals(&context, &action.candidate_id)?;
    Ok(())
}

struct M2InterruptedContext<'a> {
    project_id: &'a str,
    task_id: &'a str,
    fixture: &'a M2MetaReplayFixture,
}

struct M2InterruptedActionFixture {
    experiment_id: String,
    experiment_revision: u64,
    candidate_id: String,
    promotion_hash: String,
}

fn assert_interrupted_replay_heals(context: &M2InterruptedContext<'_>) -> TestResult {
    let project_id = context.project_id;
    let task_id = context.task_id;
    let fixture = context.fixture;
    let replay_key = "m2-replay-interrupted";
    let replay_request = m2_replay_request(M2ReplayRequest {
        project_id,
        task_id,
        task_revision: fixture.task_revision,
        idempotency_key: replay_key,
        role: "fixed",
        trace_refs: &fixture.trace_refs,
        baseline_policy: &fixture.baseline_policy,
        candidate_policy: &fixture.candidate_policy,
    });
    {
        let mut failing = McpClient::start_with_replay_failure(replay_key)?;
        assert!(
            failing
                .tool_call(620, "eliot_replay_run", &replay_request)
                .is_err()
        );
    }
    let healed_replay = {
        let mut controller = McpClient::start()?;
        let partial_status = controller.tool_call(
            621,
            "eliot_l11_status",
            &json!({"project_id": project_id, "task_id": task_id}),
        )?;
        assert_eq!(
            partial_status["sealed_replay_executions"]
                .as_array()
                .map(Vec::len),
            Some(4)
        );
        let mut conflicting = replay_request.clone();
        conflicting["set_name"] = json!("changed-input-with-same-key");
        assert!(
            controller
                .tool_call(622, "eliot_replay_run", &conflicting)
                .is_err()
        );
        let healed = controller.tool_call(623, "eliot_replay_run", &replay_request)?;
        assert_eq!(healed["replayed"], true);
        assert_eq!(healed["cases"].as_array().map(Vec::len), Some(2));
        assert_eq!(healed["snapshots"].as_array().map(Vec::len), Some(2));
        healed
    };
    let healed_candidate_write = required_test_string(
        &healed_replay,
        "/canonical_receipts/candidate_execution/0/write_id",
    )?;
    {
        let mut controller = McpClient::start()?;
        let ambiguous_request = m2_replay_request(M2ReplayRequest {
            project_id,
            task_id,
            task_revision: fixture.task_revision,
            idempotency_key: "m2-replay-ambiguous-candidate",
            role: "fixed",
            trace_refs: &fixture.trace_refs,
            baseline_policy: &fixture.baseline_policy,
            candidate_policy: &fixture.candidate_policy,
        });
        let ambiguous = controller.tool_call(624, "eliot_replay_run", &ambiguous_request)?;
        let ambiguous_candidate_write = required_test_string(
            &ambiguous,
            "/canonical_receipts/candidate_execution/0/write_id",
        )?;
        assert_ne!(ambiguous_candidate_write, healed_candidate_write);
        let exact = controller.tool_call(625, "eliot_replay_run", &replay_request)?;
        assert_eq!(exact["replayed"], true);
        assert_eq!(
            required_test_string(&exact, "/canonical_receipts/candidate_execution/0/write_id")?,
            healed_candidate_write
        );
    }
    Ok(())
}

fn assert_interrupted_safe_meta_heals(
    context: &M2InterruptedContext<'_>,
) -> TestResult<M2InterruptedActionFixture> {
    let project_id = context.project_id;
    let task_id = context.task_id;
    let fixture = context.fixture;
    let safe_key = "m2-meta-primary-safe-interrupted";
    let safe_request = m2_meta_request(
        fixture,
        project_id,
        task_id,
        safe_key,
        &uuid::Uuid::new_v4().to_string(),
        None,
    );
    {
        let mut failing = McpClient::start_with_meta_experiment_failure(safe_key)?;
        assert!(
            failing
                .tool_call(630, "eliot_meta_experiment_run", &safe_request)
                .is_err()
        );
    }
    let safe = {
        let mut controller = McpClient::start()?;
        let healed = controller.tool_call(631, "eliot_meta_experiment_run", &safe_request)?;
        assert_eq!(healed["accepted"], true);
        assert_eq!(healed["replayed"], true);
        assert_eq!(healed["metric_receipts"].as_array().map(Vec::len), Some(2));
        assert!(healed["policy_candidate"]["canonical_receipt"].is_array());
        healed
    };
    let experiment_id = required_test_string(&safe, "/experiment/harness_experiment_record_id")?;
    let experiment_revision = required_test_u64(&safe, "/experiment_revision")?;
    let candidate_id = required_test_string(&safe, "/policy_candidate/candidate/candidate_id")?;
    let promotion_hash = required_test_string(&safe, "/policy_candidate/promotion_action_hash")?;
    Ok(M2InterruptedActionFixture {
        experiment_id,
        experiment_revision,
        candidate_id,
        promotion_hash,
    })
}

fn assert_interrupted_promotion_heals(
    context: &M2InterruptedContext<'_>,
    action: &M2InterruptedActionFixture,
) -> TestResult<String> {
    let project_id = context.project_id;
    let task_id = context.task_id;
    let fixture = context.fixture;
    let experiment_id = &action.experiment_id;
    let experiment_revision = action.experiment_revision;
    let promotion_hash = &action.promotion_hash;
    let promotion_key = "m2-meta-promotion-interrupted";
    let promotion_request = json!({
        "project_id": project_id,
        "task_id": task_id,
        "expected_task_revision": fixture.task_revision,
        "idempotency_key": promotion_key,
        "experiment_id": experiment_id,
        "expected_experiment_revision": experiment_revision,
        "decision": "PROMOTED",
        "operator_command_ref": "operator:m2-interruption-proof",
        "expected_action_hash": promotion_hash
    });
    {
        let mut failing = McpClient::start_with_meta_action_failure(promotion_key)?;
        assert!(
            failing
                .tool_call(632, "eliot_meta_experiment_disposition", &promotion_request)
                .is_err()
        );
    }
    let promoted = {
        let mut controller = McpClient::start()?;
        let mut distinct = promotion_request.clone();
        distinct["idempotency_key"] = json!("m2-meta-promotion-distinct-after-crash");
        assert!(
            controller
                .tool_call(633, "eliot_meta_experiment_disposition", &distinct)
                .is_err()
        );
        let healed =
            controller.tool_call(634, "eliot_meta_experiment_disposition", &promotion_request)?;
        assert_eq!(healed["accepted"], true);
        assert_eq!(healed["replayed"], true);
        assert_eq!(healed["policy_candidate"]["state"], "promoted");
        healed
    };
    let rollback_hash = required_test_string(&promoted, "/rollback_action_hash")?;
    Ok(rollback_hash)
}

fn assert_interrupted_rollback_heals(
    context: &M2InterruptedContext<'_>,
    action: &M2InterruptedActionFixture,
    rollback_hash: &str,
) -> TestResult {
    let project_id = context.project_id;
    let task_id = context.task_id;
    let fixture = context.fixture;
    let experiment_id = &action.experiment_id;
    let experiment_revision = action.experiment_revision;
    let rollback_key = "m2-meta-rollback-interrupted";
    let rollback_request = json!({
        "project_id": project_id,
        "task_id": task_id,
        "expected_task_revision": fixture.task_revision,
        "idempotency_key": rollback_key,
        "experiment_id": experiment_id,
        "expected_experiment_revision": experiment_revision,
        "decision": "PROMOTED",
        "rollback_requested": true,
        "operator_command_ref": "operator:m2-interruption-proof",
        "expected_action_hash": rollback_hash
    });
    {
        let mut failing = McpClient::start_with_meta_action_failure(rollback_key)?;
        assert!(
            failing
                .tool_call(635, "eliot_meta_experiment_disposition", &rollback_request)
                .is_err()
        );
    }
    let rollback = {
        let mut controller = McpClient::start()?;
        let mut distinct = rollback_request.clone();
        distinct["idempotency_key"] = json!("m2-meta-rollback-distinct-after-crash");
        assert!(
            controller
                .tool_call(636, "eliot_meta_experiment_disposition", &distinct)
                .is_err()
        );
        let healed =
            controller.tool_call(637, "eliot_meta_experiment_disposition", &rollback_request)?;
        assert_eq!(healed["accepted"], true);
        assert_eq!(healed["replayed"], true);
        assert_eq!(healed["policy_candidate"]["state"], "rolled_back");
        let exact =
            controller.tool_call(638, "eliot_meta_experiment_disposition", &rollback_request)?;
        assert_eq!(exact["rollback"], healed["rollback"]);
        assert_eq!(
            exact["canonical_receipts"]["rollback"],
            healed["canonical_receipts"]["rollback"]
        );
        healed
    };
    assert!(rollback["canonical_receipts"]["candidate_state"].is_array());
    Ok(())
}

fn assert_interrupted_rejected_meta_heals(
    context: &M2InterruptedContext<'_>,
    candidate_id: &str,
) -> TestResult {
    let project_id = context.project_id;
    let task_id = context.task_id;
    let fixture = context.fixture;
    let rejected_key = "m2-meta-primary-rejected-interrupted";
    let rejected_request = m2_meta_request(
        fixture,
        project_id,
        task_id,
        rejected_key,
        &uuid::Uuid::new_v4().to_string(),
        Some(json!({
            "evaluator_version": "fabricated",
            "evaluator_hash": "fabricated",
            "threshold_version": "fabricated",
            "threshold_hash": "fabricated",
            "fixed_replay_set_hash": "fabricated",
            "holdout_replay_set_hash": "fabricated"
        })),
    );
    {
        let mut failing = McpClient::start_with_meta_experiment_failure(rejected_key)?;
        assert!(
            failing
                .tool_call(640, "eliot_meta_experiment_run", &rejected_request)
                .is_err()
        );
    }
    let mut controller = McpClient::start()?;
    let rejected = controller.tool_call(641, "eliot_meta_experiment_run", &rejected_request)?;
    assert_eq!(rejected["accepted"], false);
    assert_eq!(rejected["replayed"], true);
    assert!(rejected["isolation_rejection_receipt"].is_array());
    assert!(rejected["policy_candidate"].is_null());
    let rejected_exact =
        controller.tool_call(642, "eliot_meta_experiment_run", &rejected_request)?;
    assert_eq!(rejected_exact["accepted"], false);
    assert_eq!(
        rejected_exact["isolation_rejection_receipt"],
        rejected["isolation_rejection_receipt"]
    );
    let status = controller.tool_call(
        643,
        "eliot_l11_status",
        &json!({"project_id": project_id, "task_id": task_id}),
    )?;
    let terminal_actions = status["policy_execution_receipts"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("policy execution receipts missing"))?
        .iter()
        .filter(|record| record["receipt_body"]["candidate_id"] == candidate_id)
        .collect::<Vec<_>>();
    assert_eq!(
        terminal_actions
            .iter()
            .filter(|record| record["receipt_body"]["action"] == "promote")
            .count(),
        1
    );
    assert_eq!(
        terminal_actions
            .iter()
            .filter(|record| record["receipt_body"]["action"] == "rollback")
            .count(),
        1
    );
    assert!(
        status["meta_metric_evidence"]
            .as_array()
            .is_some_and(|records| records.len() >= 4)
    );
    assert!(
        status["meta_isolation_rejections"]
            .as_array()
            .is_some_and(|records| records.len() == 1)
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn canonical_m2_exact_authority_survives_projection_saturation_and_restart() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let fixture = {
        let mut controller = McpClient::start()?;
        let fixture = seed_m2_meta_replay_fixture(&mut controller, &project_id, &task_id, 660)?;
        seed_m2_projection_noise(&mut controller, &fixture, &project_id, &task_id)?;
        fixture
    };
    let context = M2InterruptedContext {
        project_id: &project_id,
        task_id: &task_id,
        fixture: &fixture,
    };
    assert_saturated_replay_heals(&context)?;
    let action = assert_interrupted_safe_meta_heals(&context)?;
    let rollback_hash = assert_interrupted_promotion_heals(&context, &action)?;
    assert_interrupted_rollback_heals(&context, &action, &rollback_hash)?;
    assert_saturated_rejected_meta_heals(&context)?;
    assert_saturated_sleep_heals(&context)?;
    Ok(())
}

fn assert_saturated_replay_heals(context: &M2InterruptedContext<'_>) -> TestResult {
    let key = "m2-saturated-replay-interrupted";
    let request = m2_replay_request(M2ReplayRequest {
        project_id: context.project_id,
        task_id: context.task_id,
        task_revision: context.fixture.task_revision,
        idempotency_key: key,
        role: "fixed",
        trace_refs: &context.fixture.trace_refs,
        baseline_policy: &context.fixture.baseline_policy,
        candidate_policy: &context.fixture.candidate_policy,
    });
    {
        let mut failing = McpClient::start_with_replay_failure(key)?;
        assert!(
            failing
                .tool_call(670, "eliot_replay_run", &request)
                .is_err()
        );
    }
    let mut controller = McpClient::start()?;
    let healed = controller.tool_call(671, "eliot_replay_run", &request)?;
    assert_eq!(healed["replayed"], true);
    assert_eq!(healed["cases"].as_array().map(Vec::len), Some(2));
    let exact = controller.tool_call(672, "eliot_replay_run", &request)?;
    assert_eq!(exact["canonical_receipts"], healed["canonical_receipts"]);
    let mut conflicting = request;
    conflicting["set_name"] = json!("saturated-conflicting-input");
    assert!(
        controller
            .tool_call(673, "eliot_replay_run", &conflicting)
            .is_err()
    );
    Ok(())
}

fn assert_saturated_rejected_meta_heals(context: &M2InterruptedContext<'_>) -> TestResult {
    let key = "m2-saturated-rejected-interrupted";
    let request = m2_meta_request(
        context.fixture,
        context.project_id,
        context.task_id,
        key,
        &uuid::Uuid::new_v4().to_string(),
        Some(json!({
            "evaluator_version": "saturated",
            "evaluator_hash": "saturated",
            "threshold_version": "saturated",
            "threshold_hash": "saturated",
            "fixed_replay_set_hash": "saturated",
            "holdout_replay_set_hash": "saturated"
        })),
    );
    {
        let mut failing = McpClient::start_with_meta_experiment_failure(key)?;
        assert!(
            failing
                .tool_call(674, "eliot_meta_experiment_run", &request)
                .is_err()
        );
    }
    let mut controller = McpClient::start()?;
    let healed = controller.tool_call(675, "eliot_meta_experiment_run", &request)?;
    assert_eq!(healed["accepted"], false);
    assert_eq!(healed["replayed"], true);
    assert!(healed["isolation_rejection_receipt"].is_array());
    let exact = controller.tool_call(676, "eliot_meta_experiment_run", &request)?;
    assert_eq!(
        exact["isolation_rejection_receipt"],
        healed["isolation_rejection_receipt"]
    );
    Ok(())
}

fn assert_saturated_sleep_heals(context: &M2InterruptedContext<'_>) -> TestResult {
    let request = json!({
        "project_id": context.project_id,
        "task_id": context.task_id,
        "expected_task_revision": context.fixture.task_revision,
        "idempotency_key": "m2-saturated-sleep-interrupted",
        "trigger": "post_task",
        "dry_run": true,
        "trace_refs": context.fixture.trace_refs
    });
    {
        let mut failing = McpClient::start_with_sleep_failure_after(2)?;
        assert!(failing.tool_call(677, "eliot_sleep_run", &request).is_err());
    }
    let mut controller = McpClient::start()?;
    let healed = controller.tool_call(678, "eliot_sleep_run", &request)?;
    assert_eq!(healed["replayed"], true);
    assert_eq!(
        healed["artifact_receipts"].as_array().map(Vec::len),
        Some(5)
    );
    let exact = controller.tool_call(679, "eliot_sleep_run", &request)?;
    assert_eq!(exact["artifacts"], healed["artifacts"]);
    let healed_receipts = healed["artifact_receipts"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("healed sleep artifact receipts missing"))?;
    let exact_receipts = exact["artifact_receipts"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("exact sleep artifact receipts missing"))?;
    for (healed, exact) in healed_receipts.iter().zip(exact_receipts) {
        assert_eq!(exact["canonical_receipt"], healed["canonical_receipt"]);
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn bounded_autonomy_runtime_is_durable_scoped_and_verifier_gated() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let run_id = "m3-production-runtime";
    let workspace = m3_fixture_repository()?;

    let (daemon_owner, created_task, controller_session_id, claimed_work) = {
        let mut controller = McpClient::start_in_workspace(&workspace)?;
        let created_task = create_m3_task_fixture(&mut controller, &project_id, &task_id)?;
        let controller_session_id = controller.agent_session_id.clone();
        let mut fixture_call_id = 200;
        let claimed_work = vec![
            m3_claim_work_fixture(
                &mut controller,
                &project_id,
                &task_id,
                "opencode",
                "opencode/candidate.txt",
                &mut fixture_call_id,
            )?,
            m3_claim_work_fixture(
                &mut controller,
                &project_id,
                &task_id,
                "antigravity",
                "antigravity/candidate.txt",
                &mut fixture_call_id,
            )?,
            m3_claim_work_fixture(
                &mut controller,
                &project_id,
                &task_id,
                "antigravity",
                "final/candidate.txt",
                &mut fixture_call_id,
            )?,
        ];
        (
            controller,
            created_task,
            controller_session_id,
            claimed_work,
        )
    };
    let controller_role_lease_id = m3_grant_task_role(
        "codex",
        &controller_session_id,
        &task_id,
        "controller",
        "delegate,review,verify",
    )?;
    let mut worker_role_lease_ids = Vec::with_capacity(claimed_work.len());
    for claimed in &claimed_work {
        worker_role_lease_ids.push(m3_grant_task_role(
            &claimed.host,
            &claimed.worker_session_id,
            &task_id,
            "implementer",
            "rust",
        )?);
    }
    drop(daemon_owner);

    let (
        verification_id,
        verifier_scope_hash,
        state_revision,
        mut runtime_revision,
        host_chains,
        retired_worktree_leases,
    ) = {
        let mut controller = McpClient::start_scoped_in_workspace(
            &workspace,
            "codex",
            &controller_session_id,
            &controller_role_lease_id,
            &task_id,
        )?;
        assert_eq!(controller.agent_session_id, controller_session_id);
        let created_task =
            refresh_m3_task_fixture(&mut controller, &project_id, &task_id, created_task)?;
        let mut fixture_call_id = 206;
        let mut claimed_work = claimed_work.into_iter();
        let mut worker_role_lease_ids = worker_role_lease_ids.into_iter();
        let first_prepared = m3_prepare_host_authority_fixture(
            &mut controller,
            &workspace,
            &project_id,
            &task_id,
            claimed_work
                .next()
                .ok_or_else(|| std::io::Error::other("OpenCode work claim missing"))?,
            worker_role_lease_ids
                .next()
                .ok_or_else(|| std::io::Error::other("OpenCode role lease missing"))?,
            &created_task.verifier_ref,
            &mut fixture_call_id,
        )?;
        let second_prepared = m3_prepare_host_authority_fixture(
            &mut controller,
            &workspace,
            &project_id,
            &task_id,
            claimed_work
                .next()
                .ok_or_else(|| std::io::Error::other("Antigravity work claim missing"))?,
            worker_role_lease_ids
                .next()
                .ok_or_else(|| std::io::Error::other("Antigravity role lease missing"))?,
            &created_task.verifier_ref,
            &mut fixture_call_id,
        )?;
        let third_prepared = m3_prepare_host_authority_fixture(
            &mut controller,
            &workspace,
            &project_id,
            &task_id,
            claimed_work
                .next()
                .ok_or_else(|| std::io::Error::other("final work claim missing"))?,
            worker_role_lease_ids
                .next()
                .ok_or_else(|| std::io::Error::other("final role lease missing"))?,
            &created_task.verifier_ref,
            &mut fixture_call_id,
        )?;
        let created_task =
            refresh_m3_task_fixture(&mut controller, &project_id, &task_id, created_task)?;
        let verification_id =
            observe_and_verify_m3_task(&mut controller, &project_id, &task_id, &created_task)?;
        let task_state = controller.tool_call(
            85,
            "eliot_task_state",
            &json!({"project_id": project_id, "task_id": task_id}),
        )?;
        let verifier_scope_hash = required_test_string(
            &task_state,
            "/task_contract/verification_scopes/0/canonical_scope_hash",
        )?;
        let verifier_ref = format!("verification:{verification_id}");
        let first_chain = m3_finalize_host_authority_fixture(
            &mut controller,
            &workspace,
            &task_id,
            first_prepared,
            &verifier_ref,
            &mut fixture_call_id,
        )?;
        let second_chain = m3_finalize_host_authority_fixture(
            &mut controller,
            &workspace,
            &task_id,
            second_prepared,
            &verifier_ref,
            &mut fixture_call_id,
        )?;
        let third_chain = m3_finalize_host_authority_fixture(
            &mut controller,
            &workspace,
            &task_id,
            third_prepared,
            &verifier_ref,
            &mut fixture_call_id,
        )?;
        let first_work = first_chain.work_item_id.clone();
        let second_work = second_chain.work_item_id.clone();
        let third_work = third_chain.work_item_id.clone();
        drop(controller);
        let mut controller = McpClient::start_in_workspace(&workspace)?;
        controller.tool_call(
            100,
            "eliot_autonomy_contract_write",
            &json!({
                "contract": {
                    "autonomy_run_id": run_id,
                    "project_id": project_id,
                    "root_task_id": task_id,
                    "user_goal": "finish M6 and bounded product backlog with durable runtime evidence",
                    "acceptance_items": ["verified"],
                    "contour_route_policy_ref": "route-policy-m3",
                    "allowed_projects": [project_id],
                    "max_work_items": 3,
                    "max_active_agents": 2,
                    "max_model_invocations": 10,
                    "max_tool_calls": 20,
                    "max_wall_time_seconds": 3600,
                    "cost_or_token_budget": "50000 tokens",
                    "allowed_paths": ["opencode", "antigravity", "final"],
                    "forbidden_paths": [".git", "secrets"],
                    "forbidden_effects": ["service_install", "network_write"],
                    "allowed_risk_tiers": ["R1", "R2", "R3"],
                    "required_verifiers": ["daemon-receipt-resolution"],
                    "approval_boundaries": ["R3"],
                    "pause_conditions": ["canonical tripwire"],
                    "stop_conditions": ["CompletionProof verified"],
                    "fallback_routes": [
                        {
                            "host_id": "opencode",
                            "model_route_optional": null,
                            "requested_role": "worker",
                            "capability_requirements": ["rust"]
                        },
                        {
                            "host_id": "antigravity",
                            "model_route_optional": null,
                            "requested_role": "worker",
                            "capability_requirements": ["review"]
                        }
                    ],
                    "recovery_policy_ref": "recovery-policy-m3",
                    "policy_snapshot_id": "policy-snapshot-m3",
                    "created_by": "codex-controller",
                    "state": "DRAFT",
                    "state_revision": 0,
                    "created_at": "2026-07-16T12:00:00Z"
                }
            }),
        )?;
        let plan = m3_runtime_action(
            &mut controller,
            101,
            &project_id,
            &task_id,
            run_id,
            0,
            0,
            "m3-plan",
            json!({
                "action": "create_work_plan",
                "tripwire_policy": {
                    "repeated_failure_threshold": 2,
                    "no_novelty_tool_call_threshold": 3
                },
                "work_items": [
                    m3_work_item(&first_work, &project_id, &[], "daemon-receipt-resolution"),
                    m3_work_item(&second_work, &project_id, &[], "daemon-receipt-resolution"),
                    m3_work_item(
                        &third_work,
                        &project_id,
                        &[first_work.as_str(), second_work.as_str()],
                        "daemon-receipt-resolution"
                    )
                ]
            }),
        )?;
        let mut state_revision = required_test_u64(&plan, "/state_revision")?;
        let mut runtime_revision = required_test_u64(&plan, "/runtime_revision")?;
        for (id, key, target) in [(102, "m3-ready", "READY"), (103, "m3-running", "RUNNING")] {
            let advanced = m3_runtime_action(
                &mut controller,
                id,
                &project_id,
                &task_id,
                run_id,
                state_revision,
                runtime_revision,
                key,
                json!({
                    "action": "advance",
                    "target": target,
                    "reason": format!("advance to {target}"),
                    "risk_tier": "R1",
                    "verifier_refs": []
                }),
            )?;
            state_revision = required_test_u64(&advanced, "/state_revision")?;
            runtime_revision = required_test_u64(&advanced, "/runtime_revision")?;
        }
        for (id, key, chain) in [
            (104, "m3-assign-opencode", &first_chain),
            (105, "m3-assign-antigravity", &second_chain),
        ] {
            let assigned = m3_runtime_action(
                &mut controller,
                id,
                &project_id,
                &task_id,
                run_id,
                state_revision,
                runtime_revision,
                key,
                json!({
                    "action": "assign_work",
                    "work_item_id": chain.work_item_id,
                    "host_id": chain.host,
                    "lease": chain.autonomy_lease
                }),
            )?;
            assert_m3_committed_action(&assigned, "assign_work")?;
            assert_eq!(
                assigned["action_result"]["host_result_chain"]["result_id"],
                chain.result_id
            );
            runtime_revision = required_test_u64(&assigned, "/runtime_revision")?;
        }
        let charged = m3_runtime_action(
            &mut controller,
            106,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-charge-real-usage",
            json!({
                "action": "charge_usage",
                "work_item_id": first_chain.work_item_id,
                "lease_ref": first_chain.autonomy_lease["lease_ref"],
                "usage_evidence_ref": "usage-report:m3-opencode-1",
                "intent": {
                    "project_id": project_id,
                    "paths": [first_chain.changed_file],
                    "effect": "source_edit",
                    "model_invocations": 1,
                    "tool_calls": 2,
                    "wall_time_seconds": 15,
                    "cost_or_token_units": 800,
                    "work_items_started": 0,
                    "active_agents": 2,
                    "novelty_observed": true,
                    "failure_signature": null
                }
            }),
        )?;
        runtime_revision = required_test_u64(&charged, "/runtime_revision")?;
        assert_eq!(charged["run"]["model_invocations_used"], 1);
        assert_eq!(charged["run"]["tool_calls_used"], 2);

        let tripped = m3_runtime_action(
            &mut controller,
            108,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-provider-tripwire",
            json!({
                "action": "record_tripwire",
                "work_item_id": first_chain.work_item_id,
                "kind": "provider_runtime_failure",
                "signature": "provider-timeout-m3",
                "reason": "provider response timed out after bounded lease activation",
                "evidence_ref": "runtime-report:m3-provider-timeout"
            }),
        )?;
        runtime_revision = required_test_u64(&tripped, "/runtime_revision")?;
        let tripwire_id = required_test_string(&tripped, "/action_result/tripwire/tripwire_id")?;
        let paused = m3_runtime_action(
            &mut controller,
            109,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-pause",
            json!({
                "action": "pause_for_recovery",
                "work_item_id": first_work,
                "tripwire_id": tripwire_id,
                "reason": "preserve branch state for bounded recovery"
            }),
        )?;
        state_revision = required_test_u64(&paused, "/state_revision")?;
        runtime_revision = required_test_u64(&paused, "/runtime_revision")?;
        let resumed = m3_runtime_action(
            &mut controller,
            110,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-resume",
            json!({
                "action": "resume_after_recovery",
                "work_item_id": first_work,
                "reason": "narrow fallback route is healthy"
            }),
        )?;
        state_revision = required_test_u64(&resumed, "/state_revision")?;
        runtime_revision = required_test_u64(&resumed, "/runtime_revision")?;

        for (id, key, chain) in [
            (111, "m3-complete-first", &first_chain),
            (112, "m3-complete-second", &second_chain),
        ] {
            let completed = m3_runtime_action(
                &mut controller,
                id,
                &project_id,
                &task_id,
                run_id,
                state_revision,
                runtime_revision,
                key,
                json!({
                    "action": "complete_work_item",
                    "work_item_id": chain.work_item_id,
                    "lease_ref": chain.autonomy_lease["lease_ref"],
                    "verifier_names": ["daemon-receipt-resolution"],
                    "verifier_refs": [verifier_ref]
                }),
            )?;
            assert_m3_committed_action(&completed, "complete_work_item")?;
            assert_eq!(
                completed["action_result"]["host_result_chain"]["result_id"],
                chain.result_id
            );
            runtime_revision = required_test_u64(&completed, "/runtime_revision")?;
        }
        let assigned_third = m3_runtime_action(
            &mut controller,
            113,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-assign-third",
            json!({
                "action": "assign_work",
                "work_item_id": third_chain.work_item_id,
                "host_id": third_chain.host,
                "lease": third_chain.autonomy_lease
            }),
        )?;
        assert_m3_committed_action(&assigned_third, "assign_work")?;
        assert_eq!(
            assigned_third["action_result"]["host_result_chain"]["result_id"],
            third_chain.result_id
        );
        runtime_revision = required_test_u64(&assigned_third, "/runtime_revision")?;
        let fabricated_reassign = m3_runtime_action(
            &mut controller,
            4_500,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-fabricated-reassign-denied",
            json!({
                "action": "reassign_work",
                "work_item_id": third_chain.work_item_id,
                "host_id": "opencode",
                "work_lease_ref": format!("work-lease:{}", uuid::Uuid::new_v4()),
                "reason": "fabricated narrow lease must not authorize reassignment"
            }),
        )?;
        assert_m3_denied_without_receipt(&fabricated_reassign);
        assert_eq!(
            required_test_u64(&fabricated_reassign, "/runtime_revision")?,
            runtime_revision
        );

        let reassigned = m3_runtime_action(
            &mut controller,
            4_550,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-real-lease-reassign",
            json!({
                "action": "reassign_work",
                "work_item_id": third_chain.work_item_id,
                "host_id": third_chain.host,
                "work_lease_ref": third_chain.autonomy_lease["lease_ref"],
                "reason": "rebind recovery through the exact active authenticated host lease"
            }),
        )?;
        assert_m3_committed_action(&reassigned, "reassign_work")?;
        assert_eq!(
            reassigned["action_result"]["canonical_lease"]["lease_ref"],
            third_chain.autonomy_lease["lease_ref"]
        );
        runtime_revision = required_test_u64(&reassigned, "/runtime_revision")?;
        let completed_third = m3_runtime_action(
            &mut controller,
            114,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-complete-third",
            json!({
                "action": "complete_work_item",
                "work_item_id": third_chain.work_item_id,
                "lease_ref": third_chain.autonomy_lease["lease_ref"],
                "verifier_names": ["daemon-receipt-resolution"],
                "verifier_refs": [verifier_ref]
            }),
        )?;
        assert_m3_committed_action(&completed_third, "complete_work_item")?;
        assert_eq!(
            completed_third["action_result"]["host_result_chain"]["result_id"],
            third_chain.result_id
        );
        runtime_revision = required_test_u64(&completed_third, "/runtime_revision")?;
        let verifying = m3_runtime_action(
            &mut controller,
            115,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-verifying",
            json!({
                "action": "advance",
                "target": "VERIFYING",
                "reason": "all required work items have canonical verifier receipts",
                "risk_tier": "R1",
                "verifier_refs": [verifier_ref]
            }),
        )?;
        state_revision = required_test_u64(&verifying, "/state_revision")?;
        runtime_revision = required_test_u64(&verifying, "/runtime_revision")?;
        (
            verification_id,
            verifier_scope_hash,
            state_revision,
            runtime_revision,
            vec![first_chain, second_chain, third_chain],
            Vec::<String>::new(),
        )
    };

    let completion_proof = json!({
            "task_id": task_id,
            "project_id": project_id,
            "goal": "finish M6 and bounded product backlog with durable runtime evidence",
            "changed_files": host_chains
                .iter()
                .map(|chain| chain.changed_file.clone())
                .collect::<Vec<_>>(),
            "memory_refs_used": [],
            "checks_run": [
                "daemon-receipt-resolution",
                "resolve canonical observation receipt"
            ],
            "checks_not_run": [],
            "acceptance_items": [{
                "item": "verified",
                "status": "verified",
                "evidence": format!("verification:{verification_id}"),
                "verifier": "daemon-receipt-resolution",
                "residual_uncertainty": ""
            }],
            "evidence": [format!("verification:{verification_id}"), verifier_scope_hash],
            "skill_refs": [],
            "skill_execution_proof_refs": [],
            "residual_uncertainty": "",
            "known_risks": []
    });
    let completion_reason = "all required work and acceptance are verifier complete";
    let completion_verifier_refs = vec![format!("verification:{verification_id}")];

    let completion_action = {
        let mut reconnected = McpClient::start_in_workspace(&workspace)?;
        let status = reconnected.tool_call(
            116,
            "eliot_autonomy_run_status",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "autonomy_run_id": run_id
            }),
        )?;
        assert_eq!(
            status["runs"][0]["work_item_refs"].as_array().map(Vec::len),
            Some(3)
        );
        assert_eq!(status["runs"][0]["model_invocations_used"], 1);
        assert_eq!(status["runs"][0]["tool_calls_used"], 2);
        assert_eq!(
            status["runtime_controls"][0]["state_revision"],
            state_revision
        );
        assert_eq!(
            status["runtime_controls"][0]["runtime_revision"],
            runtime_revision
        );
        assert!(status["runtime_controls"][0]["ledger"].is_object());
        assert_eq!(
            status["runtime_controls"][0]["integrity_status"],
            "authoritative_atomic_aggregate"
        );
        assert!(
            status["runtime_controls"][0]["canonical_record_refs"]
                .as_array()
                .is_some_and(|refs| refs.len() >= 3)
        );
        assert!(
            status["runs"][0]["recovery_event_refs"]
                .as_array()
                .is_some_and(|refs| refs.len() >= 2)
        );

        let rejected = m3_runtime_action(
            &mut reconnected,
            117,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-bogus-completion",
            json!({
                "action": "complete_run",
                "completion_proof": completion_proof.clone(),
                "reason": "bogus verifier must not complete",
                "approval_id": format!("autonomy-approval:{}", uuid::Uuid::new_v4()),
                "verifier_refs": [uuid::Uuid::new_v4().to_string()]
            }),
        );
        assert!(rejected.is_err());

        let mut stale_approval_id = String::new();
        for index in 0..129_u64 {
            let noise = m3_approval_request(
                &mut reconnected,
                4_000 + index,
                &project_id,
                &task_id,
                run_id,
                state_revision,
                runtime_revision,
                &format!("m3-approval-noise-{index}"),
                &completion_proof,
                completion_reason,
                &completion_verifier_refs,
            )?;
            assert_eq!(noise["accepted"], true);
            if index == 0 {
                stale_approval_id = required_test_string(&noise, "/approval/approval_id")?;
            }
        }
        let approval_noise_tripwire = m3_runtime_action(
            &mut reconnected,
            4_200,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-approval-noise-revision",
            json!({
                "action": "record_tripwire",
                "work_item_id": host_chains[0].work_item_id,
                "kind": "policy_violation",
                "signature": "approval-noise-revision",
                "reason": "advance the canonical runtime revision after stale approval noise",
                "evidence_ref": "runtime-report:m3-approval-noise"
            }),
        )?;
        runtime_revision = required_test_u64(&approval_noise_tripwire, "/runtime_revision")?;
        let stale = m3_runtime_action(
            &mut reconnected,
            4_201,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-stale-approval-denied",
            json!({
                "action": "complete_run",
                "completion_proof": completion_proof.clone(),
                "reason": completion_reason,
                "approval_id": stale_approval_id,
                "verifier_refs": completion_verifier_refs.clone()
            }),
        )?;
        assert_m3_denied_without_receipt(&stale);

        let denied_request = m3_approval_request(
            &mut reconnected,
            4_202,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-denied-approval",
            &completion_proof,
            completion_reason,
            &completion_verifier_refs,
        )?;
        let denied_approval_id = required_test_string(&denied_request, "/approval/approval_id")?;
        let denied_exact_action_hash =
            required_test_string(&denied_request, "/approval/exact_action_hash")?;
        let mut operator =
            McpClient::connect_to_running_with_profile_in_workspace("human_operator", &workspace)?;
        let denied_decision = m3_operator_approval_decision(
            &mut operator,
            10,
            &project_id,
            &task_id,
            &denied_approval_id,
            &denied_exact_action_hash,
            "denied",
            "completion evidence requires operator rejection proof",
            "m3-human-denial",
        )?;
        assert_eq!(
            denied_decision["accepted"], true,
            "unexpected approval denial: {denied_decision:#}"
        );
        assert_eq!(denied_decision["executed"], true);
        assert_eq!(denied_decision["outcome"], "autonomy_approval_denied");
        assert!(denied_decision["canonical_receipt"].is_object());
        let denied_completion = m3_runtime_action(
            &mut reconnected,
            4_203,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-denied-approval-consume",
            json!({
                "action": "complete_run",
                "completion_proof": completion_proof.clone(),
                "reason": completion_reason,
                "approval_id": denied_approval_id,
                "verifier_refs": completion_verifier_refs.clone()
            }),
        )?;
        assert_m3_denied_without_receipt(&denied_completion);

        let approval_request = m3_approval_request(
            &mut reconnected,
            4_204,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-exact-approval-after-128-noise",
            &completion_proof,
            completion_reason,
            &completion_verifier_refs,
        )?;
        let approval_id = required_test_string(&approval_request, "/approval/approval_id")?;
        let exact_action_hash =
            required_test_string(&approval_request, "/approval/exact_action_hash")?;
        let stale_decision = m3_approval_decision(
            &mut operator,
            2,
            &project_id,
            &task_id,
            run_id,
            &approval_id,
            99,
            "granted",
            "grant exact completion",
            "m3-stale-decision-cas",
        )?;
        assert_m3_denied_without_receipt(&stale_decision);
        let granted = m3_operator_approval_decision(
            &mut operator,
            20,
            &project_id,
            &task_id,
            &approval_id,
            &exact_action_hash,
            "granted",
            "grant exact completion",
            "m3-human-grant",
        )?;
        assert_eq!(granted["accepted"], true);
        assert_eq!(granted["executed"], true);
        assert_eq!(granted["outcome"], "autonomy_approval_granted");
        assert!(granted["canonical_receipt"].is_object());
        let grant_replay = m3_operator_approval_decision(
            &mut operator,
            22,
            &project_id,
            &task_id,
            &approval_id,
            &exact_action_hash,
            "granted",
            "grant exact completion",
            "m3-human-grant-replay-key-ignored",
        )?;
        assert_eq!(grant_replay["preview"]["idempotent_replay"], true);
        assert_eq!(
            grant_replay["canonical_receipt"],
            granted["canonical_receipt"]
        );
        drop(operator);

        let completion_action = json!({
            "action": "complete_run",
            "completion_proof": completion_proof.clone(),
            "reason": completion_reason,
            "approval_id": approval_id.clone(),
            "verifier_refs": completion_verifier_refs.clone()
        });
        let wrong_action = m3_runtime_action(
            &mut reconnected,
            4_205,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-wrong-approved-action",
            json!({
                "action": "complete_run",
                "completion_proof": completion_proof.clone(),
                "reason": "different completion action",
                "approval_id": approval_id.clone(),
                "verifier_refs": completion_verifier_refs.clone()
            }),
        )?;
        assert_m3_denied_without_receipt(&wrong_action);
        let mut different_principal = McpClient::connect_to_running_with_profile_in_workspace(
            "codex_controller",
            &workspace,
        )?;
        let principal_denied = m3_runtime_action(
            &mut different_principal,
            1,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-principal-mismatch",
            completion_action.clone(),
        )?;
        assert_m3_denied_without_receipt(&principal_denied);
        drop(different_principal);

        let (fabricated_invocation, original_result_ref) =
            replace_m3_local_job_result_ref(&host_chains[0], "result:fabricated-canonical-less")?;
        let fabricated_result = m3_runtime_action(
            &mut reconnected,
            4_206,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-canonical-less-result-denied",
            completion_action.clone(),
        )?;
        assert_m3_denied_without_receipt(&fabricated_result);
        restore_m3_local_job_result_ref(&fabricated_invocation, &original_result_ref)?;
        delete_m3_local_authority_projections(&host_chains[0])?;

        let completed = m3_runtime_action(
            &mut reconnected,
            118,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-complete-run",
            completion_action.clone(),
        )?;
        assert_m3_committed_action(&completed, "complete_run")?;
        assert_eq!(completed["run"]["finish_status"], "doneverified");
        assert!(completed["run"]["completion_proof"].is_object());
        let replay = m3_runtime_action(
            &mut reconnected,
            119,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-complete-run",
            completion_action.clone(),
        )?;
        assert_eq!(replay["idempotent_replay"], true);
        assert!(
            m3_runtime_action(
                &mut reconnected,
                120,
                &project_id,
                &task_id,
                run_id,
                state_revision,
                runtime_revision,
                "m3-complete-run",
                json!({
                    "action": "advance",
                    "target": "CANCELLED",
                    "reason": "conflicting retry",
                    "risk_tier": "R1",
                    "verifier_refs": []
                }),
            )
            .is_err()
        );
        drop(reconnected);
        let mut durable = McpClient::start_in_workspace(&workspace)?;
        let terminal_status = durable.tool_call(
            123,
            "eliot_autonomy_run_status",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "autonomy_run_id": run_id
            }),
        )?;
        assert_eq!(terminal_status["runs"][0]["finish_status"], "doneverified");
        assert_eq!(
            terminal_status["runtime_controls"][0]["integrity_status"],
            "authoritative_atomic_aggregate"
        );
        assert!(terminal_status["runs"][0]["completion_proof"].is_object());
        let mut restarted_operator =
            McpClient::connect_to_running_with_profile_in_workspace("human_operator", &workspace)?;
        let grant_after_restart = m3_operator_approval_decision(
            &mut restarted_operator,
            30,
            &project_id,
            &task_id,
            &approval_id,
            &exact_action_hash,
            "granted",
            "grant exact completion",
            "m3-human-grant-after-restart",
        )?;
        assert_eq!(grant_after_restart["preview"]["idempotent_replay"], true);
        assert_eq!(
            grant_after_restart["preview"]["decision"]["approval_id"],
            approval_id
        );
        drop(restarted_operator);
        let terminal_state_revision =
            required_test_u64(&terminal_status, "/runtime_controls/0/state_revision")?;
        let terminal_runtime_revision =
            required_test_u64(&terminal_status, "/runtime_controls/0/runtime_revision")?;
        let reused_after_restart = m3_runtime_action(
            &mut durable,
            4_300,
            &project_id,
            &task_id,
            run_id,
            terminal_state_revision,
            terminal_runtime_revision,
            "m3-consumed-approval-after-restart",
            completion_action.clone(),
        )?;
        assert_m3_denied_without_receipt(&reused_after_restart);
        for (offset, chain) in host_chains.iter().enumerate() {
            let cleanup = durable.tool_call(
                124 + u64::try_from(offset)?,
                "eliot_worktree_cleanup",
                &json!({"worktree_lease": chain.worktree_lease_id}),
            )?;
            assert_eq!(cleanup["operation_status"], "OPERATION_COMPLETED");
            assert!(cleanup.get("final_status").is_none());
        }
        for (offset, lease_id) in retired_worktree_leases.iter().enumerate() {
            let cleanup = durable.tool_call(
                4_400 + u64::try_from(offset)?,
                "eliot_worktree_cleanup",
                &json!({"worktree_lease": lease_id}),
            )?;
            assert_eq!(cleanup["operation_status"], "OPERATION_COMPLETED");
            assert!(cleanup.get("final_status").is_none());
        }
        completion_action
    };

    let mut readonly = McpClient::start_with_profile("human_readonly")?;
    assert!(
        m3_runtime_action(
            &mut readonly,
            121,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-readonly-denied",
            completion_action.clone(),
        )
        .is_err()
    );
    drop(readonly);
    let mut worker = McpClient::start_with_profile("codex_worker")?;
    assert!(
        m3_runtime_action(
            &mut worker,
            122,
            &project_id,
            &task_id,
            run_id,
            state_revision,
            runtime_revision,
            "m3-worker-denied",
            completion_action,
        )
        .is_err()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn m3_runtime_action(
    client: &mut McpClient,
    id: u64,
    project_id: &str,
    task_id: &str,
    run_id: &str,
    state_revision: u64,
    runtime_revision: u64,
    idempotency_key: &str,
    action: Value,
) -> TestResult<Value> {
    client.tool_call(
        id,
        "eliot_autonomy_runtime_action",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "autonomy_run_id": run_id,
            "expected_state_revision": state_revision,
            "expected_runtime_revision": runtime_revision,
            "idempotency_key": idempotency_key,
            "action": action
        }),
    )
}

fn assert_m3_denied_without_receipt(response: &Value) {
    assert_eq!(response["accepted"], false);
    assert_eq!(response["canonical_receipt"], Value::Null);
    assert_eq!(
        response["canonical_receipts"].as_array().map(Vec::len),
        Some(0)
    );
}

#[allow(clippy::too_many_arguments)]
fn m3_approval_request(
    client: &mut McpClient,
    id: u64,
    project_id: &str,
    task_id: &str,
    run_id: &str,
    state_revision: u64,
    runtime_revision: u64,
    idempotency_key: &str,
    completion_proof: &Value,
    reason: &str,
    verifier_refs: &[String],
) -> TestResult<Value> {
    client.tool_call(
        id,
        "eliot_autonomy_approval_request",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "autonomy_run_id": run_id,
            "expected_state_revision": state_revision,
            "expected_runtime_revision": runtime_revision,
            "idempotency_key": idempotency_key,
            "completion_proof": completion_proof,
            "reason": reason,
            "verifier_refs": verifier_refs,
            "ttl_minutes": 60
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn m3_approval_decision(
    client: &mut McpClient,
    id: u64,
    project_id: &str,
    task_id: &str,
    run_id: &str,
    approval_id: &str,
    expected_approval_revision: u64,
    decision: &str,
    reason: &str,
    idempotency_key: &str,
) -> TestResult<Value> {
    client.tool_call(
        id,
        "eliot_autonomy_approval_decide",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "autonomy_run_id": run_id,
            "approval_id": approval_id,
            "expected_approval_revision": expected_approval_revision,
            "decision": decision,
            "reason": reason,
            "idempotency_key": idempotency_key
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn m3_operator_approval_decision(
    client: &mut McpClient,
    id: u64,
    project_id: &str,
    task_id: &str,
    approval_id: &str,
    exact_action_hash: &str,
    decision: &str,
    reason: &str,
    idempotency_key: &str,
) -> TestResult<Value> {
    let snapshot = client.tool_call(
        id,
        "eliot_operator_snapshot",
        &json!({"project_id": project_id, "task_id": task_id}),
    )?;
    let revision = required_test_u64(&snapshot, "/task_cognition/0/task_contract/memory_revision")?;
    let command = if decision == "granted" {
        json!({
            "command": "grant_approval",
            "approval_id": approval_id,
            "exact_action_hash": exact_action_hash
        })
    } else {
        json!({
            "command": "deny_approval",
            "approval_id": approval_id,
            "exact_action_hash": exact_action_hash,
            "reason": reason
        })
    };
    client.tool_call(
        id.saturating_add(1),
        "eliot_operator_command",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "expected_revision": revision,
            "idempotency_key": idempotency_key,
            "command": command
        }),
    )
}

fn m3_work_item(
    work_item_id: &str,
    project_id: &str,
    dependencies: &[&str],
    verifier: &str,
) -> Value {
    json!({
        "work_item_id": work_item_id,
        "project_id": project_id,
        "dependencies": dependencies,
        "status": "open",
        "required": true,
        "required_verifiers": [verifier],
        "verifier_refs": [],
        "assigned_agent": null,
        "lease": null
    })
}

#[derive(Clone, Debug)]
struct M3HostAuthorityFixture {
    host: String,
    work_item_id: String,
    worktree_lease_id: String,
    result_id: String,
    changed_file: String,
    autonomy_lease: Value,
}

#[derive(Clone, Debug)]
struct M3PreparedHostAuthorityFixture {
    host: String,
    work_item_id: String,
    worktree_lease_id: String,
    changed_file: String,
    autonomy_lease: Value,
    worker_session_id: String,
    role_lease_id: String,
    invocation_id: String,
    diff_ref: String,
    commit_ref: String,
}

#[derive(Clone, Debug)]
struct M3ClaimedWorkFixture {
    host: String,
    changed_file: String,
    work_item_id: String,
    work_lease_id: String,
    worker_session_id: String,
    work_lease: Value,
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn managed_finalization_restarts_every_stage_and_converges_without_provider_dispatch() -> TestResult
{
    let _guard = TestLock::acquire()?;
    let stages = [
        "intent",
        "apply",
        "commit",
        "candidate_secondaries",
        "result_secondaries",
        "aggregate",
        "authority_secondaries",
        "local_save",
    ];
    for stage in stages {
        let fixture = prepare_managed_finalization_fixture(stage).map_err(|error| {
            std::io::Error::other(format!("prepare managed stage {stage}: {error}"))
        })?;
        let request = json!({
            "invocation_id": fixture.invocation_id,
            "expected_provider_output_hash": fixture.provider_output_hash,
            "idempotency_key": format!("finalize-{stage}"),
            "verifier_refs": [fixture.verifier_ref],
        });
        let mut failed = McpClient::start_scoped_with_failure_in_workspace(
            &fixture.workspace,
            "codex",
            &fixture.controller_session_id,
            &fixture.controller_role_lease_id,
            &fixture.task_id,
            stage,
        )?;
        let Err(error) = failed.tool_call(800, "eliot_agent_result_finalize", &request) else {
            return Err(std::io::Error::other(format!(
                "managed finalization stage {stage} did not inject its required failure"
            ))
            .into());
        };
        assert!(
            error.to_string().contains(stage),
            "stage {stage} returned an unrelated failure: {error}"
        );
        drop(failed);

        let mut restarted = McpClient::start_scoped_in_workspace(
            &fixture.workspace,
            "codex",
            &fixture.controller_session_id,
            &fixture.controller_role_lease_id,
            &fixture.task_id,
        )?;
        let recovered = restarted.tool_call(801, "eliot_agent_result_finalize", &request)?;
        let recovered_diff_id =
            required_test_string(&recovered, "/candidate_diff/candidate_diff_id")?;
        let recovered_review_id = required_test_string(&recovered, "/candidate_review/review_id")?;
        let recovered_disposition_id =
            required_test_string(&recovered, "/disposition/disposition_id")?;
        let work_path = test_runtime_root().join("reports/work/state.json");
        let mut lost_work: eliot_engine::WorkState =
            serde_json::from_reader(fs::File::open(&work_path)?)?;
        lost_work
            .candidate_diffs
            .retain(|diff| diff.candidate_diff_id.to_string() != recovered_diff_id);
        lost_work
            .candidate_reviews
            .retain(|review| review.review_id != recovered_review_id);
        lost_work
            .worktree_leases
            .retain(|lease| lease.worktree_lease_id.to_string() != fixture.worktree_lease_id);
        lost_work
            .leases
            .retain(|lease| lease.work_lease_id.to_string() != fixture.work_lease_id);
        fs::write(&work_path, serde_json::to_vec_pretty(&lost_work)?)?;
        let broker_path = test_runtime_root().join("reports/delegation-state/latest.json");
        let mut lost_broker: eliot_types::DelegationState =
            serde_json::from_reader(fs::File::open(&broker_path)?)?;
        lost_broker
            .agent_results
            .retain(|result| result.invocation_id != fixture.invocation_id);
        lost_broker
            .agent_result_dispositions
            .retain(|item| item.disposition_id != recovered_disposition_id);
        lost_broker
            .operation_jobs
            .retain(|job| job.job_id != fixture.job_id);
        fs::write(&broker_path, serde_json::to_vec_pretty(&lost_broker)?)?;
        let replay = restarted.tool_call(802, "eliot_agent_result_finalize", &request)?;
        for pointer in [
            "/finalization_id",
            "/candidate_diff/candidate_diff_id",
            "/candidate_review/review_id",
            "/result/result_id",
            "/disposition/disposition_id",
            "/commit_ref",
            "/canonical_aggregate_receipt/receipt_id",
            "/canonical_aggregate_receipt/write_id",
        ] {
            assert_eq!(
                recovered.pointer(pointer),
                replay.pointer(pointer),
                "stage {stage} changed deterministic field {pointer} on replay"
            );
        }
        assert_eq!(recovered["completion_authority_granted"], false);
        let commit_ref = required_test_string(&recovered, "/commit_ref")?;
        assert_eq!(
            m3_git(&fixture.worktree, &["rev-parse", "HEAD"])?,
            commit_ref
        );
        assert_eq!(
            m3_git(
                &fixture.worktree,
                &[
                    "rev-list",
                    "--count",
                    &format!("{}..HEAD", fixture.baseline_commit)
                ],
            )?,
            "1",
            "stage {stage} created more than one finalization commit"
        );
        assert!(m3_git(&fixture.worktree, &["status", "--porcelain=v1"])?.is_empty());

        let aggregate_write =
            required_test_string(&recovered, "/canonical_aggregate_receipt/write_id")?
                .parse::<WriteId>()?;
        let observation_count = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                Ok::<usize, Box<dyn std::error::Error + Send + Sync>>(
                    managed_test_store()?
                        .tool_observations_by_write_id(&aggregate_write)
                        .await?
                        .len(),
                )
            })?;
        assert_eq!(
            observation_count, 1,
            "stage {stage} materialized more than one terminal aggregate"
        );
        let work: eliot_engine::WorkState = serde_json::from_reader(fs::File::open(
            test_runtime_root().join("reports/work/state.json"),
        )?)?;
        assert!(work.candidate_diffs.iter().any(|diff| {
            diff.candidate_diff_id.to_string() == recovered["candidate_diff"]["candidate_diff_id"]
        }));
        assert!(
            work.candidate_reviews
                .iter()
                .any(|review| { review.review_id == recovered["candidate_review"]["review_id"] })
        );
        assert!(work.worktree_leases.iter().any(|lease| {
            lease.worktree_lease_id.to_string() == fixture.worktree_lease_id
                && serde_json::to_value(lease.state).ok().as_ref() == Some(&json!("accepted"))
        }));
        let broker: eliot_types::DelegationState = serde_json::from_reader(fs::File::open(
            test_runtime_root().join("reports/delegation-state/latest.json"),
        )?)?;
        assert!(
            broker
                .agent_results
                .iter()
                .any(|result| { result.result_id == recovered["result"]["result_id"] })
        );
        assert!(broker.agent_result_dispositions.iter().any(|disposition| {
            disposition.disposition_id == recovered["disposition"]["disposition_id"]
        }));
        assert!(broker.operation_jobs.iter().any(|job| {
            job.job_id == fixture.job_id
                && job.result_ref.as_deref() == recovered["result"]["result_id"].as_str()
        }));
        assert!(
            !broker
                .agent_results
                .iter()
                .any(|result| result.result_id == fixture.provider_result_id)
        );
        let result: Value = serde_json::from_reader(fs::File::open(
            test_runtime_root()
                .join("reports/host-invocations")
                .join(fixture.invocation_id.replace(':', "_"))
                .join("result.json"),
        )?)?;
        assert_eq!(result["execution_evidence"]["provider_dispatched"], false);
        drop(restarted);
    }

    let fixture = prepare_managed_finalization_fixture("concurrent")
        .map_err(|error| std::io::Error::other(format!("prepare managed race: {error}")))?;
    let request = json!({
        "invocation_id": fixture.invocation_id,
        "expected_provider_output_hash": fixture.provider_output_hash,
        "idempotency_key": "finalize-concurrent",
        "verifier_refs": [fixture.verifier_ref],
    });
    // Each stdio facade is an independent OS process. Both forward the same
    // authenticated invocation concurrently to the durable daemon boundary.
    let first = McpClient::start_scoped_in_workspace(
        &fixture.workspace,
        "codex",
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
    )?;
    let second = McpClient::connect_scoped_controller(
        &fixture.workspace,
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
    )?;
    let barrier = Arc::new(Barrier::new(2));
    let run = |mut client: McpClient, barrier: Arc<Barrier>, id: u64, request: Value| {
        thread::spawn(move || {
            barrier.wait();
            let result = client.tool_call(id, "eliot_agent_result_finalize", &request);
            (client, result)
        })
    };
    let left = run(first, Arc::clone(&barrier), 900, request.clone());
    let right = run(second, barrier, 901, request);
    let (left_client, left) = left
        .join()
        .map_err(|_| std::io::Error::other("first concurrent finalizer panicked"))?;
    let (right_client, right) = right
        .join()
        .map_err(|_| std::io::Error::other("second concurrent finalizer panicked"))?;
    let left = left?;
    let right = right?;
    assert_eq!(left["finalization_id"], right["finalization_id"]);
    assert_eq!(left["commit_ref"], right["commit_ref"]);
    assert_eq!(
        left["canonical_aggregate_receipt"],
        right["canonical_aggregate_receipt"]
    );
    assert_eq!(
        m3_git(
            &fixture.worktree,
            &[
                "rev-list",
                "--count",
                &format!("{}..HEAD", fixture.baseline_commit)
            ],
        )?,
        "1"
    );
    let aggregate_write =
        required_test_string(&left, "/canonical_aggregate_receipt/write_id")?.parse::<WriteId>()?;
    let count = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            Ok::<usize, Box<dyn std::error::Error + Send + Sync>>(
                managed_test_store()?
                    .tool_observations_by_write_id(&aggregate_write)
                    .await?
                    .len(),
            )
        })?;
    assert_eq!(count, 1);
    drop(right_client);
    drop(left_client);
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn managed_finalization_rejects_local_only_invocation_authority() -> TestResult {
    let _guard = TestLock::acquire()?;
    let fixture = prepare_managed_finalization_fixture_with_invocation_authority(
        "local-only-request",
        false,
    )?;
    let mut controller = McpClient::start_scoped_in_workspace(
        &fixture.workspace,
        "codex",
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
    )?;
    let error = match controller.tool_call(
        950,
        "eliot_agent_result_finalize",
        &json!({
            "invocation_id": fixture.invocation_id,
            "expected_provider_output_hash": fixture.provider_output_hash,
            "idempotency_key": "reject-local-only-invocation",
            "verifier_refs": [fixture.verifier_ref],
        }),
    ) {
        Ok(value) => {
            return Err(std::io::Error::other(format!(
                "local-only AgentInvocationRequest authorized finalization: {value}"
            ))
            .into());
        }
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("agent_invocation_request has no current canonical authority"),
        "unexpected finalization denial: {error}"
    );
    assert_eq!(
        managed_finalization_record_count(
            &fixture,
            &[
                "managed_finalization_intent",
                "managed_finalization_aggregate"
            ]
        )?,
        0
    );
    assert_eq!(
        m3_git(&fixture.worktree, &["rev-parse", "HEAD"])?,
        fixture.baseline_commit
    );
    assert!(m3_git(&fixture.worktree, &["status", "--porcelain=v1"])?.is_empty());
    drop(controller);
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn managed_finalization_rejects_local_invocation_mismatch_with_canonical() -> TestResult {
    let _guard = TestLock::acquire()?;
    let fixture = prepare_managed_finalization_fixture("canonical-request-mismatch")?;
    let broker_path = test_runtime_root().join("reports/delegation-state/latest.json");
    let mut broker: eliot_types::DelegationState =
        serde_json::from_reader(fs::File::open(&broker_path)?)?;
    let invocation = broker
        .agent_invocations
        .iter_mut()
        .find(|request| request.invocation_id == fixture.invocation_id)
        .ok_or_else(|| std::io::Error::other("fixture invocation request is absent"))?;
    invocation.expected_result_kind = "fabricated-local-result-kind".to_owned();
    fs::write(&broker_path, serde_json::to_vec_pretty(&broker)?)?;
    let mut controller = McpClient::start_scoped_in_workspace(
        &fixture.workspace,
        "codex",
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
    )?;
    let error = match controller.tool_call(
        951,
        "eliot_agent_result_finalize",
        &json!({
            "invocation_id": fixture.invocation_id,
            "expected_provider_output_hash": fixture.provider_output_hash,
            "idempotency_key": "reject-mismatched-local-invocation",
            "verifier_refs": [fixture.verifier_ref],
        }),
    ) {
        Ok(value) => {
            return Err(std::io::Error::other(format!(
                "mismatched local AgentInvocationRequest authorized finalization: {value}"
            ))
            .into());
        }
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("local agent_invocation_request projection differs"),
        "unexpected canonical mismatch denial: {error}"
    );
    assert_eq!(
        managed_finalization_record_count(
            &fixture,
            &[
                "managed_finalization_intent",
                "managed_finalization_aggregate"
            ]
        )?,
        0
    );
    assert_eq!(
        m3_git(&fixture.worktree, &["rev-parse", "HEAD"])?,
        fixture.baseline_commit
    );
    drop(controller);
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn managed_aggregate_replay_rejects_reset_extra_commit_and_worktree_drift() -> TestResult {
    let _guard = TestLock::acquire()?;
    for mode in ["reset", "extra-commit", "worktree-drift"] {
        let fixture = prepare_managed_finalization_fixture(&format!("aggregate-{mode}"))?;
        let request = json!({
            "invocation_id": fixture.invocation_id,
            "expected_provider_output_hash": fixture.provider_output_hash,
            "idempotency_key": format!("finalize-aggregate-{mode}"),
            "verifier_refs": [fixture.verifier_ref],
        });
        let mut controller = McpClient::start_scoped_in_workspace(
            &fixture.workspace,
            "codex",
            &fixture.controller_session_id,
            &fixture.controller_role_lease_id,
            &fixture.task_id,
        )?;
        let finalized = controller.tool_call(960, "eliot_agent_result_finalize", &request)?;
        let before = managed_finalization_record_count(
            &fixture,
            &[
                "managed_finalization_intent",
                "candidate_diff",
                "candidate_review",
                "agent_result",
                "agent_result_disposition",
                "managed_finalization_aggregate",
            ],
        )?;
        remove_managed_finalization_local_projections(&fixture, &finalized)?;
        match mode {
            "reset" => {
                m3_git(
                    &fixture.worktree,
                    &["reset", "--hard", &fixture.baseline_commit],
                )?;
            }
            "extra-commit" => {
                fs::write(
                    fixture.worktree.join("unexpected-extra.txt"),
                    "unexpected\n",
                )?;
                m3_git(&fixture.worktree, &["add", "unexpected-extra.txt"])?;
                m3_git(
                    &fixture.worktree,
                    &[
                        "-c",
                        "user.name=Eliot Test",
                        "-c",
                        "user.email=eliot-test@example.invalid",
                        "commit",
                        "-m",
                        "unexpected post-aggregate commit",
                    ],
                )?;
            }
            "worktree-drift" => {
                fs::write(
                    fixture.worktree.join("unexpected-drift.txt"),
                    "unexpected\n",
                )?;
            }
            _ => unreachable!(),
        }
        let error = match controller.tool_call(961, "eliot_agent_result_finalize", &request) {
            Ok(value) => {
                return Err(std::io::Error::other(format!(
                    "mode {mode} re-admitted projections after Git drift: {value}"
                ))
                .into());
            }
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("managed finalization"),
            "mode {mode} returned unrelated denial: {error}"
        );
        assert_eq!(
            managed_finalization_record_count(
                &fixture,
                &[
                    "managed_finalization_intent",
                    "candidate_diff",
                    "candidate_review",
                    "agent_result",
                    "agent_result_disposition",
                    "managed_finalization_aggregate",
                ],
            )?,
            before,
            "mode {mode} wrote canonical records before denying replay"
        );
        assert_managed_finalization_local_projections_absent(&fixture, &finalized)?;
        drop(controller);
    }
    Ok(())
}

fn managed_finalization_record_count(
    fixture: &ManagedFinalizationFixture,
    kinds: &[&str],
) -> TestResult<usize> {
    let project_id = fixture.project_id.parse::<ProjectId>()?;
    let task_id = fixture.task_id.parse::<TaskId>()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            Ok::<usize, Box<dyn std::error::Error + Send + Sync>>(
                managed_test_store()?
                    .canonical_records_by_kind::<Value>(project_id, Some(task_id), kinds, 128)
                    .await?
                    .len(),
            )
        })
}

fn remove_managed_finalization_local_projections(
    fixture: &ManagedFinalizationFixture,
    finalized: &Value,
) -> TestResult {
    let diff_id = required_test_string(finalized, "/candidate_diff/candidate_diff_id")?;
    let review_id = required_test_string(finalized, "/candidate_review/review_id")?;
    let result_id = required_test_string(finalized, "/result/result_id")?;
    let disposition_id = required_test_string(finalized, "/disposition/disposition_id")?;
    let work_path = test_runtime_root().join("reports/work/state.json");
    let mut work: eliot_engine::WorkState = serde_json::from_reader(fs::File::open(&work_path)?)?;
    work.candidate_diffs
        .retain(|diff| diff.candidate_diff_id.to_string() != diff_id);
    work.candidate_reviews
        .retain(|review| review.review_id != review_id);
    work.worktree_leases
        .retain(|lease| lease.worktree_lease_id.to_string() != fixture.worktree_lease_id);
    work.leases
        .retain(|lease| lease.work_lease_id.to_string() != fixture.work_lease_id);
    fs::write(&work_path, serde_json::to_vec_pretty(&work)?)?;
    let broker_path = test_runtime_root().join("reports/delegation-state/latest.json");
    let mut broker: eliot_types::DelegationState =
        serde_json::from_reader(fs::File::open(&broker_path)?)?;
    broker
        .agent_results
        .retain(|result| result.result_id != result_id);
    broker
        .agent_result_dispositions
        .retain(|item| item.disposition_id != disposition_id);
    broker
        .operation_jobs
        .retain(|job| job.job_id != fixture.job_id);
    fs::write(broker_path, serde_json::to_vec_pretty(&broker)?)?;
    Ok(())
}

fn assert_managed_finalization_local_projections_absent(
    fixture: &ManagedFinalizationFixture,
    finalized: &Value,
) -> TestResult {
    let diff_id = required_test_string(finalized, "/candidate_diff/candidate_diff_id")?;
    let result_id = required_test_string(finalized, "/result/result_id")?;
    let work: eliot_engine::WorkState = serde_json::from_reader(fs::File::open(
        test_runtime_root().join("reports/work/state.json"),
    )?)?;
    assert!(
        !work
            .candidate_diffs
            .iter()
            .any(|diff| diff.candidate_diff_id.to_string() == diff_id)
    );
    assert!(
        !work
            .worktree_leases
            .iter()
            .any(|lease| lease.worktree_lease_id.to_string() == fixture.worktree_lease_id)
    );
    let broker: eliot_types::DelegationState = serde_json::from_reader(fs::File::open(
        test_runtime_root().join("reports/delegation-state/latest.json"),
    )?)?;
    assert!(
        !broker
            .agent_results
            .iter()
            .any(|result| result.result_id == result_id)
    );
    assert!(
        !broker
            .operation_jobs
            .iter()
            .any(|job| job.job_id == fixture.job_id)
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct ManagedFinalizationFixture {
    workspace: PathBuf,
    worktree: PathBuf,
    project_id: String,
    task_id: String,
    controller_session_id: String,
    controller_role_lease_id: String,
    invocation_id: String,
    provider_output_hash: String,
    verifier_ref: String,
    baseline_commit: String,
    provider_result_id: String,
    job_id: String,
    work_lease_id: String,
    worktree_lease_id: String,
}

fn managed_test_hash_bytes(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn managed_test_hash_json(value: &Value) -> TestResult<String> {
    Ok(managed_test_hash_bytes(&serde_json::to_vec(value)?))
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn managed_finalization_rejects_missing_fabricated_and_mismatched_actual_verifier_refs()
-> TestResult {
    let _guard = TestLock::acquire()?;
    for (label, verifier_refs) in [
        ("missing", json!([])),
        (
            "fabricated",
            json!([format!("verification:{}", uuid::Uuid::new_v4())]),
        ),
        (
            "planned-registry-ref",
            json!(["eliot/verifier/daemon-receipt-resolution@v1#blake3:fabricated"]),
        ),
    ] {
        let fixture = prepare_managed_finalization_fixture(&format!("actual-verifier-{label}"))?;
        let mut controller = McpClient::start_scoped_in_workspace(
            &fixture.workspace,
            "codex",
            &fixture.controller_session_id,
            &fixture.controller_role_lease_id,
            &fixture.task_id,
        )?;
        let error = match controller.tool_call(
            952,
            "eliot_agent_result_finalize",
            &json!({
                "invocation_id": fixture.invocation_id,
                "expected_provider_output_hash": fixture.provider_output_hash,
                "idempotency_key": format!("reject-actual-verifier-{label}"),
                "verifier_refs": verifier_refs,
            }),
        ) {
            Ok(value) => {
                return Err(std::io::Error::other(format!(
                    "{label} verifier refs authorized finalization: {value}"
                ))
                .into());
            }
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("verifier") || error.to_string().contains("verification"),
            "unexpected {label} verifier denial: {error}"
        );
        assert_eq!(
            managed_finalization_record_count(
                &fixture,
                &[
                    "managed_finalization_intent",
                    "managed_finalization_aggregate"
                ]
            )?,
            0
        );
        assert_eq!(
            m3_git(&fixture.worktree, &["rev-parse", "HEAD"])?,
            fixture.baseline_commit
        );
        drop(controller);
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn task_completion_and_managed_finalization_race_has_one_serialized_authority_order() -> TestResult
{
    let _guard = TestLock::acquire()?;
    let fixture = prepare_managed_finalization_fixture("task_completion-finalization-race")?;
    let mut inspector = McpClient::start_scoped_in_workspace(
        &fixture.workspace,
        "codex",
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
    )?;
    let task_state = inspector.tool_call(
        953,
        "eliot_task_state",
        &json!({"project_id": fixture.project_id, "task_id": fixture.task_id}),
    )?;
    let task = &task_state["task_contract"];
    let acceptance_item_ids = task["acceptance_items"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("race acceptance items missing"))?
        .iter()
        .map(|item| required_test_string(item, "/item_id"))
        .collect::<Result<Vec<_>, _>>()?;
    let completion_proof = completion_proof_for_task_contract(task)?;
    let completion_request = json!({
        "project_id": fixture.project_id,
        "task_id": fixture.task_id,
        "write_id": uuid::Uuid::new_v4().to_string(),
        "expected_revision": required_test_u64(task, "/memory_revision")?,
        "completion_proof": completion_proof,
        "acceptance_item_ids": acceptance_item_ids,
        "observation_ids": task["observation_ids"],
        "verification_ids": task["verification_ids"],
    });
    let finalization_request = json!({
        "invocation_id": fixture.invocation_id,
        "expected_provider_output_hash": fixture.provider_output_hash,
        "idempotency_key": "task_completion-finalization-race",
        "verifier_refs": [fixture.verifier_ref],
    });
    drop(inspector);

    let completion_client = McpClient::start_scoped_in_workspace(
        &fixture.workspace,
        "codex",
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
    )?;
    let finalization_client = McpClient::connect_scoped_controller(
        &fixture.workspace,
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
    )?;
    let barrier = Arc::new(Barrier::new(2));
    let completion_barrier = Arc::clone(&barrier);
    let completion = thread::spawn(move || {
        let mut client = completion_client;
        completion_barrier.wait();
        client.tool_call(954, "eliot_submit_completion_proof", &completion_request)
    });
    let finalization = thread::spawn(move || {
        let mut client = finalization_client;
        barrier.wait();
        client.tool_call(955, "eliot_agent_result_finalize", &finalization_request)
    });
    let completed = completion
        .join()
        .map_err(|_| std::io::Error::other("task completion racer panicked"))??;
    assert_eq!(completed["decision"], "DONE_VERIFIED");
    let finalized = finalization
        .join()
        .map_err(|_| std::io::Error::other("managed finalization racer panicked"))?;
    match finalized {
        Ok(finalized) => {
            assert_eq!(
                finalized["schema_version"],
                "eliot-agent-result-finalize-v2"
            );
            let mut replay = McpClient::start_scoped_in_workspace(
                &fixture.workspace,
                "codex",
                &fixture.controller_session_id,
                &fixture.controller_role_lease_id,
                &fixture.task_id,
            )?;
            let replayed = replay.tool_call(
                956,
                "eliot_agent_result_finalize",
                &json!({
                    "invocation_id": fixture.invocation_id,
                    "expected_provider_output_hash": fixture.provider_output_hash,
                    "idempotency_key": "task_completion-finalization-race",
                    "verifier_refs": [fixture.verifier_ref],
                }),
            )?;
            assert_eq!(replayed["finalization_id"], finalized["finalization_id"]);
            assert_eq!(
                replayed["canonical_aggregate_receipt"],
                finalized["canonical_aggregate_receipt"]
            );
        }
        Err(error) => {
            let message = error.to_string();
            if !message.contains("Active")
                && !message.contains("active")
                && !message.contains("DoneVerified")
            {
                assert!(
                    message.contains("closed stdout")
                        || message.contains("closed named pipe")
                        || message.contains("daemon connection failed"),
                    "completion-first race produced unrelated finalization failure: {error}"
                );
                let mut replay = McpClient::start_scoped_in_workspace(
                    &fixture.workspace,
                    "codex",
                    &fixture.controller_session_id,
                    &fixture.controller_role_lease_id,
                    &fixture.task_id,
                )?;
                match replay.tool_call(
                    956,
                    "eliot_agent_result_finalize",
                    &json!({
                        "invocation_id": fixture.invocation_id,
                        "expected_provider_output_hash": fixture.provider_output_hash,
                        "idempotency_key": "task_completion-finalization-race",
                        "verifier_refs": [fixture.verifier_ref],
                    }),
                ) {
                    Ok(reconciled) => assert_eq!(
                        reconciled["schema_version"],
                        "eliot-agent-result-finalize-v2"
                    ),
                    Err(replay_error) => {
                        let replay_message = replay_error.to_string();
                        assert!(
                            replay_message.contains("Active")
                                || replay_message.contains("active")
                                || replay_message.contains("DoneVerified")
                                || replay_message.contains("closed stdout")
                                || replay_message.contains("closed named pipe")
                                || replay_message.contains("daemon connection failed"),
                            "finalization reconciliation failed for an unrelated reason: {replay_error}"
                        );
                        assert_eq!(
                            managed_finalization_record_count(
                                &fixture,
                                &[
                                    "managed_finalization_intent",
                                    "managed_finalization_aggregate"
                                ]
                            )?,
                            0,
                            "response loss without a replayable aggregate must leave no canonical finalization"
                        );
                        assert_eq!(
                            m3_git(&fixture.worktree, &["rev-parse", "HEAD"])?,
                            fixture.baseline_commit
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn second_process_verification_waits_until_managed_finalization_materializes() -> TestResult {
    let _guard = TestLock::acquire()?;
    let fixture = prepare_managed_finalization_fixture("verification-finalization-lock-race")?;
    let marker = test_runtime_root()
        .join("reports")
        .join("managed-finalization-authority-held.marker");
    if marker.exists() {
        fs::remove_file(&marker)?;
    }
    let mut owner = McpClient::start_scoped_with_finalization_pause_in_workspace(
        &fixture.workspace,
        "codex",
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
        3_000,
    )?;
    let task_state = owner.tool_call(
        957,
        "eliot_task_state",
        &json!({"project_id": fixture.project_id, "task_id": fixture.task_id}),
    )?;
    let task = &task_state["task_contract"];
    let verification_item_id = task["acceptance_items"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["required_evidence"] == "verification")
        })
        .and_then(|item| item["item_id"].as_str())
        .ok_or_else(|| std::io::Error::other("verification acceptance item is absent"))?
        .to_owned();
    let observation_id = task["observation_ids"]
        .as_array()
        .and_then(|ids| ids.first())
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("task observation id is absent"))?
        .to_owned();
    let planned_verifier_ref =
        required_test_string(task, "/action_provenance/planned_verifier_ref")?;
    let provenance_set_hash = required_test_string(task, "/action_provenance/hash")?;
    let verifier_config_hash = required_test_string(task, "/verification_scopes/0/config_hash")?;
    let original_revision = required_test_u64(task, "/memory_revision")?;
    let verification_request = json!({
        "project_id": fixture.project_id,
        "task_id": fixture.task_id,
        "write_id": uuid::Uuid::new_v4().to_string(),
        "expected_revision": original_revision,
        "item_id": verification_item_id,
        "observation_id": observation_id,
        "mode": "registered",
        "verifier_ref": planned_verifier_ref,
        "verifier_config_hash": verifier_config_hash,
        "provenance_set_hash": provenance_set_hash,
        "acceptance_item_ids": [verification_item_id],
        "artifact_paths": []
    });
    let finalization_request = json!({
        "invocation_id": fixture.invocation_id,
        "expected_provider_output_hash": fixture.provider_output_hash,
        "idempotency_key": "verification-finalization-lock-race",
        "verifier_refs": [fixture.verifier_ref],
    });
    let finalization_client = McpClient::connect_scoped_controller(
        &fixture.workspace,
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
    )?;
    let finalize_handle = thread::spawn(move || {
        let mut client = finalization_client;
        client.tool_call(958, "eliot_agent_result_finalize", &finalization_request)
    });
    let marker_deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        if finalize_handle.is_finished() {
            let outcome = finalize_handle
                .join()
                .map_err(|_| std::io::Error::other("managed finalizer racer panicked"))?;
            return match outcome {
                Ok(value) => Err(std::io::Error::other(format!(
                    "managed finalizer completed before holding task authority: {value}"
                ))
                .into()),
                Err(error) => Err(std::io::Error::other(format!(
                    "managed finalizer failed before holding task authority: {error}"
                ))
                .into()),
            };
        }
        if Instant::now() >= marker_deadline {
            return Err(std::io::Error::other(
                "managed finalizer did not expose the authority-held test marker",
            )
            .into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    let verification_client = McpClient::connect_scoped_controller(
        &fixture.workspace,
        &fixture.controller_session_id,
        &fixture.controller_role_lease_id,
        &fixture.task_id,
    )?;
    let verification_handle = thread::spawn(move || {
        let mut client = verification_client;
        client.tool_call(959, "eliot_task_verification_run", &verification_request)
    });
    thread::sleep(Duration::from_secs(1));
    assert!(
        !verification_handle.is_finished(),
        "second-process verification advanced while finalization held cached singleton authority"
    );
    let completion_payload = finalize_handle
        .join()
        .map_err(|_| std::io::Error::other("managed finalizer racer panicked"))??;
    assert_eq!(
        completion_payload["schema_version"],
        "eliot-agent-result-finalize-v2"
    );
    let verification_payload = verification_handle
        .join()
        .map_err(|_| std::io::Error::other("second verifier racer panicked"))??;
    assert_eq!(verification_payload["status"], "passed");
    let advanced = owner.tool_call(
        960,
        "eliot_task_state",
        &json!({"project_id": fixture.project_id, "task_id": fixture.task_id}),
    )?;
    assert!(required_test_u64(&advanced, "/task_contract/memory_revision")? > original_revision);
    assert_eq!(
        advanced["task_contract"]["verification_ids"]
            .as_array()
            .map(Vec::len),
        Some(2),
        "second verification must advance only after finalization releases task authority"
    );
    Ok(())
}

fn managed_test_write_id(key: &str) -> WriteId {
    let digest = blake3::hash(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

fn managed_test_store() -> TestResult<CanonicalStore> {
    let mut config = eliot_types::GovernorConfig::default().db.surreal;
    config.endpoint = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT")?;
    config.bind = std::env::var("ELIOT_TEST_SURREAL_BIND")?;
    config.password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")?;
    config.storage = std::env::var("ELIOT_TEST_SURREAL_STORAGE")?;
    Ok(CanonicalStore::new(config))
}

fn managed_test_canonical_write(
    project_id: ProjectId,
    task_id: Option<TaskId>,
    agent_id: AgentId,
    write_id: WriteId,
    key: &str,
    receipt_kind: &str,
    body: &Value,
) -> TestResult<WriteReceiptRef> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let store = managed_test_store()?;
        store.migrate_schema().await?;
        let wal_path = test_runtime_root()
            .join("reports")
            .join("managed-finalization-test-wal")
            .join(format!("{write_id}.redb"));
        let wal = ControlWal::open(&ControlWalConfig {
            path: wal_path.to_string_lossy().into_owned(),
        })?;
        let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
        let actor_task = tokio::spawn(actor.run());
        let payload = if receipt_kind == "agent_session" {
            json!({
                "receipt_kind": receipt_kind,
                "body_hash": managed_test_hash_json(body)?,
                "agent_session": body,
            })
        } else {
            json!({
                "receipt_kind": receipt_kind,
                "body_hash": managed_test_hash_json(body)?,
                "receipt_body": body,
            })
        };
        let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
            context: CommandContext {
                write_id,
                agent_id,
                session_id: Some(SessionId::from_uuid(agent_id.as_uuid())),
                project_id,
                task_id,
                scope: "governed host authority".to_owned(),
                authority: "canonical Eliot host boundary".to_owned(),
                visibility: Visibility::Internal,
                taint: TaintClass::LocalVerified,
                lifecycle_status: LifecycleStatus::Active,
            },
            tool_name: "eliot-governor-host".to_owned(),
            observation: format!("canonical {receipt_kind} fixture {key}"),
            payload,
        });
        let receipt = writer
            .submit(WriteAdmissionService.admit(&command)?)
            .await?;
        drop(writer);
        actor_task.await?;
        Ok(WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        })
    })
}

fn managed_fixture_repository(label: &str, changed_file: &str) -> TestResult<PathBuf> {
    let root = test_runtime_root().join(format!(
        "mf-{}",
        &blake3::hash(label.as_bytes()).to_hex()[..8]
    ));
    fs::create_dir_all(&root)?;
    fs::write(root.join("README.md"), "managed finalization fixture\n")?;
    fs::write(root.join(changed_file), "before managed finalization\n")?;
    m3_git(&root, &["init"])?;
    m3_git(&root, &["add", "README.md", changed_file])?;
    m3_git(
        &root,
        &[
            "-c",
            "user.name=Eliot Test",
            "-c",
            "user.email=eliot-test@example.invalid",
            "commit",
            "-m",
            "initialize managed finalization fixture",
        ],
    )?;
    Ok(root)
}

#[allow(clippy::too_many_lines)]
fn prepare_managed_finalization_fixture(label: &str) -> TestResult<ManagedFinalizationFixture> {
    prepare_managed_finalization_fixture_with_invocation_authority(label, true)
}

#[allow(clippy::too_many_lines)]
fn prepare_managed_finalization_fixture_with_invocation_authority(
    label: &str,
    canonical_invocation: bool,
) -> TestResult<ManagedFinalizationFixture> {
    let changed_file = format!(
        "candidate-{}.txt",
        &blake3::hash(label.as_bytes()).to_hex()[..8]
    );
    let workspace = managed_fixture_repository(label, &changed_file)?;
    let project_id = uuid::Uuid::new_v4().to_string();
    let task_id = uuid::Uuid::new_v4().to_string();
    let (daemon_owner, controller_session_id, claimed, created_task) = {
        let mut controller = McpClient::start_in_workspace(&workspace)?;
        let created_task = create_m3_task_fixture(&mut controller, &project_id, &task_id)?;
        let controller_session_id = controller.agent_session_id.clone();
        let mut next_id = 700;
        let claimed = m3_claim_work_fixture(
            &mut controller,
            &project_id,
            &task_id,
            "antigravity",
            &changed_file,
            &mut next_id,
        )?;
        (controller, controller_session_id, claimed, created_task)
    };
    let controller_role_lease_id = m3_grant_task_role(
        "codex",
        &controller_session_id,
        &task_id,
        "controller",
        "delegate,review,verify",
    )?;
    let provider_role_lease_id = m3_grant_task_role(
        "antigravity",
        &claimed.worker_session_id,
        &task_id,
        "implementer",
        "rust,lease_scoped_candidate_implementation",
    )?;
    drop(daemon_owner);
    let mut controller = McpClient::start_scoped_in_workspace(
        &workspace,
        "codex",
        &controller_session_id,
        &controller_role_lease_id,
        &task_id,
    )?;
    let worktree = controller.tool_call(
        701,
        "eliot_worktree_create",
        &json!({"lease_id": claimed.work_lease_id}),
    )?;
    let worktree_lease_id = required_test_string(&worktree, "/worktree_lease/worktree_lease_id")?;
    let worktree_path = PathBuf::from(required_test_string(
        &worktree,
        "/worktree_lease/worktree_path",
    )?);
    let baseline_commit = m3_git(&worktree_path, &["rev-parse", "HEAD"])?;
    fs::write(
        worktree_path.join(&changed_file),
        "managed provider candidate\n",
    )?;
    let candidate = Command::new("git")
        .current_dir(&worktree_path)
        .args([
            "diff",
            "--binary",
            "--no-ext-diff",
            &baseline_commit,
            "--",
            &changed_file,
        ])
        .output()?;
    if !candidate.status.success() {
        return Err(std::io::Error::other("managed fixture diff generation failed").into());
    }
    let candidate = candidate.stdout;
    m3_git(&worktree_path, &["restore", &changed_file])?;
    let provider_output_hash = managed_test_hash_bytes(&candidate);
    let invocation_id = format!(
        "host-invocation:{}",
        blake3::hash(format!("managed-stage:{label}").as_bytes()).to_hex()
    );
    let provider_result_id = format!(
        "agent-result:{}",
        blake3::hash(invocation_id.as_bytes()).to_hex()
    );
    let job_id = format!("operation-job:{}", uuid::Uuid::new_v4());
    let completed_at = "2026-07-16T12:00:00Z";
    let invocation_root = test_runtime_root()
        .join("reports")
        .join("host-invocations")
        .join(invocation_id.replace(':', "_"));
    fs::create_dir_all(&invocation_root)?;
    let stdout_ref = invocation_root.join("stdout.txt");
    let stderr_ref = invocation_root.join("stderr.log");
    fs::write(&stdout_ref, &candidate)?;
    fs::write(&stderr_ref, b"")?;
    let snapshot = json!({
        "head": baseline_commit,
        "status_hash": managed_test_hash_bytes(b"clean"),
        "diff_hash": managed_test_hash_bytes(b"clean"),
        "untracked_hash": managed_test_hash_bytes(b"clean"),
        "aggregate_hash": managed_test_hash_bytes(b"clean"),
    });
    let launch_boundary = json!({
        "schema_version": "eliot-managed-launch-boundary-v1",
        "executable_path": invocation_root.join("agy.exe"),
        "executable_hash": managed_test_hash_bytes(b"provider-free-agy"),
        "executable_version": "provider-free-fixture",
        "capability_probe_receipt": managed_test_hash_bytes(b"provider-free-capability"),
        "integration_bundle_ref": invocation_root.join("integration-bundle"),
        "integration_bundle_hash": managed_test_hash_bytes(b"provider-free-bundle"),
        "invocation_root": invocation_root,
        "environment": {
            "inherited_environment_cleared": true,
            "inherited_environment_allowlist": [],
            "environment_names": [],
            "sandbox_root": invocation_root.join("sandbox"),
            "isolated_paths": [],
        },
    });
    let request_hash = managed_test_hash_bytes(format!("request:{label}").as_bytes());
    let contract_hash = managed_test_hash_bytes(format!("contract:{label}").as_bytes());
    let authority_hash = managed_test_hash_bytes(format!("authority:{label}").as_bytes());
    let idempotency_key = format!("managed-finalization-{label}");
    let mut attempt = json!({
        "schema_version": "eliot-managed-host-attempt-v4",
        "invocation_id": invocation_id,
        "idempotency_key": idempotency_key,
        "request_hash": request_hash,
        "contract_hash": contract_hash,
        "host": "antigravity",
        "project_id": project_id,
        "task_id": task_id,
        "work_item_id": claimed.work_item_id,
        "agent_session_id": claimed.worker_session_id,
        "role_lease_id": provider_role_lease_id,
        "work_lease_id": claimed.work_lease_id,
        "worktree_lease_id": worktree_lease_id,
        "cwd_or_worktree": worktree_path,
        "write_set": [&changed_file],
        "tool": "agy",
        "tool_version": "provider-free-fixture",
        "model": Value::Null,
        "prompt_hash": managed_test_hash_bytes(b"fixture-prompt"),
        "owner_pid": std::process::id(),
        "authority_hash": authority_hash,
        "worktree_before": snapshot,
        "launch_boundary": launch_boundary,
        "broker_job_id": job_id,
        "broker_result_id": provider_result_id,
        "broker_host_session_id": claimed.worker_session_id,
        "planned_verifier_ref": created_task.verifier_ref.clone(),
        "attempt_hash": "",
        "attempt_recorded_before_provider_call": true,
        "provider_call_budget_consumed": false,
        "redispatch_allowed": false,
        "started_at": completed_at,
    });
    attempt["attempt_hash"] = Value::String(managed_test_hash_json(&attempt)?);
    let attempt_path = invocation_root.join("attempt.json");
    let result_path = invocation_root.join("result.json");
    fs::write(&attempt_path, serde_json::to_vec_pretty(&attempt)?)?;
    let base = json!({
        "schema_version": "eliot-managed-host-launch-result-v1",
        "invocation_id": invocation_id,
        "idempotency_key": idempotency_key,
        "request_hash": request_hash,
        "contract_hash": contract_hash,
        "attempt_hash": attempt["attempt_hash"],
        "authority_hash": authority_hash,
        "host": "antigravity",
        "status": "succeeded",
        "outcome_known": true,
        "reason": "provider-free managed candidate fixture",
        "scope": {
            "project_id": project_id,
            "task_id": task_id,
            "work_item_id": claimed.work_item_id,
            "agent_session_id": claimed.worker_session_id,
            "role_lease_id": provider_role_lease_id,
            "work_lease_id": claimed.work_lease_id,
            "worktree_lease_id": worktree_lease_id,
            "cwd_or_worktree": worktree_path,
            "baseline_commit": baseline_commit,
            "write_set": [&changed_file],
        },
        "tool_evidence": {
            "tool": "agy",
            "official_cli": true,
            "executable": launch_boundary["executable_path"],
            "executable_hash": launch_boundary["executable_hash"],
            "version": "fixture",
            "capability_probe_receipt": launch_boundary["capability_probe_receipt"],
        },
        "model_evidence": {"selected_model": Value::Null, "exact_model_cli_flag": true},
        "exit_evidence": {"code": 0, "success": true},
        "attempt_ref": attempt_path,
        "result_ref": result_path,
        "execution_evidence": {
            "provider_dispatched": false,
            "stdout_ref": stdout_ref,
            "stderr_ref": stderr_ref,
            "stdout_hash": provider_output_hash,
            "stderr_hash": managed_test_hash_bytes(b""),
            "candidate_diff_hash": provider_output_hash,
            "candidate_diff_ref": format!("candidate-unified-diff:{provider_output_hash}"),
            "worktree_before": snapshot,
            "worktree_after": snapshot,
            "worktree_immutable": true,
            "launch_boundary": launch_boundary,
            "launch_boundary_intact": true,
            "native_process_tree_guard": true,
            "process_tree_terminated": true,
        },
        "candidate_only": true,
        "truth_promoted": false,
        "disposition": "candidate_unreviewed",
        "cancellation_requested": false,
        "redispatch_allowed": false,
        "reconciliation_required": false,
        "broker_chain": {
            "job_id": job_id,
            "result_id": provider_result_id,
            "job_result_ref": provider_result_id,
            "host_session_id": claimed.worker_session_id,
            "planned_verifier_ref": created_task.verifier_ref.clone(),
            "candidate_status": "candidate_only",
            "operation_job_recorded": true,
            "agent_result_recorded": true,
            "controller_disposition_required": true,
            "direct_truth_promotion": false,
        },
        "completed_at": completed_at,
    });
    let project = project_id.parse::<ProjectId>()?;
    let task = task_id.parse::<TaskId>()?;
    let provider_agent = AgentId::from_uuid(claimed.worker_session_id.parse::<uuid::Uuid>()?);
    let managed_receipt = managed_test_canonical_write(
        project,
        Some(task),
        provider_agent,
        managed_test_write_id(&format!("managed-host-result:{invocation_id}")),
        &format!("managed-host-result:{invocation_id}"),
        "managed_host_launch_result",
        &base,
    )?;
    let mut result = base;
    let body_hash = managed_test_hash_json(&result)?;
    result["canonical_authority"] = json!({
        "receipt": managed_receipt,
        "body_hash": body_hash,
        "receipt_kind": "managed_host_launch_result",
    });
    result["receipt_hash"] = Value::String(managed_test_hash_json(&result)?);
    fs::write(&result_path, serde_json::to_vec_pretty(&result)?)?;

    let provider_result = AgentResultEnvelope {
        result_id: provider_result_id.clone(),
        invocation_id: invocation_id.clone(),
        host_id: AgentHostId::Antigravity,
        host_session_id: Some(claimed.worker_session_id.clone()),
        status: AgentResultStatus::Succeeded,
        role_lease_epoch: 1,
        operation_generation: 1,
        summary: "provider-free managed candidate fixture".to_owned(),
        artifact_refs: vec![format!("candidate-unified-diff:{provider_output_hash}")],
        evidence_refs: vec![
            attempt_path.to_string_lossy().into_owned(),
            result_path.to_string_lossy().into_owned(),
        ],
        verifier_refs: Vec::new(),
        candidate_only: true,
        exit_status: Some(0),
        token_or_cost_telemetry: None,
        unknown_outcome_evidence_refs: Vec::new(),
        supersedes_result_id: None,
        provider_output_hash: None,
        canonical_receipt: None,
    };
    let provider_result_value = serde_json::to_value(&provider_result)?;
    let provider_receipt = managed_test_canonical_write(
        project,
        Some(task),
        provider_agent,
        managed_test_write_id(&format!("managed-provider-result:{provider_result_id}")),
        &format!("managed-provider-result:{provider_result_id}"),
        "agent_result",
        &provider_result_value,
    )?;
    let mut provider_result = provider_result;
    provider_result.canonical_receipt = Some(provider_receipt);
    let timestamp =
        time::OffsetDateTime::parse(completed_at, &time::format_description::well_known::Rfc3339)?;
    let job = OperationJob {
        job_id: job_id.clone(),
        invocation_id: invocation_id.clone(),
        host_id: AgentHostId::Antigravity,
        state: OperationJobState::Completed,
        attempt: 1,
        resume_session_id: Some(claimed.worker_session_id.clone()),
        result_ref: Some(provider_result_id.clone()),
        idempotency_key: idempotency_key.clone(),
        created_at: timestamp,
        updated_at: timestamp,
        generation: 1,
        phase: eliot_types::OperationPhase::Completed,
        phase_started_at: Some(timestamp),
        last_progress_at: Some(timestamp),
        phase_deadline_at: None,
        absolute_deadline_at: None,
        restart_count: 0,
        runtime_contract_sha256: None,
        role_lease_id: Some(provider_role_lease_id.clone()),
        role_lease_epoch: Some(1),
    };
    managed_test_canonical_write(
        project,
        Some(task),
        provider_agent,
        managed_test_write_id(&format!("managed-operation-job:{job_id}:completed")),
        &format!("managed-operation-job:{job_id}:completed"),
        "operation_job",
        &serde_json::to_value(&job)?,
    )?;
    let broker_path = test_runtime_root().join("reports/delegation-state/latest.json");
    let mut broker: eliot_types::DelegationState =
        serde_json::from_reader(fs::File::open(&broker_path)?)?;
    let invocation_request = AgentInvocationRequest {
        invocation_id: invocation_id.clone(),
        project_id: project,
        task_id: task,
        work_item_id: claimed.work_item_id.parse::<WorkItemId>()?,
        requested_capabilities: vec!["lease_scoped_candidate_implementation".to_owned()],
        role_lease_id: provider_role_lease_id,
        role_lease_epoch: 1,
        operation_generation: 1,
        runtime_contract_sha256: None,
        work_lease_id: Some(claimed.work_lease_id.parse::<WorkLeaseId>()?),
        packet_refs: Vec::new(),
        expected_result_kind: "candidate_unified_diff".to_owned(),
        verifier_ref: created_task.verifier_ref.clone(),
        idempotency_key,
    };
    if canonical_invocation {
        managed_test_canonical_write(
            project,
            Some(task),
            provider_agent,
            managed_test_write_id(&format!("managed-agent-invocation:{invocation_id}")),
            &format!("managed-agent-invocation:{invocation_id}"),
            "agent_invocation_request",
            &serde_json::to_value(&invocation_request)?,
        )?;
    }
    broker.agent_invocations.push(invocation_request);
    broker.operation_jobs.push(job);
    broker.agent_results.push(provider_result);
    fs::write(broker_path, serde_json::to_vec_pretty(&broker)?)?;
    let work_path = test_runtime_root().join("reports/work/state.json");
    let mut work: eliot_engine::WorkState = serde_json::from_reader(fs::File::open(&work_path)?)?;
    let controller_agent = AgentId::from_uuid(controller_session_id.parse::<uuid::Uuid>()?);
    let controller_session = AgentSession {
        agent_session_id: controller_session_id.parse::<AgentSessionId>()?,
        agent_id: controller_agent,
        project_id: project,
        role: AgentRole::Controller,
        transport: AgentTransport::McpTool,
        status: AgentSessionStatus::Active,
        parent_session_id: None,
        current_work_item_id: None,
        started_at: timestamp,
        last_heartbeat_at: timestamp,
        stopped_at: None,
        unavailable_reason: None,
        write_receipt: None,
    };
    managed_test_canonical_write(
        project,
        None,
        controller_agent,
        managed_test_write_id(&format!(
            "managed-controller-session:{controller_session_id}"
        )),
        &format!("managed-controller-session:{controller_session_id}"),
        "agent_session",
        &serde_json::to_value(&controller_session)?,
    )?;
    work.sessions.push(controller_session);
    fs::write(work_path, serde_json::to_vec_pretty(&work)?)?;
    let created_task =
        refresh_m3_task_fixture(&mut controller, &project_id, &task_id, created_task)?;
    let verification_id =
        observe_and_verify_m3_task(&mut controller, &project_id, &task_id, &created_task)?;
    drop(controller);
    Ok(ManagedFinalizationFixture {
        workspace,
        worktree: worktree_path,
        project_id,
        task_id,
        controller_session_id,
        controller_role_lease_id,
        invocation_id,
        provider_output_hash,
        verifier_ref: format!("verification:{verification_id}"),
        baseline_commit,
        provider_result_id,
        job_id,
        work_lease_id: claimed.work_lease_id,
        worktree_lease_id,
    })
}

fn m3_fixture_repository() -> TestResult<PathBuf> {
    // Git for Windows exports the linked-worktree git dir through GIT_DIR.
    // Keep the isolated fixture's root deliberately short so that the nested
    // worktree metadata remains below the Windows environment/path limit.
    let root = test_runtime_root().join("m3r");
    fs::create_dir_all(&root)?;
    fs::write(root.join("README.md"), "isolated M3 authority fixture\n")?;
    m3_git(&root, &["init"])?;
    m3_git(&root, &["add", "README.md"])?;
    m3_git(
        &root,
        &[
            "-c",
            "user.name=Eliot Test",
            "-c",
            "user.email=eliot-test@example.invalid",
            "commit",
            "-m",
            "initialize M3 authority fixture",
        ],
    )?;
    Ok(root)
}

fn m3_git(root: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "git {args:?} failed in {}: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn m3_grant_task_role(
    host: &str,
    session_id: &str,
    task_id: &str,
    role: &str,
    capabilities: &str,
) -> TestResult<String> {
    let registered = run_json(&[
        "host",
        "session-register",
        "--host",
        host,
        "--session",
        session_id,
        "--client-instance",
        session_id,
    ])?;
    assert_eq!(registered["binding"]["agent_session_id"], session_id);
    assert_eq!(registered["host_identity_granted_role"], false);
    let granted = run_json(&[
        "host",
        "role-grant",
        "--task",
        task_id,
        "--session",
        session_id,
        "--role",
        role,
        "--capability",
        capabilities,
        "--ttl-minutes",
        "60",
    ])?;
    assert!(granted["canonical_authority_receipt"].is_object());
    assert!(granted["canonical_host_binding_receipt"].is_object());
    required_test_string(&granted, "/task_role_lease/role_lease_id")
}

fn next_m3_tool_call(
    client: &mut McpClient,
    next_id: &mut u64,
    name: &str,
    arguments: &Value,
) -> TestResult<Value> {
    let id = *next_id;
    *next_id += 1;
    client.tool_call(id, name, arguments)
}

fn m3_claim_work_fixture(
    controller: &mut McpClient,
    project_id: &str,
    task_id: &str,
    host: &str,
    changed_file: &str,
    next_id: &mut u64,
) -> TestResult<M3ClaimedWorkFixture> {
    let created = next_m3_tool_call(
        controller,
        next_id,
        "eliot_work_create",
        &json!({
            "project": project_id,
            "task": task_id,
            "goal": format!("produce exact {host} M3 candidate"),
            "read": [changed_file],
            "write": [changed_file]
        }),
    )?;
    let work_item = created["work_items"]
        .as_array()
        .and_then(|items| items.last())
        .cloned()
        .ok_or_else(|| std::io::Error::other("work create returned no item"))?;
    let work_item_id = required_test_string(&work_item, "/work_item_id")?;
    let claimed = next_m3_tool_call(
        controller,
        next_id,
        "eliot_work_claim",
        &json!({"project": project_id, "task": task_id, "role": "implementer"}),
    )?;
    let worker_session = claimed["sessions"]
        .as_array()
        .and_then(|sessions| {
            sessions.iter().find(|session| {
                session["current_work_item_id"].as_str() == Some(work_item_id.as_str())
            })
        })
        .ok_or_else(|| std::io::Error::other("work claim returned no exact worker session"))?;
    assert_eq!(
        worker_session["role"], "implementer",
        "claimed AgentSession role must equal the requested WorkLease role"
    );
    let work_lease = claimed["active_leases"]
        .as_array()
        .and_then(|leases| {
            leases
                .iter()
                .find(|lease| lease["work_item_id"] == work_item_id)
        })
        .cloned()
        .ok_or_else(|| std::io::Error::other("work claim returned no exact active lease"))?;
    Ok(M3ClaimedWorkFixture {
        host: host.to_owned(),
        changed_file: changed_file.to_owned(),
        work_item_id,
        work_lease_id: required_test_string(&work_lease, "/work_lease_id")?,
        worker_session_id: required_test_string(&work_lease, "/agent_session_id")?,
        work_lease,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn m3_prepare_host_authority_fixture(
    controller: &mut McpClient,
    workspace: &Path,
    project_id: &str,
    task_id: &str,
    claimed: M3ClaimedWorkFixture,
    role_lease_id: String,
    planned_verifier_ref: &str,
    next_id: &mut u64,
) -> TestResult<M3PreparedHostAuthorityFixture> {
    let M3ClaimedWorkFixture {
        host,
        changed_file,
        work_item_id,
        work_lease_id,
        worker_session_id,
        work_lease,
    } = claimed;

    let worktree = next_m3_tool_call(
        controller,
        next_id,
        "eliot_worktree_create",
        &json!({"lease_id": work_lease_id}),
    )?;
    let worktree_lease_id = required_test_string(&worktree, "/worktree_lease/worktree_lease_id")?;
    let worktree_path = PathBuf::from(required_test_string(
        &worktree,
        "/worktree_lease/worktree_path",
    )?);
    let candidate_path = worktree_path.join(&changed_file);
    if let Some(parent) = candidate_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&candidate_path, format!("committed {host} candidate\n"))?;
    m3_git(&worktree_path, &["add", "--", &changed_file])?;
    m3_git(
        &worktree_path,
        &[
            "-c",
            "user.name=Eliot Test",
            "-c",
            "user.email=eliot-test@example.invalid",
            "commit",
            "-m",
            &format!("record {host} candidate"),
        ],
    )?;
    let head = m3_git(&worktree_path, &["rev-parse", "HEAD"])?;
    OpenOptions::new()
        .append(true)
        .open(&candidate_path)?
        .write_all(b"captured candidate delta\n")?;

    let captured = next_m3_tool_call(
        controller,
        next_id,
        "eliot_worktree_capture_diff",
        &json!({"worktree_lease": worktree_lease_id}),
    )?;
    assert_eq!(captured["candidate_diff"]["capture_status"], "captured");
    assert_eq!(captured["candidate_diff"]["worktree_head"], head);
    let candidate_diff_id = required_test_string(&captured, "/candidate_diff/candidate_diff_id")?;
    let diff_ref = required_test_string(&captured, "/candidate_diff/diff_ref")?;
    let reviewed = next_m3_tool_call(
        controller,
        next_id,
        "eliot_worktree_review",
        &json!({"candidate_diff": candidate_diff_id, "decision": "accept"}),
    )?;
    assert_eq!(
        reviewed["candidate_review"]["decision"],
        "accept_for_patch_runner"
    );
    assert_eq!(
        reviewed["candidate_diff"]["capture_status"],
        "accepted_for_patch_runner"
    );
    assert!(reviewed["candidate_review"]["write_receipt"].is_object());

    let delegated = next_m3_tool_call(
        controller,
        next_id,
        "eliot_agent_delegate",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "work_item_id": work_item_id,
            "target_host": host,
            "target_role_lease_id": role_lease_id,
            "work_lease_id": work_lease_id,
            "requested_capabilities": ["rust"],
            "packet_refs": ["packet:m3-exact-authority"],
            "expected_result_kind": "candidate_diff",
            "verifier_ref": planned_verifier_ref,
            "idempotency_key": format!("m3-delegate-{host}-{work_item_id}")
        }),
    )?;
    let invocation_id = required_test_string(&delegated, "/request/invocation_id")?;
    assert_eq!(delegated["job"]["state"], "queued");

    let mut worker = McpClient::connect_scoped(
        workspace,
        &host,
        &worker_session_id,
        &role_lease_id,
        task_id,
    )?;
    let session = worker.tool_call(1, "eliot_host_session_status", &json!({}))?;
    assert_eq!(session["role_status"], "task_role_lease_active");
    let claimed_job = worker.tool_call(
        2,
        "eliot_agent_job_claim",
        &json!({"invocation_id": invocation_id}),
    )?;
    assert_eq!(claimed_job["job"]["state"], "running");
    drop(worker);

    Ok(M3PreparedHostAuthorityFixture {
        host,
        work_item_id,
        worktree_lease_id,
        changed_file,
        autonomy_lease: json!({
            "lease_ref": format!("work-lease:{work_lease_id}"),
            "holder": work_lease["agent_id"],
            "project_id": project_id,
            "scope": work_lease["scope"],
            "expires_at": work_lease["expires_at"]
        }),
        worker_session_id,
        role_lease_id,
        invocation_id,
        diff_ref,
        commit_ref: format!("commit:{head}"),
    })
}

fn m3_finalize_host_authority_fixture(
    controller: &mut McpClient,
    workspace: &Path,
    task_id: &str,
    prepared: M3PreparedHostAuthorityFixture,
    verifier_ref: &str,
    next_id: &mut u64,
) -> TestResult<M3HostAuthorityFixture> {
    let mut worker = McpClient::connect_scoped(
        workspace,
        &prepared.host,
        &prepared.worker_session_id,
        &prepared.role_lease_id,
        task_id,
    )?;
    let result_id = format!("result:m3-{}-{}", prepared.host, uuid::Uuid::new_v4());
    let result = worker.tool_call(
        1,
        "eliot_agent_result_submit",
        &json!({
            "result_id": result_id,
            "invocation_id": prepared.invocation_id,
            "status": "succeeded",
            "summary": format!("{} produced a verified candidate", prepared.host),
            "artifact_refs": [prepared.diff_ref, prepared.commit_ref],
            "evidence_refs": [verifier_ref],
            "verifier_refs": [verifier_ref],
            "exit_status": 0,
            "unknown_outcome_evidence_refs": []
        }),
    )?;
    assert_eq!(result["result"]["status"], "succeeded");
    drop(worker);
    let disposition = next_m3_tool_call(
        controller,
        next_id,
        "eliot_agent_result_disposition",
        &json!({
            "result_id": result_id,
            "kind": "accepted",
            "reason": "exact diff, commit, and verifier chain accepted",
            "evidence_refs": [prepared.diff_ref],
            "idempotency_key": format!(
                "m3-disposition-{}-{}",
                prepared.host, prepared.work_item_id
            )
        }),
    )?;
    assert_eq!(disposition["disposition"]["kind"], "accepted");
    let job = next_m3_tool_call(
        controller,
        next_id,
        "eliot_agent_job_status",
        &json!({"invocation_id": prepared.invocation_id}),
    )?;
    assert_eq!(job["job"]["state"], "completed");
    assert_eq!(job["job"]["result_ref"], result_id);
    assert_eq!(job["result"]["result_id"], result_id);
    assert_eq!(job["dispositions"][0]["kind"], "accepted");

    Ok(M3HostAuthorityFixture {
        host: prepared.host,
        work_item_id: prepared.work_item_id,
        worktree_lease_id: prepared.worktree_lease_id,
        result_id,
        changed_file: prepared.changed_file,
        autonomy_lease: prepared.autonomy_lease,
    })
}

fn replace_m3_local_job_result_ref(
    chain: &M3HostAuthorityFixture,
    replacement: &str,
) -> TestResult<(String, String)> {
    let path = test_runtime_root().join("reports/delegation-state/latest.json");
    let mut broker: eliot_types::DelegationState = serde_json::from_reader(fs::File::open(&path)?)?;
    let invocation_id = broker
        .agent_results
        .iter()
        .find(|item| item.result_id == chain.result_id)
        .map(|item| item.invocation_id.clone())
        .ok_or_else(|| std::io::Error::other("M3 result projection missing before tamper"))?;
    let job = broker
        .operation_jobs
        .iter_mut()
        .find(|item| item.invocation_id == invocation_id)
        .ok_or_else(|| std::io::Error::other("M3 job projection missing before tamper"))?;
    let original = job
        .result_ref
        .replace(replacement.to_owned())
        .ok_or_else(|| std::io::Error::other("M3 job result_ref missing before tamper"))?;
    fs::write(path, serde_json::to_vec_pretty(&broker)?)?;
    Ok((invocation_id, original))
}

fn restore_m3_local_job_result_ref(invocation_id: &str, result_ref: &str) -> TestResult {
    let path = test_runtime_root().join("reports/delegation-state/latest.json");
    let mut broker: eliot_types::DelegationState = serde_json::from_reader(fs::File::open(&path)?)?;
    let job = broker
        .operation_jobs
        .iter_mut()
        .find(|item| item.invocation_id == invocation_id)
        .ok_or_else(|| std::io::Error::other("M3 job projection missing during restore"))?;
    job.result_ref = Some(result_ref.to_owned());
    fs::write(path, serde_json::to_vec_pretty(&broker)?)?;
    Ok(())
}

fn delete_m3_local_authority_projections(chain: &M3HostAuthorityFixture) -> TestResult {
    let root = test_runtime_root();
    let broker_path = root.join("reports/delegation-state/latest.json");
    let mut broker: eliot_types::DelegationState =
        serde_json::from_reader(fs::File::open(&broker_path)?)?;
    broker
        .agent_results
        .retain(|item| item.result_id != chain.result_id);
    broker
        .agent_result_dispositions
        .retain(|item| item.result_id != chain.result_id);
    fs::write(broker_path, serde_json::to_vec_pretty(&broker)?)?;

    let work_path = root.join("reports/work/state.json");
    let mut work: eliot_engine::WorkState = serde_json::from_reader(fs::File::open(&work_path)?)?;
    let worktree_id = chain
        .worktree_lease_id
        .parse::<eliot_types::WorktreeLeaseId>()?;
    let diff_ids = work
        .candidate_diffs
        .iter()
        .filter(|item| item.worktree_lease_id == worktree_id)
        .map(|item| item.candidate_diff_id)
        .collect::<Vec<_>>();
    let work_lease_ids = work
        .worktree_leases
        .iter()
        .filter(|item| item.worktree_lease_id == worktree_id)
        .map(|item| item.work_lease_id)
        .collect::<Vec<_>>();
    work.candidate_reviews
        .retain(|item| !diff_ids.contains(&item.candidate_diff_id));
    work.candidate_diffs
        .retain(|item| item.worktree_lease_id != worktree_id);
    work.worktree_leases
        .retain(|item| item.worktree_lease_id != worktree_id);
    work.leases
        .retain(|item| !work_lease_ids.contains(&item.work_lease_id));
    fs::write(work_path, serde_json::to_vec_pretty(&work)?)?;
    Ok(())
}

fn assert_m3_committed_action(response: &Value, action: &str) -> TestResult {
    assert_eq!(response["accepted"], true, "M3 denial response: {response}");
    assert_eq!(response["action"], action);
    let receipts = response["canonical_receipts"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("M3 action has no canonical receipt array"))?;
    assert!(!receipts.is_empty());
    assert!(receipts[0]["write_id"].is_string());
    assert!(receipts[0]["receipt_id"].is_string());
    Ok(())
}

struct M3CreatedTaskFixture {
    created_revision: u64,
    create_receipt: String,
    packet: Value,
    verifier_ref: String,
    verifier_config_hash: String,
}

fn create_m3_task_fixture(
    client: &mut McpClient,
    project_id: &str,
    task_id: &str,
) -> TestResult<M3CreatedTaskFixture> {
    let created = client.tool_call(
        80,
        "eliot_task_contract_create",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": uuid::Uuid::new_v4().to_string(),
            "title": "M3 bounded autonomy runtime proof",
            "acceptance_items": [
                {"item_id": "observed", "description": "runtime action observed", "required_evidence": "observation"},
                {"item_id": "verified", "description": "runtime verifier passed", "required_evidence": "verification"}
            ]
        }),
    )?;
    let created_revision = required_test_u64(&created, "/task_contract/memory_revision")?;
    let create_receipt = required_test_string(&created, "/write_receipt/receipt_id")?;
    let packet = client.tool_call(
        81,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "prove the bounded autonomy runtime",
            "candidate_handles": [],
            "max_tokens": 1200
        }),
    )?;
    let descriptor = packet["registered_verifiers"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["verifier_id"] == "daemon-receipt-resolution")
        })
        .ok_or_else(|| std::io::Error::other("registered verifier missing"))?;
    let verifier_ref = required_test_string(descriptor, "/verifier_ref")?;
    let verifier_config_hash = required_test_string(descriptor, "/config_hash")?;
    Ok(M3CreatedTaskFixture {
        created_revision,
        create_receipt,
        packet,
        verifier_ref,
        verifier_config_hash,
    })
}

fn refresh_m3_task_fixture(
    client: &mut McpClient,
    project_id: &str,
    task_id: &str,
    mut fixture: M3CreatedTaskFixture,
) -> TestResult<M3CreatedTaskFixture> {
    let packet = client.tool_call(
        81,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "prove the bounded autonomy runtime after authority registration",
            "candidate_handles": [],
            "max_tokens": 1200
        }),
    )?;
    let descriptor = packet["registered_verifiers"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["verifier_id"] == "daemon-receipt-resolution")
        })
        .ok_or_else(|| std::io::Error::other("registered verifier missing after restart"))?;
    fixture.verifier_ref = required_test_string(descriptor, "/verifier_ref")?;
    fixture.verifier_config_hash = required_test_string(descriptor, "/config_hash")?;
    fixture.packet = packet;
    Ok(fixture)
}

#[allow(clippy::too_many_lines)]
fn observe_and_verify_m3_task(
    client: &mut McpClient,
    project_id: &str,
    task_id: &str,
    fixture: &M3CreatedTaskFixture,
) -> TestResult<String> {
    let action = client.tool_call(
        82,
        "eliot_task_action_request",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": uuid::Uuid::new_v4().to_string(),
            "expected_revision": fixture.created_revision,
            "packet_id": required_test_string(&fixture.packet, "/packet_id")?,
            "packet_revision_fence": required_test_u64(&fixture.packet, "/packet_revision_fence")?,
            "task_contract_ref": required_test_string(&fixture.packet, "/task_contract_ref")?,
            "current_truth_refs": fixture.packet["current_truth_refs"].clone(),
            "provenance_handles": [fixture.create_receipt],
            "negative_memory_checked": true,
            "negative_memory_check_ref": required_test_string(
                &fixture.packet,
                "/negative_memory_check_ref"
            )?,
            "planned_action": "record bounded runtime observation",
            "planned_verifier_ref": fixture.verifier_ref
        }),
    )?;
    let action_revision = required_test_u64(&action, "/task_contract/memory_revision")?;
    let action_lease_id = required_test_string(&action, "/action_lease/lease_id")?;
    let provenance_hash = required_test_string(&action, "/action_lease/provenance_set_hash")?;
    let action_receipt = required_test_string(&action, "/write_receipt/receipt_id")?;
    let observation_write = uuid::Uuid::new_v4().to_string();
    let observed = client.tool_call(
        83,
        "eliot_task_observation_record",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": observation_write,
            "expected_revision": action_revision,
            "action_lease_id": action_lease_id,
            "item_id": "observed",
            "tool_name": "m3_runtime_probe",
            "observation": "bounded runtime uses canonical WriterActor records",
            "status": "passed",
            "scope": format!("eliot/task/{task_id}/acceptance/observed"),
            "provenance_handles": [action_receipt],
            "provenance_set_hash": provenance_hash
        }),
    )?;
    let observation_revision = required_test_u64(&observed, "/task_contract/memory_revision")?;
    let observation_id = required_test_string(&observed, "/observation_id")?;
    let verified = client.tool_call(
        84,
        "eliot_task_verification_run",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": uuid::Uuid::new_v4().to_string(),
            "expected_revision": observation_revision,
            "item_id": "verified",
            "observation_id": observation_id,
            "mode": "registered",
            "verifier_ref": fixture.verifier_ref,
            "verifier_config_hash": fixture.verifier_config_hash,
            "provenance_set_hash": provenance_hash,
            "acceptance_item_ids": ["verified"],
            "artifact_paths": []
        }),
    )?;
    assert_eq!(verified["status"], "passed");
    required_test_string(&verified, "/verification_id")
}

fn seed_m3_verified_task(
    client: &mut McpClient,
    project_id: &str,
    task_id: &str,
) -> TestResult<String> {
    let fixture = create_m3_task_fixture(client, project_id, task_id)?;
    observe_and_verify_m3_task(client, project_id, task_id, &fixture)
}

struct M2TraceFixture {
    task_revision: u64,
    task_contract: Value,
    observation_id: String,
    verification_id: String,
    trace_refs: [String; 2],
}

struct M2MetaReplayFixture {
    task_revision: u64,
    trace_refs: [String; 2],
    fixed_baseline: String,
    fixed_candidate: String,
    holdout_baseline: String,
    holdout_candidate: String,
    baseline_policy: Value,
    candidate_policy: Value,
}

fn seed_m2_trace_fixture(
    client: &mut McpClient,
    project_id: &str,
    task_id: &str,
    id_base: u64,
) -> TestResult<M2TraceFixture> {
    let verification_id = seed_m3_verified_task(client, project_id, task_id)?;
    let task_state = client.tool_call(
        id_base,
        "eliot_task_state",
        &json!({"project_id": project_id, "task_id": task_id}),
    )?;
    let task_revision = required_test_u64(&task_state, "/task_contract/memory_revision")?;
    let task_contract = task_state
        .pointer("/task_contract")
        .cloned()
        .ok_or_else(|| std::io::Error::other("seeded M2 task contract missing"))?;
    let observation_id = required_test_string(&task_state, "/task_contract/observation_ids/0")?;
    let artifact_ref = required_test_string(
        &task_state,
        "/task_contract/verification_scopes/0/artifact_refs/0/resource_ref",
    )?;
    let trace_refs = [
        format!("trace:m2-audit-{id_base}-a"),
        format!("trace:m2-audit-{id_base}-b"),
    ];
    for (index, trace_ref) in trace_refs.iter().enumerate() {
        let trace = client.tool_call(
            id_base + 1 + u64::try_from(index)?,
            "eliot_trace_completeness",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "expected_task_revision": task_revision,
                "idempotency_key": format!("m2-audit-trace-{id_base}-{index}"),
                "trace_ref": trace_ref,
                "actual_observation_ref": format!("actual_observation:{observation_id}"),
                "verifier_run_ref": format!("verifier_run:{verification_id}"),
                "artifact_ref": format!("artifact_ref:{artifact_ref}"),
                "source_route": "controller",
                "source_tool": "m2-audit-runtime-test",
                "source_verifier": "daemon-receipt-resolution",
                "outcome": "passed",
                "taint": "local_verified"
            }),
        )?;
        assert_eq!(trace["accepted"], true);
    }
    Ok(M2TraceFixture {
        task_revision,
        task_contract,
        observation_id,
        verification_id,
        trace_refs,
    })
}

fn seed_m2_meta_replay_fixture(
    client: &mut McpClient,
    project_id: &str,
    task_id: &str,
    id_base: u64,
) -> TestResult<M2MetaReplayFixture> {
    let trace = seed_m2_trace_fixture(client, project_id, task_id, id_base)?;
    let (baseline_policy, candidate_policy) = m2_replay_policies();
    let fixed = client.tool_call(
        id_base + 10,
        "eliot_replay_run",
        &m2_replay_request(M2ReplayRequest {
            project_id,
            task_id,
            task_revision: trace.task_revision,
            idempotency_key: &format!("m2-seed-fixed-{id_base}"),
            role: "fixed",
            trace_refs: &trace.trace_refs,
            baseline_policy: &baseline_policy,
            candidate_policy: &candidate_policy,
        }),
    )?;
    let holdout = client.tool_call(
        id_base + 11,
        "eliot_replay_run",
        &m2_replay_request(M2ReplayRequest {
            project_id,
            task_id,
            task_revision: trace.task_revision,
            idempotency_key: &format!("m2-seed-holdout-{id_base}"),
            role: "holdout",
            trace_refs: &trace.trace_refs,
            baseline_policy: &baseline_policy,
            candidate_policy: &candidate_policy,
        }),
    )?;
    Ok(M2MetaReplayFixture {
        task_revision: trace.task_revision,
        trace_refs: trace.trace_refs,
        fixed_baseline: required_test_string(&fixed, "/baseline_execution/execution_id")?,
        fixed_candidate: required_test_string(&fixed, "/candidate_execution/execution_id")?,
        holdout_baseline: required_test_string(&holdout, "/baseline_execution/execution_id")?,
        holdout_candidate: required_test_string(&holdout, "/candidate_execution/execution_id")?,
        baseline_policy,
        candidate_policy,
    })
}

#[derive(Clone, Copy)]
struct M2ReplayRequest<'a> {
    project_id: &'a str,
    task_id: &'a str,
    task_revision: u64,
    idempotency_key: &'a str,
    role: &'a str,
    trace_refs: &'a [String; 2],
    baseline_policy: &'a Value,
    candidate_policy: &'a Value,
}

fn m2_replay_request(request: M2ReplayRequest<'_>) -> Value {
    json!({
        "project_id": request.project_id,
        "task_id": request.task_id,
        "expected_task_revision": request.task_revision,
        "idempotency_key": request.idempotency_key,
        "trace_refs": request.trace_refs,
        "set_name": format!("m2-{}-restart-proof", request.role),
        "set_role": request.role,
        "set_version": 1,
        "case_kind": "regression",
        "baseline_policy": request.baseline_policy,
        "candidate_policy": request.candidate_policy,
        "baseline_version": "baseline-v1",
        "candidate_version": "candidate-v1",
        "sealed_context_version": "context-v1",
        "evaluator_version": "canonical-replay-evaluator-v1"
    })
}

fn m2_meta_request(
    fixture: &M2MetaReplayFixture,
    project_id: &str,
    task_id: &str,
    idempotency_key: &str,
    eval_run_id: &str,
    attempted_fence: Option<Value>,
) -> Value {
    let mut request = json!({
        "project_id": project_id,
        "task_id": task_id,
        "expected_task_revision": fixture.task_revision,
        "idempotency_key": idempotency_key,
        "eval_run_id": eval_run_id,
        "change_class": "verification_map",
        "changed_variables": ["minimum_pass_basis_points"],
        "baseline_policy": fixture.baseline_policy,
        "candidate_policy": fixture.candidate_policy,
        "fixed_baseline_execution_id": fixture.fixed_baseline,
        "fixed_candidate_execution_id": fixture.fixed_candidate,
        "holdout_baseline_execution_id": fixture.holdout_baseline,
        "holdout_candidate_execution_id": fixture.holdout_candidate
    });
    if let Some(fence) = attempted_fence {
        request["attempted_fence"] = fence;
    }
    request
}

fn m2_replay_policies() -> (Value, Value) {
    (
        json!({
            "schema_version": "1",
            "evaluator_version": "canonical-replay-evaluator-v1",
            "minimum_pass_basis_points": 9000,
            "maximum_counter_regressions": 1
        }),
        json!({
            "schema_version": "1",
            "evaluator_version": "canonical-replay-evaluator-v1",
            "minimum_pass_basis_points": 10000,
            "maximum_counter_regressions": 0
        }),
    )
}

const M2_PROJECTION_NOISE_RECORDS: usize = 129;

fn operator_record_refs(page: &Value) -> TestResult<Vec<String>> {
    page["records"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("operator page records missing"))?
        .iter()
        .map(|record| {
            record["record_ref"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| std::io::Error::other("operator record_ref missing").into())
        })
        .collect()
}

fn seed_operator_cursor_records(project_id: &str, task_id: &str, count: usize) -> TestResult {
    let project_id = project_id.parse::<ProjectId>()?;
    let task_id = task_id.parse::<TaskId>()?;
    let write_id = WriteId::new_v7();
    let created_at = time::OffsetDateTime::now_utc();
    let observations = (0..count)
        .map(|index| {
            let body = OperatorControlRequest {
                request_id: format!("operator-cursor-request-{index:03}"),
                project_id,
                task_id,
                operation: "deny_approval".to_owned(),
                target_ref: format!("approval:operator-cursor-{index:03}"),
                disposition: "denied_test_fixture".to_owned(),
                exact_action_hash: None,
                reason_or_evidence_refs: vec!["isolated-cursor-restart-test".to_owned()],
                requested_by: "mcp_protocol".to_owned(),
                created_at,
                canonical_receipt: None,
            };
            eliot_types::ToolObservationInput {
                observation_id: format!("operator-cursor-record-{index:03}"),
                tool_name: "operator_cursor_restart_fixture".to_owned(),
                observation: "canonical operator cursor restart fixture".to_owned(),
                payload: json!({
                    "receipt_kind": "operator_control_request",
                    "receipt_body": body,
                    "writer_path": "mcp_protocol::seed_operator_cursor_records"
                }),
            }
        })
        .collect::<Vec<_>>();
    let input_hash = blake3::hash(&serde_json::to_vec(&observations)?)
        .to_hex()
        .to_string();
    let envelope = eliot_types::MemoryWriteEnvelope {
        write_id,
        operation_id: eliot_types::OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(task_id),
        command_kind: eliot_types::SemanticCommandKind::ToolObservationRecord,
        input_hash,
        policy_snapshot_id: Some("policy:operator-cursor-restart-fixture".to_owned()),
        project_sequence_hint: Some(eliot_types::ProjectSequence::new(2)),
        created_at,
        scope: "isolated-operator-cursor-restart".to_owned(),
        authority: "isolated-local-verified".to_owned(),
        task_contracts: Vec::new(),
        source_snapshots: Vec::new(),
        evidence_atoms: Vec::new(),
        tool_observations: observations,
        failures: Vec::new(),
        claims: Vec::new(),
        verification_runs: Vec::new(),
        relations: Vec::new(),
        lifecycle: eliot_types::LifecycleWriteOptions {
            status: LifecycleStatus::Active,
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
        },
        idempotency: eliot_types::IdempotencyOptions { allow_replay: true },
    };
    let mut config = eliot_types::GovernorConfig::default().db.surreal;
    config.endpoint = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT")?;
    config.bind = std::env::var("ELIOT_TEST_SURREAL_BIND")?;
    config.password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")?;
    config.storage = std::env::var("ELIOT_TEST_SURREAL_STORAGE")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let receipt = runtime.block_on(CanonicalStore::new(config).apply_write_envelope(&envelope))?;
    assert_eq!(receipt.status, eliot_types::WriteStatus::Committed);
    Ok(())
}

fn seed_m2_canonical_noise(
    project_id: &str,
    task_id: &str,
    receipt_kind: &str,
    template: &Value,
) -> TestResult {
    let project_id = project_id.parse::<eliot_types::ProjectId>()?;
    let task_id = task_id.parse::<eliot_types::TaskId>()?;
    let write_id = eliot_types::WriteId::new_v7();
    let observations = (0..M2_PROJECTION_NOISE_RECORDS)
        .map(|index| {
            let mut body = template.clone();
            rewrite_m2_noise_identity(&mut body, index);
            eliot_types::ToolObservationInput {
                observation_id: eliot_types::WriteId::new_v7().to_string(),
                tool_name: "m2_projection_noise_fixture".to_owned(),
                observation: format!("bounded {receipt_kind} projection noise {index}"),
                payload: json!({
                    "receipt_kind": receipt_kind,
                    "receipt_body": body,
                    "writer_path": "mcp_protocol::seed_m2_canonical_noise"
                }),
            }
        })
        .collect::<Vec<_>>();
    let input_hash = blake3::hash(&serde_json::to_vec(&observations)?)
        .to_hex()
        .to_string();
    let envelope = eliot_types::MemoryWriteEnvelope {
        write_id,
        operation_id: eliot_types::OperationId::new_v7(),
        agent_id: eliot_types::AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(task_id),
        command_kind: eliot_types::SemanticCommandKind::ToolObservationRecord,
        input_hash,
        policy_snapshot_id: Some("policy:m2-projection-saturation".to_owned()),
        project_sequence_hint: None,
        created_at: time::OffsetDateTime::now_utc(),
        scope: "isolated-m2-projection-saturation".to_owned(),
        authority: "isolated-local-verified".to_owned(),
        task_contracts: Vec::new(),
        source_snapshots: Vec::new(),
        evidence_atoms: Vec::new(),
        tool_observations: observations,
        failures: Vec::new(),
        claims: Vec::new(),
        verification_runs: Vec::new(),
        relations: Vec::new(),
        lifecycle: eliot_types::LifecycleWriteOptions {
            status: eliot_types::LifecycleStatus::Active,
            visibility: eliot_types::Visibility::Internal,
            taint: eliot_types::TaintClass::LocalVerified,
        },
        idempotency: eliot_types::IdempotencyOptions { allow_replay: true },
    };
    let mut config = eliot_types::GovernorConfig::default().db.surreal;
    config.endpoint = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT")?;
    config.bind = std::env::var("ELIOT_TEST_SURREAL_BIND")?;
    config.password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")?;
    config.storage = std::env::var("ELIOT_TEST_SURREAL_STORAGE")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let receipt = runtime
        .block_on(eliot_store::CanonicalStore::new(config).apply_write_envelope(&envelope))?;
    assert_eq!(receipt.status, eliot_types::WriteStatus::Committed);
    Ok(())
}

fn rewrite_m2_noise_identity(body: &mut Value, index: usize) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    let unique = format!("m2-noise-{index}-{}", uuid::Uuid::new_v4());
    for field in [
        "trace_ref",
        "execution_id",
        "candidate_id",
        "source_experiment_ref",
        "evidence_hash",
        "artifact_id",
        "rejection_id",
        "bundle_id",
        "sleep_run_id",
    ] {
        if object.contains_key(field) {
            object.insert(field.to_owned(), json!(unique));
        }
    }
    if object.contains_key("harness_experiment_record_id") {
        object.insert(
            "harness_experiment_record_id".to_owned(),
            json!(uuid::Uuid::new_v4().to_string()),
        );
    }
    if let Some(candidate) = object
        .get_mut("resulting_candidate")
        .and_then(Value::as_object_mut)
    {
        candidate.insert("candidate_id".to_owned(), json!(unique));
    }
}

fn seed_m2_projection_noise(
    client: &mut McpClient,
    fixture: &M2MetaReplayFixture,
    project_id: &str,
    task_id: &str,
) -> TestResult {
    let replay = client.tool_call(
        650,
        "eliot_replay_run",
        &m2_replay_request(M2ReplayRequest {
            project_id,
            task_id,
            task_revision: fixture.task_revision,
            idempotency_key: "m2-noise-replay-template",
            role: "fixed",
            trace_refs: &fixture.trace_refs,
            baseline_policy: &fixture.baseline_policy,
            candidate_policy: &fixture.candidate_policy,
        }),
    )?;
    let sleep = client.tool_call(
        651,
        "eliot_sleep_run",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "expected_task_revision": fixture.task_revision,
            "idempotency_key": "m2-noise-sleep-template",
            "trigger": "post_task",
            "dry_run": true,
            "trace_refs": fixture.trace_refs
        }),
    )?;
    let mut templates = vec![
        ("replay_set", replay["sealed_set"].clone()),
        ("replay_case", replay["cases"][0].clone()),
        ("replay_input_snapshot", replay["snapshots"][0].clone()),
        ("sealed_replay_run", replay["candidate_execution"].clone()),
        ("sleep_consolidation_bundle", sleep["bundle"].clone()),
    ];
    for artifact in sleep["artifacts"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("sleep noise artifacts missing"))?
    {
        let kind = match artifact["artifact_kind"].as_str() {
            Some("procedure") => "procedure_candidate",
            Some("forgetting_action") => "forgetting_candidate",
            Some("test") => "test_candidate",
            Some("replay_case") => "replay_case_candidate",
            Some("dream") => "dream_candidate",
            other => return Err(format!("unexpected sleep artifact kind: {other:?}").into()),
        };
        templates.push((kind, artifact.clone()));
    }
    let meta_template_project = uuid::Uuid::new_v4().to_string();
    let meta_template_task = uuid::Uuid::new_v4().to_string();
    let meta_template_fixture =
        seed_m2_meta_replay_fixture(client, &meta_template_project, &meta_template_task, 680)?;
    templates.extend(m2_meta_noise_templates(
        client,
        &meta_template_fixture,
        &meta_template_project,
        &meta_template_task,
    )?);
    for (kind, template) in templates {
        seed_m2_canonical_noise(project_id, task_id, kind, &template)?;
    }
    Ok(())
}

fn m2_meta_noise_templates(
    client: &mut McpClient,
    fixture: &M2MetaReplayFixture,
    project_id: &str,
    task_id: &str,
) -> TestResult<Vec<(&'static str, Value)>> {
    let safe = client.tool_call(
        652,
        "eliot_meta_experiment_run",
        &m2_meta_request(
            fixture,
            project_id,
            task_id,
            "m2-noise-meta-safe-template",
            &uuid::Uuid::new_v4().to_string(),
            None,
        ),
    )?;
    let experiment_id = required_test_string(&safe, "/experiment/harness_experiment_record_id")?;
    let experiment_revision = required_test_u64(&safe, "/experiment_revision")?;
    let promotion_hash = required_test_string(&safe, "/policy_candidate/promotion_action_hash")?;
    let promotion = client.tool_call(
        653,
        "eliot_meta_experiment_disposition",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "expected_task_revision": fixture.task_revision,
            "idempotency_key": "m2-noise-promotion-template",
            "experiment_id": experiment_id,
            "expected_experiment_revision": experiment_revision,
            "decision": "PROMOTED",
            "operator_command_ref": "operator:m2-noise-template",
            "expected_action_hash": promotion_hash
        }),
    )?;
    let rollback = client.tool_call(
        654,
        "eliot_meta_experiment_disposition",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "expected_task_revision": fixture.task_revision,
            "idempotency_key": "m2-noise-rollback-template",
            "experiment_id": experiment_id,
            "expected_experiment_revision": experiment_revision,
            "decision": "PROMOTED",
            "rollback_requested": true,
            "operator_command_ref": "operator:m2-noise-template",
            "expected_action_hash": promotion["rollback_action_hash"]
        }),
    )?;
    let rejected = client.tool_call(
        655,
        "eliot_meta_experiment_run",
        &m2_meta_request(
            fixture,
            project_id,
            task_id,
            "m2-noise-meta-rejected-template",
            &uuid::Uuid::new_v4().to_string(),
            Some(json!({
                "evaluator_version": "noise",
                "evaluator_hash": "noise",
                "threshold_version": "noise",
                "threshold_hash": "noise",
                "fixed_replay_set_hash": "noise",
                "holdout_replay_set_hash": "noise"
            })),
        ),
    )?;
    Ok(vec![
        ("harness_experiment", safe["experiment"].clone()),
        (
            "meta_metric_evidence",
            safe["assessment"]["records"]["metric_evidence"][0].clone(),
        ),
        (
            "experimental_policy_candidate",
            safe["policy_candidate"]["candidate"].clone(),
        ),
        (
            "meta_isolation_rejection",
            rejected["isolation_rejection"].clone(),
        ),
        ("meta_policy_promotion", promotion["promotion"].clone()),
        ("meta_policy_rollback", rollback["rollback"].clone()),
    ])
}

fn required_test_string(value: &Value, pointer: &str) -> TestResult<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing string {pointer} in {value}").into())
}

fn required_test_u64(value: &Value, pointer: &str) -> TestResult<u64> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing u64 {pointer} in {value}").into())
}

fn completion_proof_for_task_contract(task: &Value) -> TestResult<Value> {
    let task_id = required_test_string(task, "/task_id")?;
    let project_id = required_test_string(task, "/project_id")?;
    let goal = required_test_string(task, "/title")?;
    let changed_files = task
        .pointer("/action_provenance/source_scope/artifact_paths")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| std::io::Error::other("task action provenance artifact paths missing"))?;
    let task_items = task
        .pointer("/acceptance_items")
        .and_then(Value::as_array)
        .ok_or_else(|| std::io::Error::other("task acceptance items missing"))?;
    let scopes = task
        .pointer("/verification_scopes")
        .and_then(Value::as_array)
        .ok_or_else(|| std::io::Error::other("task verification scopes missing"))?;

    let mut acceptance_items = Vec::with_capacity(task_items.len());
    let mut checks_run = Vec::new();
    let mut evidence = Vec::new();
    for item in task_items {
        let item_id = required_test_string(item, "/item_id")?;
        let evidence_kind = required_test_string(item, "/required_evidence")?;
        match evidence_kind.as_str() {
            "observation" => {
                let observation_id = required_test_string(item, "/observation_id")?;
                evidence.push(Value::String(observation_id.clone()));
                acceptance_items.push(json!({
                    "item": item_id,
                    "status": "verified",
                    "evidence": observation_id,
                    "verifier": "canonical-observation",
                    "residual_uncertainty": "none"
                }));
            }
            "verification" => {
                let verification_id = required_test_string(item, "/verification_id")?;
                let scope = scopes
                    .iter()
                    .find(|scope| {
                        scope.get("verification_id").and_then(Value::as_str)
                            == Some(verification_id.as_str())
                    })
                    .ok_or_else(|| {
                        std::io::Error::other(format!(
                            "verification scope {verification_id} missing from task contract"
                        ))
                    })?;
                let verifier_id = required_test_string(scope, "/verifier_id")?;
                let scope_hash = required_test_string(scope, "/canonical_scope_hash")?;
                if !checks_run.contains(&verifier_id) {
                    checks_run.push(verifier_id.clone());
                }
                evidence.push(Value::String(format!("verification:{verification_id}")));
                evidence.push(Value::String(scope_hash));
                acceptance_items.push(json!({
                    "item": item_id,
                    "status": "verified",
                    "evidence": verification_id,
                    "verifier": verifier_id,
                    "residual_uncertainty": "none"
                }));
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "unsupported task acceptance evidence kind {other}"
                ))
                .into());
            }
        }
    }

    Ok(json!({
        "task_id": task_id,
        "project_id": project_id,
        "goal": goal,
        "changed_files": changed_files,
        "memory_refs_used": [],
        "checks_run": checks_run,
        "checks_not_run": [],
        "acceptance_items": acceptance_items,
        "evidence": evidence,
        "skill_refs": [],
        "skill_execution_proof_refs": [],
        "residual_uncertainty": "none",
        "known_risks": []
    }))
}

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

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn current_state_mcp_matches_cli() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = seed_with_writer_smoke()?;
    let cli = run_json(&["memory", "current-state", "--project", &project_id])?;
    let mut client = McpClient::start()?;
    let mcp = client.tool_call(
        2,
        "eliot_current_state",
        &json!({ "project_id": project_id, "scope": null, "at_least_revision": null }),
    )?;

    assert_eq!(mcp, cli);
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn current_state_memory_free_control_excludes_all_memory_content() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = seed_with_writer_smoke()?;
    let mut client = McpClient::start()?;
    let normal = client.tool_call(
        2,
        "eliot_current_state",
        &json!({ "project_id": project_id, "scope": "all_memory" }),
    )?;
    let normal_count = [
        "verified_now",
        "supported_now",
        "weak_or_candidate",
        "contested_now",
        "do_not_use",
        "recent_failures",
    ]
    .iter()
    .map(|field| {
        normal
            .get(field)
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    })
    .sum::<usize>();
    assert!(normal_count > 0);

    let control = client.tool_call(
        3,
        "eliot_current_state",
        &json!({ "project_id": project_id, "scope": "memory_free_control" }),
    )?;
    for field in [
        "verified_now",
        "supported_now",
        "weak_or_candidate",
        "contested_now",
        "do_not_use",
        "recent_failures",
    ] {
        assert!(
            control
                .get(field)
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        );
    }
    assert_eq!(
        control.pointer("/memory_view/mode").and_then(Value::as_str),
        Some("memory_free_control")
    );
    assert_eq!(
        control
            .pointer("/memory_view/memory_content_included")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        control
            .pointer("/memory_view/excluded_item_count")
            .and_then(Value::as_u64),
        Some(normal_count as u64)
    );
    assert_eq!(
        control.get("memory_revision"),
        normal.get("memory_revision")
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn recall_l0_mcp_matches_cli() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = seed_with_writer_smoke()?;
    let cli = run_json(&[
        "memory",
        "recall-l0",
        "--project",
        &project_id,
        "--query",
        "writer smoke",
    ])?;
    let mut client = McpClient::start()?;
    let mcp = client.tool_call(
        2,
        "eliot_recall_l0",
        &json!({ "project_id": project_id, "query": "writer smoke", "scope": null, "limit": 50 }),
    )?;

    assert_eq!(mcp, cli);
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn fetch_l2_mcp_matches_cli() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = seed_with_writer_smoke()?;
    let recall = run_json(&[
        "memory",
        "recall-l0",
        "--project",
        &project_id,
        "--query",
        "writer smoke",
    ])?;
    let handle = recall
        .get("handles")
        .and_then(Value::as_array)
        .and_then(|handles| handles.first())
        .and_then(|preview| preview.get("handle"))
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("writer smoke returned no handles"))?
        .to_owned();
    let cli = run_json(&[
        "memory",
        "fetch-l2",
        "--project",
        &project_id,
        "--handles",
        &handle,
    ])?;
    let mut client = McpClient::start()?;
    let mcp = client.tool_call(
        2,
        "eliot_fetch_l2",
        &json!({ "project_id": project_id, "handles": [handle], "at_least_revision": null }),
    )?;

    assert_eq!(mcp, cli);
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn mcp_compile_packet_and_gates_generate_reports() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = seed_with_writer_smoke()?;
    let mut client = McpClient::start()?;
    let packet = client.tool_call(
        2,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": "context-proof-mcp-report",
            "goal": "prove MCP report path",
            "candidate_handles": [],
            "max_tokens": 4000
        }),
    )?;
    let claim_ref = packet
        .get("relevant_verified_claims")
        .and_then(Value::as_array)
        .and_then(|claims| claims.first())
        .and_then(|claim| claim.get("claim_id"))
        .and_then(Value::as_str)
        .map(|claim_id| format!("claim:{claim_id}"))
        .ok_or_else(|| std::io::Error::other("packet has no verified claim"))?;
    let evidence_ref = packet
        .get("source_receipts")
        .and_then(Value::as_array)
        .and_then(|receipts| {
            receipts
                .iter()
                .filter_map(Value::as_str)
                .find(|receipt| receipt.starts_with("evidence:"))
        })
        .ok_or_else(|| std::io::Error::other("packet has no evidence receipt"))?
        .to_owned();

    let receipt = client.tool_call(
        3,
        "eliot_submit_understanding_proof",
        &json!({
            "task_id": "context-proof-mcp-report",
            "project_id": project_id,
            "goal": "prove MCP report path",
            "current_truth_refs": [claim_ref],
            "evidence_refs": [evidence_ref],
            "causal_bridge": "verified claim and evidence justify the action",
            "invariants": ["no raw SQL"],
            "negative_memory_checked": true,
            "unknowns": [],
            "planned_action": "edit governed Rust code with verifiers",
            "expected_verifiers": ["cargo test"],
            "risk_level": "low"
        }),
    )?;
    assert_eq!(receipt.get("accepted").and_then(Value::as_bool), Some(true));

    let cognitive = client.tool_call(
        4,
        "eliot_cognitive_gate",
        &json!({
            "receipt": receipt,
            "requested_action": "edit governed Rust code with verifiers"
        }),
    )?;
    assert_eq!(
        cognitive.get("decision").and_then(Value::as_str),
        Some("allow")
    );

    let completion = client.tool_call(
        5,
        "eliot_submit_completion_proof",
        &json!({
            "task_id": "context-proof-mcp-report",
            "project_id": project_id,
            "goal": "prove MCP report path",
            "changed_files": ["crates/eliot-app/src/mcp_stdio.rs"],
            "memory_refs_used": [],
            "checks_run": ["cargo test -p eliot-app --test mcp_protocol"],
            "checks_not_run": [],
            "acceptance_items": [{
                "item": "mcp reports generated",
                "status": "verified",
                "evidence": "MCP tool calls returned success",
                "verifier": "mcp_protocol",
                "residual_uncertainty": "none"
            }],
            "evidence": ["MCP compile/gate/completion calls succeeded"],
            "residual_uncertainty": "none",
            "known_risks": []
        }),
    )?;
    assert_eq!(
        completion.get("final_status").and_then(Value::as_str),
        Some("DONE_VERIFIED")
    );
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn codecortex_mcp_l3_and_gate_smoke() -> TestResult {
    let _guard = TestLock::acquire()?;
    let project_id = seed_with_writer_smoke()?;
    let mut client = McpClient::start()?;
    run_codecortex_scan(&mut client)?;
    let latest = client.tool_call(3, "eliot_codecortex_latest", &json!({}))?;
    let report_ref = codecortex_report_ref(&latest)?;
    let file_ref = codecortex_file_ref(&latest)?;

    assert_l3_packet_has_codecortex(&mut client, &project_id, &report_ref)?;
    assert_code_proof_blocks(&mut client, &project_id, &file_ref)?;
    assert_grounded_code_proof_read_only(&mut client, &project_id, &report_ref, &file_ref)?;
    Ok(())
}

fn run_codecortex_scan(client: &mut McpClient) -> TestResult {
    let scan = client.tool_call(
        2,
        "eliot_codecortex_scan",
        &json!({
            "project": "eliot-governor",
            "task": "cognitive-gate-mcp-smoke",
            "goal": "Find the MCP tools and cognitive gate implementation",
            "exact_patterns": ["eliot_cognitive_gate", "CognitiveGate", "governed_tool_names"],
            "max_files": 80,
            "max_matches_per_pattern": 16,
            "include_diagnostics": false
        }),
    )?;
    assert_eq!(
        scan.get("task").and_then(Value::as_str),
        Some("cognitive-gate-mcp-smoke")
    );
    assert!(
        scan.get("memory_receipt")
            .is_some_and(|value| !value.is_null())
    );
    Ok(())
}

fn assert_l3_packet_has_codecortex(
    client: &mut McpClient,
    project_id: &str,
    report_ref: &str,
) -> TestResult {
    let packet = client.tool_call(
        4,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": "cognitive-gate-mcp-l3",
            "goal": "Find the MCP tools and cognitive gate implementation",
            "candidate_handles": [],
            "max_tokens": 4000
        }),
    )?;
    let packet_refs = packet
        .get("codecortex")
        .and_then(|view| view.get("report_refs"))
        .and_then(Value::as_array)
        .ok_or_else(|| std::io::Error::other("packet missing CodeCortex refs"))?;
    assert!(
        packet_refs
            .iter()
            .any(|value| value.as_str() == Some(report_ref))
    );
    Ok(())
}

fn assert_code_proof_blocks(
    client: &mut McpClient,
    project_id: &str,
    file_ref: &str,
) -> TestResult {
    let blocked_receipt = submit_code_proof(client, project_id, &[], file_ref, "", false, 5)?;
    assert_eq!(
        blocked_receipt.get("accepted").and_then(Value::as_bool),
        Some(false)
    );
    let blocked_gate = client.tool_call(
        6,
        "eliot_cognitive_gate",
        &json!({
            "receipt": blocked_receipt,
            "requested_action": "inspect grounded code"
        }),
    )?;
    assert_eq!(
        blocked_gate.get("decision").and_then(Value::as_str),
        Some("block")
    );
    Ok(())
}

fn assert_grounded_code_proof_read_only(
    client: &mut McpClient,
    project_id: &str,
    report_ref: &str,
    file_ref: &str,
) -> TestResult {
    let grounded_receipt = submit_code_proof(
        client,
        project_id,
        &[report_ref],
        file_ref,
        "The report maps the goal to MCP stdio and CognitiveGate code.",
        true,
        7,
    )?;
    assert_eq!(
        grounded_receipt.get("accepted").and_then(Value::as_bool),
        Some(true)
    );
    let grounded_gate = client.tool_call(
        8,
        "eliot_cognitive_gate",
        &json!({
            "receipt": grounded_receipt,
            "requested_action": "inspect grounded code"
        }),
    )?;
    assert_eq!(
        grounded_gate.get("decision").and_then(Value::as_str),
        Some("allow_read_only")
    );
    Ok(())
}

fn submit_code_proof(
    client: &mut McpClient,
    project_id: &str,
    report_refs: &[&str],
    file_ref: &str,
    code_bridge: &str,
    blast_radius_acknowledged: bool,
    id: u64,
) -> TestResult<Value> {
    client.tool_call(
        id,
        "eliot_submit_understanding_proof",
        &json!({
            "task_id": "cognitive-gate-mcp-l3",
            "project_id": project_id,
            "goal": "Find the MCP tools and cognitive gate implementation",
            "code_task": true,
            "current_truth_refs": [],
            "evidence_refs": [],
            "codecortex_report_refs": report_refs,
            "files_to_change": [],
            "files_to_inspect": [file_ref],
            "causal_bridge": "CodeCortex grounding is the code evidence for this task",
            "causal_bridge_from_goal_to_code": code_bridge,
            "invariants": ["no raw tools"],
            "negative_memory_checked": true,
            "unknowns": [],
            "planned_action": "inspect grounded code",
            "expected_verifiers": ["cargo test"],
            "blast_radius_acknowledged": blast_radius_acknowledged,
            "risk_level": "low"
        }),
    )
}

struct McpClient {
    daemon: Option<Child>,
    child: Child,
    stdin: ChildStdin,
    stdout_lines: Receiver<Result<String, String>>,
    stdout_reader: Option<JoinHandle<()>>,
    workspace: PathBuf,
    agent_session_id: String,
}

#[derive(Clone, Debug)]
struct ScopedMcpSession {
    host: String,
    session_id: String,
    role_lease_id: String,
    task_id: String,
}

#[derive(Clone, Debug, Default)]
struct McpFailureInjection {
    sleep_after_secondaries: Option<usize>,
    replay_after_baseline_key: Option<String>,
    meta_after_experiment_primary_key: Option<String>,
    meta_after_action_key: Option<String>,
    managed_finalization_stage: Option<String>,
    managed_finalization_pause_after_authority_ms: Option<u64>,
}

fn mcp_child_command(
    profile: Option<&str>,
    failure: &McpFailureInjection,
    workspace: &Path,
    scoped: Option<&ScopedMcpSession>,
) -> Command {
    let mut command = Command::new(binary());
    command
        .current_dir(workspace)
        .arg("--config")
        .arg(test_config_path())
        .arg("mcp")
        .arg("stdio")
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .env("ELIOT_GOVERNOR_REPO_ROOT", repo_root());
    for variable in [
        "SURREAL_USER",
        "SURREAL_PASS",
        "ELIOT_TEST_SURREAL_BIND",
        "ELIOT_TEST_SURREAL_ENDPOINT",
        "ELIOT_TEST_SURREAL_PASSWORD_FILE",
        "ELIOT_TEST_SURREAL_STORAGE",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
    ] {
        command.env_remove(variable);
    }
    apply_m2_failure_environment(&mut command, failure);
    if let Some(scoped) = scoped {
        if profile != Some("codex_controller") {
            command.arg("--host").arg(&scoped.host);
        }
        command
            .env("ELIOT_AGENT_SESSION_ID", &scoped.session_id)
            .env("ELIOT_ROLE_LEASE_ID", &scoped.role_lease_id)
            .env("ELIOT_TASK_ID", &scoped.task_id);
    }
    if let Some(profile) = profile {
        command.arg("--profile").arg(profile);
    }
    command
}

impl McpClient {
    fn start() -> TestResult<Self> {
        Self::start_with_optional_profile(None)
    }

    fn start_with_profile(profile: &str) -> TestResult<Self> {
        Self::start_with_optional_profile(Some(profile))
    }

    fn start_with_optional_profile(profile: Option<&str>) -> TestResult<Self> {
        Self::start_with_options(profile, &McpFailureInjection::default())
    }

    fn start_with_sleep_failure_after(count: usize) -> TestResult<Self> {
        Self::start_with_options(
            None,
            &McpFailureInjection {
                sleep_after_secondaries: Some(count),
                ..McpFailureInjection::default()
            },
        )
    }

    fn start_with_replay_failure(key: &str) -> TestResult<Self> {
        Self::start_with_options(
            None,
            &McpFailureInjection {
                replay_after_baseline_key: Some(key.to_owned()),
                ..McpFailureInjection::default()
            },
        )
    }

    fn start_with_meta_experiment_failure(key: &str) -> TestResult<Self> {
        Self::start_with_options(
            None,
            &McpFailureInjection {
                meta_after_experiment_primary_key: Some(key.to_owned()),
                ..McpFailureInjection::default()
            },
        )
    }

    fn start_with_meta_action_failure(key: &str) -> TestResult<Self> {
        Self::start_with_options(
            None,
            &McpFailureInjection {
                meta_after_action_key: Some(key.to_owned()),
                ..McpFailureInjection::default()
            },
        )
    }

    fn start_with_options(
        profile: Option<&str>,
        failure: &McpFailureInjection,
    ) -> TestResult<Self> {
        Self::start_with_options_in_workspace(profile, failure, &repo_root())
    }

    fn start_in_workspace(workspace: &Path) -> TestResult<Self> {
        Self::start_with_options_in_workspace(None, &McpFailureInjection::default(), workspace)
    }

    fn start_with_options_in_workspace(
        profile: Option<&str>,
        failure: &McpFailureInjection,
        workspace: &Path,
    ) -> TestResult<Self> {
        let config_path = test_config_path();
        let previous_generation = ipc_auth_generation(&config_path);
        let mut daemon_command = Command::new(binary());
        daemon_command
            .current_dir(workspace)
            .arg("--config")
            .arg(&config_path)
            .arg("daemon")
            .arg("run")
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        apply_m2_failure_environment(&mut daemon_command, failure);
        let mut daemon = daemon_command.spawn()?;
        wait_for_ipc_auth_profile(&mut daemon, &config_path, previous_generation.as_deref())?;
        Self::start_mcp(profile, Some(daemon), failure, workspace, None)
    }

    fn connect_to_running() -> TestResult<Self> {
        Self::start_mcp(
            None,
            None,
            &McpFailureInjection::default(),
            &repo_root(),
            None,
        )
    }

    fn connect_to_running_with_profile_in_workspace(
        profile: &str,
        workspace: &Path,
    ) -> TestResult<Self> {
        Self::start_mcp(
            Some(profile),
            None,
            &McpFailureInjection::default(),
            workspace,
            None,
        )
    }

    fn connect_scoped(
        workspace: &Path,
        host: &str,
        session_id: &str,
        role_lease_id: &str,
        task_id: &str,
    ) -> TestResult<Self> {
        Self::start_mcp(
            None,
            None,
            &McpFailureInjection::default(),
            workspace,
            Some(&ScopedMcpSession {
                host: host.to_owned(),
                session_id: session_id.to_owned(),
                role_lease_id: role_lease_id.to_owned(),
                task_id: task_id.to_owned(),
            }),
        )
    }

    fn connect_scoped_controller(
        workspace: &Path,
        session_id: &str,
        role_lease_id: &str,
        task_id: &str,
    ) -> TestResult<Self> {
        Self::start_mcp(
            Some("codex_controller"),
            None,
            &McpFailureInjection::default(),
            workspace,
            Some(&ScopedMcpSession {
                host: "codex".to_owned(),
                session_id: session_id.to_owned(),
                role_lease_id: role_lease_id.to_owned(),
                task_id: task_id.to_owned(),
            }),
        )
    }

    fn start_scoped_with_finalization_pause_in_workspace(
        workspace: &Path,
        host: &str,
        session_id: &str,
        role_lease_id: &str,
        task_id: &str,
        pause_millis: u64,
    ) -> TestResult<Self> {
        let config_path = test_config_path();
        let previous_generation = ipc_auth_generation(&config_path);
        let failure = McpFailureInjection {
            managed_finalization_pause_after_authority_ms: Some(pause_millis),
            ..McpFailureInjection::default()
        };
        let mut daemon = Command::new(binary())
            .current_dir(workspace)
            .arg("--config")
            .arg(&config_path)
            .arg("daemon")
            .arg("run")
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .env(
                "ELIOT_TEST_MANAGED_FINALIZATION_PAUSE_AFTER_AUTHORITY_MS",
                pause_millis.to_string(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        wait_for_ipc_auth_profile(&mut daemon, &config_path, previous_generation.as_deref())?;
        Self::start_mcp(
            Some("codex_controller"),
            Some(daemon),
            &failure,
            workspace,
            Some(&ScopedMcpSession {
                host: host.to_owned(),
                session_id: session_id.to_owned(),
                role_lease_id: role_lease_id.to_owned(),
                task_id: task_id.to_owned(),
            }),
        )
    }

    fn start_scoped_in_workspace(
        workspace: &Path,
        host: &str,
        session_id: &str,
        role_lease_id: &str,
        task_id: &str,
    ) -> TestResult<Self> {
        let config_path = test_config_path();
        let previous_generation = ipc_auth_generation(&config_path);
        let mut daemon = Command::new(binary())
            .current_dir(workspace)
            .arg("--config")
            .arg(&config_path)
            .arg("daemon")
            .arg("run")
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        wait_for_ipc_auth_profile(&mut daemon, &config_path, previous_generation.as_deref())?;
        Self::start_mcp(
            Some("codex_controller"),
            Some(daemon),
            &McpFailureInjection::default(),
            workspace,
            Some(&ScopedMcpSession {
                host: host.to_owned(),
                session_id: session_id.to_owned(),
                role_lease_id: role_lease_id.to_owned(),
                task_id: task_id.to_owned(),
            }),
        )
    }

    fn start_scoped_with_failure_in_workspace(
        workspace: &Path,
        host: &str,
        session_id: &str,
        role_lease_id: &str,
        task_id: &str,
        stage: &str,
    ) -> TestResult<Self> {
        let config_path = test_config_path();
        let previous_generation = ipc_auth_generation(&config_path);
        let failure = McpFailureInjection {
            managed_finalization_stage: Some(stage.to_owned()),
            ..McpFailureInjection::default()
        };
        let mut daemon = Command::new(binary())
            .current_dir(workspace)
            .arg("--config")
            .arg(&config_path)
            .arg("daemon")
            .arg("run")
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .env("ELIOT_TEST_MANAGED_FINALIZATION_FAIL_AFTER", stage)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        wait_for_ipc_auth_profile(&mut daemon, &config_path, previous_generation.as_deref())?;
        Self::start_mcp(
            Some("codex_controller"),
            Some(daemon),
            &failure,
            workspace,
            Some(&ScopedMcpSession {
                host: host.to_owned(),
                session_id: session_id.to_owned(),
                role_lease_id: role_lease_id.to_owned(),
                task_id: task_id.to_owned(),
            }),
        )
    }

    fn start_mcp(
        profile: Option<&str>,
        daemon: Option<Child>,
        failure: &McpFailureInjection,
        workspace: &Path,
        scoped: Option<&ScopedMcpSession>,
    ) -> TestResult<Self> {
        let mut child = mcp_child_command(profile, failure, workspace, scoped)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| {
            std::io::Error::new(ErrorKind::BrokenPipe, "failed to open MCP stdin")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            std::io::Error::new(ErrorKind::BrokenPipe, "failed to open MCP stdout")
        })?;
        let (stdout_tx, stdout_rx) = mpsc::channel();
        let stdout_reader = thread::spawn(move || {
            let mut stdout = std::io::BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match stdout.read_line(&mut line) {
                    Ok(0) => {
                        let _ = stdout_tx.send(Err("MCP server closed stdout".to_owned()));
                        break;
                    }
                    Ok(_) => {
                        if stdout_tx.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = stdout_tx.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        let mut client = Self {
            daemon,
            child,
            stdin,
            stdout_lines: stdout_rx,
            stdout_reader: Some(stdout_reader),
            workspace: workspace.to_path_buf(),
            agent_session_id: String::new(),
        };
        let init = client.request(
            0,
            "initialize",
            &json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": scoped.map_or("context-proof-test", |scope| scope.host.as_str()),
                    "version": "0.1.0"
                }
            }),
        )?;
        if init
            .get("result")
            .and_then(|result| result.get("protocolVersion"))
            .and_then(Value::as_str)
            != Some("2025-06-18")
        {
            return Err(std::io::Error::other("MCP initialize failed").into());
        }
        client.agent_session_id = required_test_string(
            &init,
            "/result/experimental/eliotAgentSession/agent_session_id",
        )?;
        client.notify("notifications/initialized", &json!({}))?;
        Ok(client)
    }

    fn request(&mut self, id: u64, method: &str, params: &Value) -> TestResult<Value> {
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        serde_json::to_writer(&mut self.stdin, &message)?;
        writeln!(self.stdin)?;
        self.stdin.flush()?;

        let line = match self.stdout_lines.recv_timeout(Duration::from_mins(3)) {
            Ok(Ok(line)) => line,
            Ok(Err(message)) => {
                return Err(std::io::Error::new(ErrorKind::UnexpectedEof, message).into());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                kill_child_tree(&mut self.child);
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!("timed out waiting for MCP response to {method} request {id}"),
                )
                .into());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "MCP stdout reader stopped",
                )
                .into());
            }
        };
        let response: Value = serde_json::from_str(&line)?;
        if response.get("error").is_some() {
            return Err(std::io::Error::other(format!("MCP error response: {response}")).into());
        }
        Ok(response)
    }

    fn notify(&mut self, method: &str, params: &Value) -> TestResult {
        let message = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });
        serde_json::to_writer(&mut self.stdin, &message)?;
        writeln!(self.stdin)?;
        self.stdin.flush()?;
        Ok(())
    }

    fn tool_call(&mut self, id: u64, name: &str, arguments: &Value) -> TestResult<Value> {
        let response = self
            .request(
                id,
                "tools/call",
                &json!({ "name": name, "arguments": arguments }),
            )
            .map_err(|error| std::io::Error::other(format!("MCP tool {name} failed: {error}")))?;
        let result = response
            .get("result")
            .ok_or_else(|| std::io::Error::other("missing MCP tool result"))?;
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            return Err(std::io::Error::other(format!("MCP tool returned error: {result}")).into());
        }
        result
            .get("structuredContent")
            .cloned()
            .ok_or_else(|| std::io::Error::other("missing MCP structuredContent").into())
    }
}

fn apply_m2_failure_environment(command: &mut Command, failure: &McpFailureInjection) {
    if let Some(stage) = &failure.managed_finalization_stage {
        command.env("ELIOT_TEST_MANAGED_FINALIZATION_FAIL_AFTER", stage);
    }
    if let Some(millis) = failure.managed_finalization_pause_after_authority_ms {
        command.env(
            "ELIOT_TEST_MANAGED_FINALIZATION_PAUSE_AFTER_AUTHORITY_MS",
            millis.to_string(),
        );
    }
    if let Some(count) = failure.sleep_after_secondaries {
        command.env(
            "ELIOT_TEST_M2_SLEEP_FAIL_AFTER_SECONDARIES",
            count.to_string(),
        );
    }
    for (name, value) in [
        (
            "ELIOT_TEST_M2_REPLAY_FAIL_AFTER_BASELINE",
            failure.replay_after_baseline_key.as_deref(),
        ),
        (
            "ELIOT_TEST_M2_META_FAIL_AFTER_EXPERIMENT_PRIMARY",
            failure.meta_after_experiment_primary_key.as_deref(),
        ),
        (
            "ELIOT_TEST_M2_META_FAIL_AFTER_ACTION",
            failure.meta_after_action_key.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        kill_child_tree(&mut self.child);
        if let Some(daemon) = &mut self.daemon {
            let _ = Command::new(binary())
                .current_dir(&self.workspace)
                .arg("--config")
                .arg(test_config_path())
                .arg("daemon")
                .arg("stop")
                .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            kill_child_tree(daemon);
        }
        let _ = self.stdout_reader.take();
    }
}

fn test_config_path() -> PathBuf {
    std::env::var_os("ELIOT_GOVERNOR_CONFIG").map_or_else(
        || repo_root().join(".eliot-governor/config/governor.toml"),
        PathBuf::from,
    )
}

fn test_runtime_root() -> PathBuf {
    let config = test_config_path();
    let Some(root) = config.parent().and_then(Path::parent) else {
        panic!("test config must be under runtime/config");
    };
    root.to_path_buf()
}

fn ipc_auth_generation(config_path: &Path) -> Option<String> {
    let runtime_root = config_path.parent()?.parent()?;
    let profile: Value = serde_json::from_reader(
        fs::File::open(runtime_root.join("runtime").join("ipc-auth.json")).ok()?,
    )
    .ok()?;
    profile
        .get("token_generation_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn wait_for_ipc_auth_profile(
    daemon: &mut Child,
    config_path: &Path,
    previous_generation: Option<&str>,
) -> TestResult {
    let runtime_root = config_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("test config must be under runtime/config"))?;
    let auth_path = runtime_root.join("runtime").join("ipc-auth.json");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = daemon.try_wait()? {
            return Err(std::io::Error::other(format!(
                "Governor daemon exited before IPC authentication was ready: {status}"
            ))
            .into());
        }
        if let Ok(file) = fs::File::open(&auth_path)
            && let Ok(profile) = serde_json::from_reader::<_, Value>(file)
            && profile
                .get("protocol_version")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            && profile
                .get("pipe_name")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            && profile
                .get("token")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            && profile
                .get("token_generation_id")
                .and_then(Value::as_str)
                .is_some_and(|value| Some(value) != previous_generation)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "timed out waiting for Governor IPC authentication profile at {}",
                    auth_path.display()
                ),
            )
            .into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn kill_child_tree(child: &mut Child) {
    let pid = child.id();
    if cfg!(windows) {
        let _ = Command::new("taskkill")
            .arg("/PID")
            .arg(pid.to_string())
            .arg("/T")
            .arg("/F")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    } else {
        let _ = child.kill();
    }
    let _ = child.kill();
    let _ = child.wait();
}

struct TestLock {
    lock_path: PathBuf,
    file: Option<std::fs::File>,
}

impl TestLock {
    fn acquire() -> TestResult<Self> {
        let lock_path = test_runtime_root()
            .join("tmp")
            .join("eliot-governor-shared-db-test.lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let started = Instant::now();
        let timeout = Duration::from_mins(10);
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(file) => {
                    return Ok(Self {
                        lock_path,
                        file: Some(file),
                    });
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::AlreadyExists | ErrorKind::PermissionDenied
                    ) =>
                {
                    if started.elapsed() >= timeout {
                        return Err(std::io::Error::new(
                            ErrorKind::TimedOut,
                            format!(
                                "timed out waiting for shared DB test lock at {}",
                                lock_path.display()
                            ),
                        )
                        .into());
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Drop for TestLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn tool_names(response: &Value) -> TestResult<Vec<String>> {
    let tools = response
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
        .ok_or_else(|| std::io::Error::other("missing tools list"))?;
    Ok(tools
        .iter()
        .filter_map(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect())
}

fn seed_with_writer_smoke() -> TestResult<String> {
    let output = run_json(&["writer", "smoke"])?;
    output
        .get("project_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| std::io::Error::other("writer smoke returned no project_id").into())
}

fn run_json(args: &[&str]) -> TestResult<Value> {
    let output = Command::new(binary())
        .current_dir(repo_root())
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "command {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn codecortex_report_ref(report: &Value) -> TestResult<String> {
    let task = report
        .get("task")
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("CodeCortex report missing task"))?;
    let git_head = report
        .get("git_head")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let dirty_state_hash = report
        .get("scope_binding")
        .and_then(|binding| binding.get("dirty_state_hash"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Ok(format!(
        "codecortex_report:{task}:{git_head}:{dirty_state_hash}"
    ))
}

fn codecortex_file_ref(report: &Value) -> TestResult<String> {
    for key in ["file_evidence", "tracked_files"] {
        if let Some(path) = report
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|evidence| evidence.get("path").and_then(Value::as_str))
            .find(|path| {
                matches!(
                    *path,
                    "crates/eliot-app/src/mcp_stdio.rs" | "crates/eliot-engine/src/context.rs"
                )
            })
        {
            return Ok(path.to_owned());
        }
    }
    Err(std::io::Error::other("CodeCortex report missing expected code file").into())
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_eliot-governor"))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
