#![allow(clippy::expect_used)]
use super::*;

#[test]
fn inherited_database_credentials_are_rejected_by_name_only() {
    let safe = ["PATH", "SURREAL_USER", "ELIOT_AGENT_SESSION_ID"]
        .into_iter()
        .map(std::ffi::OsString::from);
    assert_eq!(inherited_database_credential_variable(safe), None);

    for forbidden in [
        "SURREAL_PASS",
        "surreal_token",
        "ELIOT_DB_PASSWORD",
        "eliot_db_token",
    ] {
        assert_eq!(
            inherited_database_credential_variable([std::ffi::OsString::from(forbidden)]),
            Some(forbidden.to_owned())
        );
    }
}

fn exact_plan_fixture() -> Vec<CognitiveRunCallPlan> {
    expected_cognitive_plan()
        .into_iter()
        .enumerate()
        .map(|(index, (call_id, host, role, variant, flow, gated))| {
            let expected_truth_revision = format!("fixture-revision-{}", index + 1);
            let expected_exposure_handles = if gated {
                vec![format!("claim:reciprocal-{}", index + 1)]
            } else if role == CognitiveInvocationRole::Target && variant == "treatment" {
                vec![format!("memory:fixture-{}", index + 1)]
            } else {
                Vec::new()
            };
            let exposure_sha256 = sha256_json(&CognitiveExposureProjection {
                revision: &expected_truth_revision,
                handles: &expected_exposure_handles,
            })
            .expect("fixture exposure serializes");
            CognitiveRunCallPlan {
                call_number: u8::try_from(index + 1).expect("fixture call fits u8"),
                call_id: call_id.to_owned(),
                case_id: call_id[..5].trim_end_matches('-').to_owned(),
                host,
                model: format!("fixture-{}", host.as_str()),
                invocation_role: role,
                variant: variant.to_owned(),
                reciprocal_flow_id: flow.map(str::to_owned),
                requires_shared_gate: gated,
                candidate_write_id: (role == CognitiveInvocationRole::SourceWrite)
                    .then(|| WriteId::from_uuid(uuid::Uuid::from_u128((index + 1) as u128))),
                candidate_body_sha256: (role == CognitiveInvocationRole::SourceWrite)
                    .then(|| "44".repeat(32)),
                prompt_sha256: "11".repeat(32),
                expected_provider_bundle_sha256: "22".repeat(32),
                expected_truth_revision,
                expected_exposure_handles,
                exposure_sha256,
                expected_output_schema_sha256: "33".repeat(32),
            }
        })
        .collect()
}

#[test]
fn exact_provider_order_and_gate_contract_are_accepted() -> Result<()> {
    let plan = exact_plan_fixture();
    validate_cognitive_plan(&plan)?;
    assert_eq!(plan[4].call_id, "LC-01-source-opencode");
    assert_eq!(plan[6].call_id, "LC-02-source-antigravity");
    assert_eq!(plan[16].call_id, "LC-01-target-antigravity-treatment");
    assert_eq!(plan[17].call_id, "LC-02-target-opencode-treatment");
    assert!(plan[16..].iter().all(|call| call.requires_shared_gate));
    assert!(plan[..16].iter().all(|call| !call.requires_shared_gate));
    Ok(())
}

#[test]
fn plan_rejects_array_order_flow_and_gate_drift() {
    let mut reordered = exact_plan_fixture();
    reordered.swap(4, 16);
    assert!(validate_cognitive_plan(&reordered).is_err());

    let mut wrong_flow = exact_plan_fixture();
    wrong_flow[4].reciprocal_flow_id = Some("LC-01".to_owned());
    assert!(validate_cognitive_plan(&wrong_flow).is_err());

    let mut premature_gate = exact_plan_fixture();
    premature_gate[15].requires_shared_gate = true;
    assert!(validate_cognitive_plan(&premature_gate).is_err());

    let mut empty_target = exact_plan_fixture();
    let target = empty_target
        .iter_mut()
        .find(|call| call.invocation_role == CognitiveInvocationRole::Target)
        .expect("fixture has a target call");
    target.expected_exposure_handles.clear();
    target.exposure_sha256 = cognitive_exposure_sha256(target).expect("exposure hashes");
    assert!(validate_cognitive_plan(&empty_target).is_err());
}

#[test]
fn contract_hash_excludes_only_its_own_field() -> Result<()> {
    let mut contract = CognitiveRunContract {
        schema_version: COGNITIVE_RUN_SCHEMA_VERSION.to_owned(),
        harness_version: "phase-l10-l12-m6-v2".to_owned(),
        instance_name: "default".to_owned(),
        run_id: "fixture-run".to_owned(),
        project_id: ProjectId::new_v7(),
        task_id: TaskId::new_v7(),
        governor_nonce: uuid::Uuid::new_v4(),
        harness_script_sha256: "44".repeat(32),
        cases_sha256: "55".repeat(32),
        exposure_map_sha256: "66".repeat(32),
        output_contract_sha256: "77".repeat(32),
        models_sha256: "88".repeat(32),
        source_commit: "11".repeat(20),
        policy_snapshot_id: "99".repeat(32),
        output_root: "C:/Profiles/fixture/AppData/Local/Eliot/cognitive/fixture-run".to_owned(),
        timeout_seconds: 300,
        exact_plan: exact_plan_fixture(),
        hard_provider_call_cap: 18,
        contract_sha256: String::new(),
        sealed_at: time::OffsetDateTime::UNIX_EPOCH,
    };
    let expected = sha256_json(&contract)?;
    contract.contract_sha256.clone_from(&expected);
    let mut projection = contract.clone();
    projection.contract_sha256.clear();
    assert_eq!(sha256_json(&projection)?, expected);
    contract.cases_sha256 = "99".repeat(32);
    contract.contract_sha256.clear();
    assert_ne!(sha256_json(&contract)?, expected);
    Ok(())
}

#[test]
fn cognitive_seal_rejects_source_commit_and_policy_drift() -> Result<()> {
    let mut input = CognitiveSealInput {
        harness_version: "phase-l13-bounded-v1".to_owned(),
        instance_name: "default".to_owned(),
        run_id: "fixture-source-binding".to_owned(),
        project_id: ProjectId::new_v7(),
        task_id: TaskId::new_v7(),
        harness_script_sha256: "11".repeat(32),
        cases_sha256: "22".repeat(32),
        exposure_map_sha256: "33".repeat(32),
        output_contract_sha256: "44".repeat(32),
        models_sha256: "55".repeat(32),
        source_commit: BUILD_SOURCE_COMMIT.to_owned(),
        policy_snapshot_id: String::new(),
        output_root: "C:/fixture/l13".to_owned(),
        timeout_seconds: 30,
        exact_plan: exact_plan_fixture(),
    };
    input.policy_snapshot_id = cognitive_policy_snapshot_id(&input)?;
    validate_cognitive_source_binding(&input)?;

    let expected_policy = input.policy_snapshot_id.clone();
    input.source_commit = "f".repeat(40);
    assert!(validate_cognitive_source_binding(&input).is_err());

    input.source_commit = BUILD_SOURCE_COMMIT.to_owned();
    input.policy_snapshot_id = "a".repeat(64);
    assert!(validate_cognitive_source_binding(&input).is_err());
    input.policy_snapshot_id = expected_policy;
    validate_cognitive_source_binding(&input)
}

#[test]
fn cognitive_roles_fail_closed_even_when_hidden_tool_names_are_called_directly() {
    assert!(tool_definitions_for_profile(McpAccessProfile::CognitiveControl).is_empty());
    for role in [
        CognitiveInvocationRole::Control,
        CognitiveInvocationRole::Target,
        CognitiveInvocationRole::SourceWrite,
    ] {
        assert!(cognitive_role_allows(role, "eliot_cognitive_job_fetch"));
    }
    assert!(cognitive_role_allows(
        CognitiveInvocationRole::SourceWrite,
        "eliot_agent_candidate_submit"
    ));
    assert!(!cognitive_role_allows(
        CognitiveInvocationRole::SourceWrite,
        "eliot_recall_l0"
    ));
    assert!(cognitive_role_allows(
        CognitiveInvocationRole::Target,
        "eliot_recall_l0"
    ));
    assert!(cognitive_role_allows(
        CognitiveInvocationRole::Target,
        "eliot_fetch_l2"
    ));
    assert!(!cognitive_role_allows(
        CognitiveInvocationRole::Target,
        "eliot_agent_candidate_submit"
    ));
    assert!(!cognitive_role_allows(
        CognitiveInvocationRole::Control,
        "eliot_recall_l0"
    ));
}

#[test]
fn stdio_facade_rejects_inherited_database_credentials_by_name_only() {
    let forbidden = inherited_database_credential_variable([
        std::ffi::OsString::from("Path"),
        std::ffi::OsString::from("surreal_pass"),
    ]);
    assert_eq!(forbidden.as_deref(), Some("surreal_pass"));
    assert!(inherited_database_credential_variable([std::ffi::OsString::from("Path")]).is_none());
}

fn db_execution(call: &CognitiveRunCallPlan) -> Result<CognitiveExecutionSeal> {
    Ok(CognitiveExecutionSeal {
        executable_sha256: sha256_json(&(call.call_number, "runner"))?,
        provider_executable_sha256: sha256_json(&(call.host, "provider"))?,
        argv_sha256: sha256_json(&(call.call_number, "argv"))?,
        environment_sha256: sha256_json(&(call.call_number, "environment"))?,
        cwd_sha256: sha256_json(&(call.call_number, "cwd"))?,
        bundle_sha256: call.expected_provider_bundle_sha256.clone(),
        prompt_sha256: call.prompt_sha256.clone(),
    })
}

fn db_job_packet(run_id: &str, call_number: u8) -> String {
    format!("sealed database cognitive job {run_id} call {call_number}")
}

fn db_plan(
    run_id: &str,
    project_id: ProjectId,
    task_id: TaskId,
    preexisting_handle: &str,
) -> Result<(
    Vec<CognitiveRunCallPlan>,
    std::collections::BTreeMap<u8, Value>,
)> {
    let mut plan = exact_plan_fixture();
    let mut candidates = std::collections::BTreeMap::new();
    for call_number in [5_u8, 7_u8] {
        let write_id = WriteId::new_v7();
        let body = json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": write_id,
            "topic": format!("reciprocal-db-source-{call_number}"),
            "statement": format!("unique reciprocal database statement {run_id} call {call_number}"),
            "where_applicable": ["isolated cognitive integration test"],
            "where_not_applicable": [],
            "negative_constraints": [],
            "provenance_refs": [format!("provider:test:{run_id}:{call_number}")],
            "freshness_rule": "valid only for this sealed isolated test run"
        });
        let call = &mut plan[usize::from(call_number - 1)];
        call.candidate_write_id = Some(write_id);
        call.candidate_body_sha256 = Some(sha256_json(&body)?);
        candidates.insert(call_number, body);
    }
    let first_handle = plan[4]
        .candidate_write_id
        .context("call 5 candidate write id")?
        .to_string();
    let second_handle = plan[6]
        .candidate_write_id
        .context("call 7 candidate write id")?
        .to_string();
    for call in &mut plan {
        call.prompt_sha256 = sha256_bytes(db_job_packet(run_id, call.call_number).as_bytes());
        call.expected_provider_bundle_sha256 =
            sha256_json(&(run_id, call.host, "provider-authority-bundle"))?;
        call.expected_truth_revision = format!("{run_id}:truth:call-{}", call.call_number);
        call.expected_exposure_handles = if call.call_number == 18 {
            vec![second_handle.clone()]
        } else if call.invocation_role == CognitiveInvocationRole::Target && call.call_number >= 6 {
            vec![first_handle.clone()]
        } else if call.invocation_role == CognitiveInvocationRole::Target {
            vec![preexisting_handle.to_owned()]
        } else {
            Vec::new()
        };
        call.exposure_sha256 = cognitive_exposure_sha256(call)?;
        call.expected_output_schema_sha256 = sha256_json(&(run_id, "output-schema"))?;
    }
    validate_cognitive_plan(&plan)?;
    Ok((plan, candidates))
}

async fn db_begin(
    state: &McpState,
    context: AuthenticatedRequestContext,
    run_id: &str,
    project_id: ProjectId,
    task_id: TaskId,
    call: &CognitiveRunCallPlan,
    gate: Option<&CognitiveSharedGateBinding>,
) -> Result<Value> {
    cognitive_run_begin(
        state,
        context,
        json!({
            "run_id": run_id,
            "project_id": project_id,
            "task_id": task_id,
            "call_number": call.call_number,
            "execution": db_execution(call)?,
            "job_packet": db_job_packet(run_id, call.call_number),
            "shared_gate": gate,
        }),
    )
    .await
}

fn db_host_observation(
    call: &CognitiveRunCallPlan,
    begin: &Value,
) -> Result<CognitiveHostObservation> {
    let governor_session_id = begin
        .pointer("/attempt/capability/session_id")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    Ok(CognitiveHostObservation {
        observation_version: "eliot-cognitive-host-observation-v1".to_owned(),
        governor_session_id,
        vendor_session_id: Some(format!("db-session-{}", call.call_number)),
        host: call.host,
        observed_model: Some(call.model.clone()),
        outer_protocol_sha256: sha256_json(&(call.call_number, "host-native-outer-protocol"))?,
    })
}

#[allow(
    clippy::if_not_else,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
async fn db_drive_successful_call(
    daemon: &McpDaemon,
    governor_context: AuthenticatedRequestContext,
    run_id: &str,
    project_id: ProjectId,
    task_id: TaskId,
    call: &CognitiveRunCallPlan,
    candidate_body: Option<&Value>,
    begin: &Value,
) -> Result<(WriteReceiptRef, Option<WriteReceiptRef>)> {
    let mut candidate_receipt = None;
    let capability_path: PathBuf = serde_json::from_value(
        begin
            .get("capability_file")
            .cloned()
            .context("begin response has no capability file")?,
    )?;
    let capability_file = read_cognitive_capability_file(&capability_path)?;
    let child_session = daemon
        .authenticate_cognitive_child(&capability_path, &capability_file.capability_token)
        .await?;
    let definitions = cognitive_tool_definitions(&daemon.cognitive_child, child_session)
        .await?
        .into_iter()
        .filter_map(|definition| {
            definition
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    let child_context = AuthenticatedRequestContext {
        session_id: child_session,
        bound_project_id: None,
        bound_task_id: None,
    };
    let fetched = call_tool(
        &daemon.cognitive_child,
        child_context,
        json!({
            "name": "eliot_cognitive_job_fetch",
            "arguments": { "call_id": call.call_id }
        }),
    )
    .await?;
    assert_eq!(
        fetched
            .pointer("/structuredContent/packet")
            .and_then(Value::as_str),
        Some(db_job_packet(run_id, call.call_number).as_str())
    );
    match call.invocation_role {
        CognitiveInvocationRole::Target => {
            assert_eq!(
                definitions,
                vec![
                    "eliot_cognitive_job_fetch",
                    "eliot_recall_l0",
                    "eliot_fetch_l2"
                ]
            );
            let query = candidate_body
                .and_then(|body| body.get("statement"))
                .and_then(Value::as_str)
                .or_else(|| call.expected_exposure_handles.first().map(String::as_str))
                .map_or_else(
                    || format!("unmatched-db-token-{run_id}-{}", call.call_number),
                    str::to_owned,
                );
            let recall = call_tool(
                &daemon.cognitive_child,
                child_context,
                json!({
                    "name": "eliot_recall_l0",
                    "arguments": {
                        "project_id": project_id,
                        "query": query,
                        "scope": "cognitive-db-test",
                        "limit": 1
                    }
                }),
            )
            .await?;
            let returned = recall
                .pointer("/structuredContent/handles")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|item| item.get("handle").and_then(Value::as_str))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert_eq!(
                returned, call.expected_exposure_handles,
                "cognitive recall response: {recall}"
            );
            if !call.expected_exposure_handles.is_empty() {
                let _ = call_tool(
                    &daemon.cognitive_child,
                    child_context,
                    json!({
                        "name": "eliot_fetch_l2",
                        "arguments": {
                            "project_id": project_id,
                            "handles": call.expected_exposure_handles,
                            "at_least_revision": null
                        }
                    }),
                )
                .await?;
            }
        }
        CognitiveInvocationRole::SourceWrite => {
            assert_eq!(
                definitions,
                vec!["eliot_cognitive_job_fetch", "eliot_agent_candidate_submit"]
            );
            let result = call_tool(
                &daemon.cognitive_child,
                child_context,
                json!({
                    "name": "eliot_agent_candidate_submit",
                    "arguments": candidate_body.context("source call has no candidate body")?
                }),
            )
            .await?;
            let receipt: WriteReceiptRef = serde_json::from_value(
                result
                    .pointer("/structuredContent/write_receipt")
                    .cloned()
                    .context("candidate tool response has no receipt")?,
            )?;
            candidate_receipt = Some(receipt);
        }
        CognitiveInvocationRole::Control => {
            assert_eq!(definitions, vec!["eliot_cognitive_job_fetch"]);
        }
    }

    let raw_verifier = (call.call_number <= COGNITIVE_RUN_RAW_VERIFIER_CALLS_U8).then(|| {
        json!({
            "verifier_version": "db-backed-canonical-verifier-v1",
            "checks_sha256": sha256_json(&(run_id, call.call_number, "checks"))
                .expect("checks hash serializes"),
            "passed": false
        })
    });
    let terminal = cognitive_run_terminal(
        &daemon.cognitive_governor,
        governor_context,
        json!({
            "run_id": run_id,
            "project_id": project_id,
            "task_id": task_id,
            "call_number": call.call_number,
            "status": "succeeded",
            "execution": db_execution(call)?,
            "process_sha256": sha256_json(&(run_id, call.call_number, "process"))?,
            "stdout_sha256": sha256_json(&(run_id, call.call_number, "stdout"))?,
            "stderr_sha256": sha256_json(&(run_id, call.call_number, "stderr"))?,
            "provider_output_sha256": sha256_json(&(run_id, call.call_number, "provider-output"))?,
            "candidate_receipt": candidate_receipt,
            "host_observation": db_host_observation(call, begin)?,
            "raw_verifier": raw_verifier,
            "reason": "isolated DB-backed successful terminal"
        }),
    )
    .await?;
    let terminal_receipt = serde_json::from_value(
        terminal
            .get("canonical_receipt")
            .cloned()
            .context("terminal response has no receipt")?,
    )?;
    Ok((terminal_receipt, candidate_receipt))
}

async fn db_promote_candidate(
    daemon: &McpDaemon,
    operator_context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    candidate: &Value,
    call_number: u8,
    run_id: &str,
) -> Result<WriteReceiptRef> {
    let task = daemon
        .human_operator
        .store
        .task_contract_by_id(task_id)
        .await?
        .context("DB test task disappeared")?;
    let write_id: WriteId = serde_json::from_value(
        candidate
            .get("write_id")
            .cloned()
            .context("candidate has no write id")?,
    )?;
    let stored_candidate = daemon
        .human_operator
        .store
        .claim_card_by_id(project_id, ClaimId::from_uuid(write_id.as_uuid()))
        .await?
        .context("candidate claim disappeared before operator review")?;
    let evidence_refs = stored_candidate
        .payload
        .get("provenance_refs")
        .and_then(Value::as_array)
        .context("stored candidate has no provenance")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let result = dispatch_operator_command(
        &daemon.human_operator,
        operator_context,
        json!({
            "project_id": project_id,
            "task_id": task_id,
            "expected_revision": task.memory_revision,
            "idempotency_key": format!("db-promote-{run_id}-{call_number}"),
            "command": {
                "command": "review_candidate",
                "task_id": task_id,
                "candidate_ref": format!("claim:{write_id}"),
                "disposition": "promote",
                "evidence_refs": evidence_refs
            }
        }),
    )
    .await?;
    serde_json::from_value(
        result
            .get("canonical_receipt")
            .cloned()
            .context("promotion response has no receipt")?,
    )
    .map_err(Into::into)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn db_assert_observation_saturation_rejected(
    daemon: &McpDaemon,
    governor_context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    seed_handle: &str,
) -> Result<()> {
    let run_id = format!("db-cognitive-saturation-{}", uuid::Uuid::new_v4());
    let (plan, _) = db_plan(&run_id, project_id, task_id, seed_handle)?;
    let harness_script_sha256 = sha256_json(&"db-harness")?;
    let cases_sha256 = sha256_json(&"db-cases")?;
    let exposure_map_sha256 = sha256_json(&"db-exposure-map")?;
    let output_contract_sha256 = sha256_json(&"db-output-contract")?;
    let models_sha256 = sha256_json(&"db-models")?;
    let policy_snapshot_id = sha256_json(&(
        "db-backed-m6-v1",
        &harness_script_sha256,
        &cases_sha256,
        &exposure_map_sha256,
        &output_contract_sha256,
        &models_sha256,
        BUILD_SOURCE_COMMIT,
    ))?;
    let _ = cognitive_run_seal(
        &daemon.cognitive_governor,
        governor_context,
        json!({
            "harness_version": "db-backed-m6-v1",
            "instance_name": daemon.cognitive_governor.instance_name,
            "run_id": run_id,
            "project_id": project_id,
            "task_id": task_id,
            "harness_script_sha256": harness_script_sha256,
            "cases_sha256": cases_sha256,
            "exposure_map_sha256": exposure_map_sha256,
            "output_contract_sha256": output_contract_sha256,
            "models_sha256": models_sha256,
            "source_commit": BUILD_SOURCE_COMMIT,
            "policy_snapshot_id": policy_snapshot_id,
            "output_root": format!("C:/eliot-db-tests/{run_id}"),
            "timeout_seconds": 30,
            "exact_plan": plan,
        }),
    )
    .await?;
    let call = &plan[0];
    let begin = db_begin(
        &daemon.cognitive_governor,
        governor_context,
        &run_id,
        project_id,
        task_id,
        call,
        None,
    )
    .await?;
    let attempt_receipt: WriteReceiptRef = serde_json::from_value(
        begin
            .get("canonical_receipt")
            .cloned()
            .context("saturation begin has no receipt")?,
    )?;
    let capability_path: PathBuf = serde_json::from_value(
        begin
            .get("capability_file")
            .cloned()
            .context("saturation begin has no capability")?,
    )?;
    let capability_file = read_cognitive_capability_file(&capability_path)?;
    let call_subject_ref = cognitive_tool_observation_subject(&run_id, call.call_number);
    let repeated_arguments = json!({"identical": true});
    let repeated_result = json!({"error": "denied-first-saturation"});
    for index in 0..COGNITIVE_TOOL_OBSERVATION_MAX {
        let observation = CognitiveToolObservation {
            schema_version: COGNITIVE_RUN_SCHEMA_VERSION.to_owned(),
            run_id: run_id.clone(),
            call_subject_ref: call_subject_ref.clone(),
            observation_id: uuid::Uuid::now_v7().to_string(),
            call_id: call.call_id.clone(),
            call_number: call.call_number,
            project_id,
            task_id,
            session_id: capability_file.capability.session_id,
            host: call.host,
            attempt_receipt: attempt_receipt.clone(),
            tool_name: "eliot_agent_candidate_submit".to_owned(),
            outcome: "denied".to_owned(),
            sealed_truth_revision: call.expected_truth_revision.clone(),
            observed_memory_revision: None,
            arguments_sha256: sha256_json(&repeated_arguments)?,
            result_sha256: sha256_json(&repeated_result)?,
            requested_handles: Vec::new(),
            returned_handles: Vec::new(),
            observed_at: time::OffsetDateTime::now_utc(),
        };
        let _ = write_canonical_observation(
            &daemon.cognitive_governor,
            governor_context,
            project_id,
            Some(task_id),
            CanonicalReceiptKind::CognitiveToolObservation,
            &format!("db-saturation-{run_id}-{index}"),
            &observation,
        )
        .await?;
    }
    let saturated_records = daemon
        .cognitive_governor
        .store
        .canonical_records_by_subject_ref::<CognitiveToolObservation>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::CognitiveToolObservation.as_str()],
            &call_subject_ref,
            COGNITIVE_TOOL_OBSERVATION_QUERY_LIMIT,
        )
        .await?;
    assert_eq!(saturated_records.len(), COGNITIVE_TOOL_OBSERVATION_MAX);
    assert!(saturated_records.iter().all(|record| {
        record.receipt_body.outcome == "denied"
            && record.receipt_body.arguments_sha256
                == sha256_json(&repeated_arguments).expect("repeated arguments hash")
            && record.receipt_body.result_sha256
                == sha256_json(&repeated_result).expect("repeated result hash")
    }));
    assert_eq!(
        saturated_records
            .iter()
            .map(|record| record.receipt_body.observation_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        COGNITIVE_TOOL_OBSERVATION_MAX
    );
    let child_session = daemon
        .authenticate_cognitive_child(&capability_path, &capability_file.capability_token)
        .await?;
    assert!(
        call_tool(
            &daemon.cognitive_child,
            AuthenticatedRequestContext {
                session_id: child_session,
                bound_project_id: None,
                bound_task_id: None,
            },
            json!({"name": "eliot_agent_candidate_submit", "arguments": {}}),
        )
        .await
        .is_err()
    );
    assert!(
        cognitive_run_terminal(
            &daemon.cognitive_governor,
            governor_context,
            json!({
                "run_id": run_id,
                "project_id": project_id,
                "task_id": task_id,
                "call_number": call.call_number,
                "status": "unknown_outcome",
                "execution": db_execution(call)?,
                "host_observation": db_host_observation(call, &begin)?,
                "raw_verifier": {
                    "verifier_version": "db-saturation-v1",
                    "checks_sha256": sha256_json(&"db-saturation")?,
                    "passed": false
                },
                "reason": "canonical observation saturation must fail closed"
            }),
        )
        .await
        .is_err()
    );
    Ok(())
}

/// Needs a live Governor config and database. Run with
/// `ELIOT_GOVERNOR_CONFIG` set and `--ignored`; ignored by default so a
/// plain `cargo test` is not a guaranteed failure on every machine.
#[test]
#[ignore = "requires ELIOT_GOVERNOR_CONFIG and a live database"]
fn cognitive_state_machine_is_db_backed_atomic_and_restart_safe() -> Result<()> {
    // This integration future owns the exact 18-call contract plus restart/saturation
    // fixtures. Give only this test an explicit stack instead of requiring a process-wide
    // RUST_MIN_STACK override on Windows.
    std::thread::Builder::new()
        .name("cognitive-db-state-machine".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(cognitive_state_machine_db_inner())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("cognitive DB state-machine test thread panicked"))?
}

#[allow(clippy::too_many_lines)]
async fn cognitive_state_machine_db_inner() -> Result<()> {
    let config_path = PathBuf::from(
        std::env::var_os("ELIOT_GOVERNOR_CONFIG")
            .context("ELIOT_GOVERNOR_CONFIG is required for the DB-backed cognitive test")?,
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
    let governor_context = AuthenticatedRequestContext {
        session_id: SessionId::new_v7(),
        bound_project_id: None,
        bound_task_id: None,
    };
    let controller_context = AuthenticatedRequestContext {
        session_id: SessionId::new_v7(),
        bound_project_id: None,
        bound_task_id: None,
    };
    let operator_context = AuthenticatedRequestContext {
        session_id: SessionId::new_v7(),
        bound_project_id: None,
        bound_task_id: None,
    };
    let _ = dispatch_task_contract_create(
        &daemon.codex_controller,
        controller_context,
        json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7(),
            "title": "Cognitive canonical state machine DB integration",
            "acceptance_items": [
                {
                    "item_id": "observed",
                    "description": "canonical cognitive transitions are DB-backed",
                    "required_evidence": "observation"
                },
                {
                    "item_id": "verified",
                    "description": "gate and restart reconciliation are verified",
                    "required_evidence": "verification"
                }
            ]
        }),
    )
    .await?;

    let operator_agent_session = AgentSessionId::from_uuid(operator_context.session_id.as_uuid());
    let mut broker = delegation_runtime::load_state(&daemon.human_operator.root)?;
    HostBrokerService.register_session(
        &mut broker,
        operator_agent_session,
        AgentHostId::Codex,
        "cognitive DB test operator".to_owned(),
        format!("db-operator-{task_id}"),
        AgentCapabilityEnvelope::default(),
    )?;
    delegation_runtime::save_host_broker_state(&daemon.human_operator.root, &broker)?;
    let _ = crate::host_runtime::grant_role_from_daemon(
        &daemon.human_operator.root,
        &daemon.human_operator.store,
        &daemon.human_operator.writer,
        json!({
            "task": task_id,
            "session": operator_agent_session,
            "role": "reviewer",
            "capability": ["review_candidate"],
            "ttl_minutes": 120
        }),
    )
    .await?;

    let seed_write_id = WriteId::new_v7();
    let _ = dispatch_agent_candidate_submit(
        &daemon.codex_controller,
        controller_context,
        json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": seed_write_id,
            "topic": "reciprocal-db-preexisting-memory",
            "statement": "preexisting exact-scope memory for early target calls",
            "where_applicable": ["isolated cognitive integration test"],
            "where_not_applicable": [],
            "negative_constraints": [],
            "provenance_refs": ["provider:test:preexisting"],
            "freshness_rule": "valid only for this isolated test"
        }),
    )
    .await?;
    let seed_handle = seed_write_id.to_string();
    let run_id = format!("db-cognitive-{}", uuid::Uuid::new_v4());
    let (plan, candidates) = db_plan(&run_id, project_id, task_id, &seed_handle)?;
    let harness_script_sha256 = sha256_json(&"db-harness")?;
    let cases_sha256 = sha256_json(&"db-cases")?;
    let exposure_map_sha256 = sha256_json(&"db-exposure-map")?;
    let output_contract_sha256 = sha256_json(&"db-output-contract")?;
    let models_sha256 = sha256_json(&"db-models")?;
    let policy_snapshot_id = sha256_json(&(
        "db-backed-m6-v1",
        &harness_script_sha256,
        &cases_sha256,
        &exposure_map_sha256,
        &output_contract_sha256,
        &models_sha256,
        BUILD_SOURCE_COMMIT,
    ))?;
    let sealed = cognitive_run_seal(
        &daemon.cognitive_governor,
        governor_context,
        json!({
            "harness_version": "db-backed-m6-v1",
            "instance_name": daemon.cognitive_governor.instance_name,
            "run_id": run_id,
            "project_id": project_id,
            "task_id": task_id,
            "harness_script_sha256": harness_script_sha256,
            "cases_sha256": cases_sha256,
            "exposure_map_sha256": exposure_map_sha256,
            "output_contract_sha256": output_contract_sha256,
            "models_sha256": models_sha256,
            "source_commit": BUILD_SOURCE_COMMIT,
            "policy_snapshot_id": policy_snapshot_id,
            "output_root": format!("C:/eliot-db-tests/{run_id}"),
            "timeout_seconds": 30,
            "exact_plan": plan,
        }),
    )
    .await?;
    let contract_receipt: WriteReceiptRef = serde_json::from_value(
        sealed
            .get("canonical_receipt")
            .cloned()
            .context("seal response has no receipt")?,
    )?;

    let mut terminal_receipts = Vec::new();
    let mut candidate_receipts = Vec::new();
    let mut promotion_receipts = Vec::new();
    for call in &plan[..16] {
        let begin = db_begin(
            &daemon.cognitive_governor,
            governor_context,
            &run_id,
            project_id,
            task_id,
            call,
            None,
        )
        .await?;
        assert_eq!(begin["dispatch_admitted"], true);
        if call.call_number == 1 {
            let replay = db_begin(
                &daemon.cognitive_governor,
                governor_context,
                &run_id,
                project_id,
                task_id,
                call,
                None,
            )
            .await?;
            assert_eq!(replay["replay"], true);
            assert_eq!(replay["dispatch_admitted"], false);
            assert_eq!(replay["reconciliation_required"], true);
        }
        let candidate = if call.invocation_role == CognitiveInvocationRole::SourceWrite {
            candidates.get(&call.call_number)
        } else if call.invocation_role == CognitiveInvocationRole::Target && call.call_number >= 6 {
            candidates.get(&5)
        } else {
            None
        };
        let (terminal, candidate_receipt) = db_drive_successful_call(
            &daemon,
            governor_context,
            &run_id,
            project_id,
            task_id,
            call,
            candidate,
            &begin,
        )
        .await?;
        terminal_receipts.push(terminal);
        if let Some(candidate_receipt) = candidate_receipt {
            candidate_receipts.push(candidate_receipt);
            promotion_receipts.push(
                db_promote_candidate(
                    &daemon,
                    operator_context,
                    project_id,
                    task_id,
                    candidate.context("source candidate body disappeared")?,
                    call.call_number,
                    &run_id,
                )
                .await?,
            );
        }
    }
    assert_eq!(terminal_receipts.len(), 16);
    assert_eq!(candidate_receipts.len(), 2);
    assert_eq!(promotion_receipts.len(), 2);
    let first_claim_id = ClaimId::from_uuid(candidate_receipts[0].write_id.as_uuid());
    let unrestricted = ReadService::new(daemon.cognitive_governor.store.clone())
        .fetch_atoms_l2(&FetchAtomsL2Request {
            project_id,
            handles: Vec::new(),
            continuation: None,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?;
    assert!(unrestricted.relations.iter().any(|relation| {
        relation.from == first_claim_id.to_string()
            && relation.to == promotion_receipts[0].write_id.to_string()
    }));
    let exact_fetch: FetchAtomsL2Response = serde_json::from_value(
        Box::pin(dispatch_tool(
            &daemon.codex_controller,
            controller_context,
            "eliot_fetch_l2",
            json!({"project_id": project_id, "handles": [first_claim_id.to_string()]}),
        ))
        .await?,
    )?;
    assert_eq!(
        exact_fetch
            .claims
            .iter()
            .map(|claim| claim.claim_id)
            .collect::<Vec<_>>(),
        vec![first_claim_id]
    );
    assert!(exact_fetch.evidence_atoms.is_empty());
    assert_eq!(exact_fetch.verification_runs.len(), 1);
    assert_eq!(
        exact_fetch.verification_runs[0].verification_id.to_string(),
        promotion_receipts[0].write_id.to_string()
    );
    assert_eq!(exact_fetch.relations.len(), 1);
    assert_eq!(exact_fetch.relations[0].from, first_claim_id.to_string());
    assert_eq!(
        exact_fetch.relations[0].to,
        promotion_receipts[0].write_id.to_string()
    );
    assert!(exact_fetch.verification_runs.iter().all(|run| {
        run.verification_id.to_string() != promotion_receipts[1].write_id.to_string()
    }));
    assert!(
        exact_fetch
            .relations
            .iter()
            .all(|relation| { relation.to != promotion_receipts[1].write_id.to_string() })
    );
    let latest_promotion = daemon
        .cognitive_governor
        .store
        .write_receipt_by_id(&promotion_receipts[1].write_id)
        .await?
        .context("latest promotion receipt disappeared")?;
    let canonical_case_dispositions = resolve_canonical_case_dispositions(
        &daemon.cognitive_governor.store,
        &load_cognitive_contract(
            &daemon.cognitive_governor,
            &CognitiveStatusInput {
                run_id: run_id.clone(),
                project_id,
                task_id,
            },
        )
        .await?,
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    let mut gate = CognitiveSharedGateBinding {
        gate_revision: latest_promotion
            .memory_revision
            .context("promotion has no memory revision")?
            .value(),
        gate_receipt: promotion_receipts[1].clone(),
        contract_receipt,
        pre_gate_terminal_receipts: terminal_receipts.clone(),
        source_disposition_receipts: promotion_receipts.clone(),
        reciprocal_verification_receipts: candidate_receipts.clone(),
        canonical_case_dispositions,
        condition_sha256: String::new(),
    };
    gate.condition_sha256 = sha256_json(&gate)?;

    let call_17 = &plan[16];
    let first_candidate_handle = format!(
        "claim:{}",
        call_17
            .expected_exposure_handles
            .first()
            .context("call 17 has no reciprocal handle")?
    );
    // More than one bounded lifecycle page must not hide the newest state. The old
    // ASC/LIMIT 128 projection saw only the first 128 transitions and could admit a
    // call after the final demotion.
    for index in 0..130_u16 {
        let (operator, label) = if index % 2 == 0 {
            (ForgettingOperator::Demote, "demote")
        } else {
            (ForgettingOperator::Restore, "restore")
        };
        persist_operator_lifecycle_transition(
            &daemon.human_operator,
            operator_context,
            project_id,
            task_id,
            &first_candidate_handle,
            operator,
            ForgettingReason::LowUtility,
            OperatorLifecycleBinding::unbound(vec![format!(
                "db-bounded-lifecycle-{label}-{index}"
            )]),
            &format!("db-bounded-lifecycle-{label}-{index}-{run_id}"),
        )
        .await?;
    }
    let call_17_begin = db_begin(
        &daemon.cognitive_governor,
        governor_context,
        &run_id,
        project_id,
        task_id,
        call_17,
        Some(&gate),
    );
    let demote_key = format!("db-race-demote-{run_id}");
    let demote = persist_operator_lifecycle_transition(
        &daemon.human_operator,
        operator_context,
        project_id,
        task_id,
        &first_candidate_handle,
        ForgettingOperator::Demote,
        ForgettingReason::LowUtility,
        OperatorLifecycleBinding::unbound(vec!["db-race-demote".to_owned()]),
        &demote_key,
    );
    let (raced_begin, demote_receipt) = tokio::join!(call_17_begin, demote);
    let demote_receipt = demote_receipt?;
    if let Ok(begin) = &raced_begin {
        let attempt_ref: WriteReceiptRef = serde_json::from_value(
            begin
                .get("canonical_receipt")
                .cloned()
                .context("raced begin has no receipt")?,
        )?;
        let attempt = daemon
            .cognitive_governor
            .store
            .write_receipt_by_id(&attempt_ref.write_id)
            .await?
            .context("raced attempt receipt disappeared")?;
        let demotion = daemon
            .cognitive_governor
            .store
            .write_receipt_by_id(&demote_receipt.write_id)
            .await?
            .context("demotion receipt disappeared")?;
        assert!(attempt.project_sequence < demotion.project_sequence);
    }
    let _restore_receipt = persist_operator_lifecycle_transition(
        &daemon.human_operator,
        operator_context,
        project_id,
        task_id,
        &first_candidate_handle,
        ForgettingOperator::Restore,
        ForgettingReason::LowUtility,
        OperatorLifecycleBinding::unbound(vec!["db-race-restore".to_owned()]),
        &format!("db-race-restore-{run_id}"),
    )
    .await?;
    let begin_17 = match raced_begin {
        Ok(begin) => begin,
        Err(_) => {
            db_begin(
                &daemon.cognitive_governor,
                governor_context,
                &run_id,
                project_id,
                task_id,
                call_17,
                Some(&gate),
            )
            .await?
        }
    };
    let (terminal_17, _) = db_drive_successful_call(
        &daemon,
        governor_context,
        &run_id,
        project_id,
        task_id,
        call_17,
        candidates.get(&5),
        &begin_17,
    )
    .await?;
    terminal_receipts.push(terminal_17);

    let call_18 = &plan[17];
    let begin_18 = db_begin(
        &daemon.cognitive_governor,
        governor_context,
        &run_id,
        project_id,
        task_id,
        call_18,
        Some(&gate),
    )
    .await?;
    let (terminal_18, _) = db_drive_successful_call(
        &daemon,
        governor_context,
        &run_id,
        project_id,
        task_id,
        call_18,
        candidates.get(&7),
        &begin_18,
    )
    .await?;
    terminal_receipts.push(terminal_18);
    let status = cognitive_run_status(
        &daemon.cognitive_governor,
        json!({"run_id": run_id, "project_id": project_id, "task_id": task_id}),
    )
    .await?;
    assert_eq!(status["complete"], true);
    assert_eq!(status["provider_calls_consumed"], 18);
    assert_eq!(status["current_revision"], 36);
    let first_raw_receipt: WriteReceiptRef = serde_json::from_value(
        status
            .pointer("/terminals/0/receipt_body/raw_verifier_receipts/0")
            .cloned()
            .context("status has no call-1 raw verifier")?,
    )?;
    let raw = daemon
        .cognitive_governor
        .store
        .canonical_record_by_write_id::<CognitiveRawVerifierEvidence>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::CognitiveRawVerifier.as_str()],
            first_raw_receipt.write_id,
        )
        .await?
        .context("call-1 raw verifier disappeared")?;
    assert!(raw.receipt_body.passed);

    let unknown_run = format!("db-cognitive-unknown-{}", uuid::Uuid::new_v4());
    let (unknown_plan, _) = db_plan(&unknown_run, project_id, task_id, &seed_handle)?;
    let _ = cognitive_run_seal(
        &daemon.cognitive_governor,
        governor_context,
        json!({
            "harness_version": "db-backed-m6-v1",
            "instance_name": daemon.cognitive_governor.instance_name,
            "run_id": unknown_run,
            "project_id": project_id,
            "task_id": task_id,
            "harness_script_sha256": harness_script_sha256,
            "cases_sha256": cases_sha256,
            "exposure_map_sha256": exposure_map_sha256,
            "output_contract_sha256": output_contract_sha256,
            "models_sha256": models_sha256,
            "source_commit": BUILD_SOURCE_COMMIT,
            "policy_snapshot_id": policy_snapshot_id,
            "output_root": format!("C:/eliot-db-tests/{unknown_run}"),
            "timeout_seconds": 30,
            "exact_plan": unknown_plan,
        }),
    )
    .await?;
    let unknown_begin = db_begin(
        &daemon.cognitive_governor,
        governor_context,
        &unknown_run,
        project_id,
        task_id,
        &unknown_plan[0],
        None,
    )
    .await?;
    let unknown_capability_path: PathBuf = serde_json::from_value(
        unknown_begin
            .get("capability_file")
            .cloned()
            .context("unknown attempt has no capability file")?,
    )?;
    let unknown_capability = read_cognitive_capability_file(&unknown_capability_path)?;
    let unknown_child_session = daemon
        .authenticate_cognitive_child(
            &unknown_capability_path,
            &unknown_capability.capability_token,
        )
        .await?;
    let unknown_child_context = AuthenticatedRequestContext {
        session_id: unknown_child_session,
        bound_project_id: None,
        bound_task_id: None,
    };
    let denied = call_tool(
        &daemon.cognitive_child,
        unknown_child_context,
        json!({
            "name": "eliot_agent_candidate_submit",
            "arguments": {}
        }),
    )
    .await?;
    assert_eq!(denied["isError"], true);
    let empty_fetch_denied = call_tool(
        &daemon.cognitive_child,
        unknown_child_context,
        json!({
            "name": "eliot_fetch_l2",
            "arguments": {
                "project_id": project_id,
                "handles": []
            }
        }),
    )
    .await?;
    assert_eq!(empty_fetch_denied["isError"], true);
    assert!(
        call_tool(
            &daemon.cognitive_child,
            unknown_child_context,
            json!({
                "name": "eliot_recall_l0",
                "arguments": {
                    "project_id": project_id,
                    "limit": 1
                }
            }),
        )
        .await
        .is_err()
    );
    drop(daemon);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let daemon = McpDaemon::new(&config_path, &instance, &publication)?;
    daemon.codex_controller.ensure_schema().await?;
    let reauthenticated_session = daemon
        .authenticate_cognitive_child(
            &unknown_capability_path,
            &unknown_capability.capability_token,
        )
        .await?;
    assert_eq!(reauthenticated_session, unknown_child_session);
    assert_eq!(
        cognitive_tool_definitions(&daemon.cognitive_child, reauthenticated_session)
            .await?
            .into_iter()
            .filter_map(|definition| definition
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned))
            .collect::<Vec<_>>(),
        vec![
            "eliot_cognitive_job_fetch",
            "eliot_recall_l0",
            "eliot_fetch_l2"
        ]
    );
    let _ = cognitive_run_terminal(
        &daemon.cognitive_governor,
        governor_context,
        json!({
            "run_id": unknown_run,
            "project_id": project_id,
            "task_id": task_id,
            "call_number": 1,
            "status": "unknown_outcome",
            "execution": db_execution(&unknown_plan[0])?,
            "host_observation": db_host_observation(&unknown_plan[0], &unknown_begin)?,
            "raw_verifier": {
                "verifier_version": "db-backed-unknown-v1",
                "checks_sha256": sha256_json(&"unknown-checks")?,
                "passed": true
            },
            "reason": "simulated response-loss unknown outcome"
        }),
    )
    .await?;
    let unknown_status = cognitive_run_status(
        &daemon.cognitive_governor,
        json!({"run_id": unknown_run, "project_id": project_id, "task_id": task_id}),
    )
    .await?;
    assert_eq!(unknown_status["stopped_no_redispatch"], true);
    assert!(
        db_begin(
            &daemon.cognitive_governor,
            governor_context,
            &unknown_run,
            project_id,
            task_id,
            &unknown_plan[1],
            None,
        )
        .await
        .is_err()
    );
    drop(daemon);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let restarted = McpDaemon::new(&config_path, &instance, &publication)?;
    restarted.codex_controller.ensure_schema().await?;
    let restarted_status = cognitive_run_status(
        &restarted.cognitive_governor,
        json!({"run_id": unknown_run, "project_id": project_id, "task_id": task_id}),
    )
    .await?;
    assert_eq!(restarted_status["current_revision"], 2);
    assert_eq!(restarted_status["stopped_no_redispatch"], true);
    assert_eq!(restarted_status["next_call"], Value::Null);
    db_assert_observation_saturation_rejected(
        &restarted,
        governor_context,
        project_id,
        task_id,
        &seed_handle,
    )
    .await?;
    Ok(())
}
