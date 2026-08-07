#[path = "support/ul_t04.rs"]
mod support;

use eliot_types::{
    AgentId, CapsuleBuild, ClaimCardInput, ClaimId, CommandContext, ConceptKind, ConceptNode,
    CueBinding, CueKind, CueMatchMode, CueStrength, DependencyManifest, EpistemicStatus,
    InjectionReceipt, LifecycleStatus, ObservabilityKind, ProjectId, PyramidBuildStatus,
    PyramidTargetKind, RelationInput, RelationType, SemanticCommand, SubsystemCapsule, TaintClass,
    TaskId, UlArtifact, UlArtifactBatchRecordCommand, UlInjectionMode, UlTaskClassPolicy,
    Visibility, WriteId, ul_token_estimate,
};
use serde_json::{Value, json};
use support::{Harness, PreparedHarness, TestResult, rerun_with_credential_gate, test_guard};

#[test]
fn u9_2_explicit_control_is_memory_free_before_any_cognitive_read() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("u9_2_explicit_control_is_memory_free_before_any_cognitive_read")?
    {
        return Ok(());
    }
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut prepared = Harness::prepare("u9-control")?;
    prepared.seed(&failure_command(project_id))?;
    prepared.seed(&claim_command(project_id, ClaimId::new_v7()))?;
    let mut harness = prepared.launch()?;
    harness.create_task(10, project_id, task_id)?;
    let before: Vec<InjectionReceipt> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::InjectionReceipt,
    )?;

    let response = compile_with_memory_mode(
        &mut harness,
        11,
        project_id,
        task_id,
        None,
        "src/net/session.rs",
        "memory_free_control",
    )?;
    let after: Vec<InjectionReceipt> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::InjectionReceipt,
    )?;

    assert_eq!(response["ul_experiment"]["arm"], "control");
    assert_eq!(
        response["ul_experiment"]["effective_memory_mode"],
        "memory_free_control"
    );
    assert!(response.get("ul_understanding").is_none());
    assert!(response.get("ul_boot").is_none());
    assert!(response.get("ul_fired").is_none());
    assert_eq!(response["compile_audit"]["stages"][0], "plan_resolved");
    assert_eq!(
        response["compile_audit"]["source_reads"]["current_state_reads"],
        0
    );
    assert_eq!(response["compile_audit"]["source_reads"]["l0_reads"], 0);
    assert_eq!(response["compile_audit"]["source_reads"]["l2_reads"], 0);
    for counter in ["l0", "l2", "pyramid", "experience", "skill"] {
        assert_eq!(
            response["compile_audit"]["read_counters"][counter], 0,
            "control read counter {counter} was not zero"
        );
    }
    assert_eq!(
        response["compile_audit"]["semantic"]["project_understanding_compiles"],
        1
    );
    assert_eq!(response["compile_audit"]["semantic"]["budget_renders"], 1);
    for memory_field in [
        "current_truth",
        "relevant_verified_claims",
        "relevant_supported_claims",
        "weak_claims_warning",
        "negative_memory",
        "recent_failures",
        "known_decisions",
        "open_questions",
        "exact_handles",
        "source_receipts",
        "memory_decisions",
        "experience_priors",
        "historical_memory",
    ] {
        assert_eq!(
            response[memory_field],
            json!([]),
            "{memory_field} leaked into the memory-free control"
        );
    }
    assert_eq!(after.len(), before.len());
    Ok(())
}

#[test]
fn u9_5_handles_only_policy_strips_negative_and_normal_payloads() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("u9_5_handles_only_policy_strips_negative_and_normal_payloads")? {
        return Ok(());
    }
    let project_id = ProjectId::new_v7();
    let control_task = TaskId::new_v7();
    let treatment_task = TaskId::new_v7();
    let claim_id = ClaimId::new_v7();
    let mut prepared = Harness::prepare("u9-handles")?;
    prepared.seed(&failure_command(project_id))?;
    prepared.seed(&claim_command(project_id, claim_id))?;
    let mut harness = prepared.launch()?;
    harness.create_task(20, project_id, control_task)?;
    harness.create_task(21, project_id, treatment_task)?;

    let control = compile_with_memory_mode(
        &mut harness,
        22,
        project_id,
        control_task,
        None,
        "src/net/session.rs",
        "memory_free_control",
    )?;
    assert_eq!(control["ul_experiment"]["arm"], "control");
    let task_class = control["ul_experiment"]["task_class"]
        .as_object()
        .ok_or("control task class missing")?;
    let class_key = format!(
        "{}|{}|{}",
        task_class["action_class"]
            .as_str()
            .ok_or("action_class missing")?,
        task_class["subsystem"]
            .as_str()
            .ok_or("subsystem missing")?,
        task_class["artifact_class"]
            .as_str()
            .ok_or("artifact_class missing")?
    );
    harness.upsert_ul_task_class_policy(&UlTaskClassPolicy {
        project_id,
        task_class_key: class_key,
        injection_mode: UlInjectionMode::HandlesOnly,
        treatment_tasks: 10,
        control_tasks: 5,
        control_median_exploration_tokens: 32,
        treatment_median_net_delta: 1,
        reason: "positive_median_net_token_delta".to_owned(),
        evidence_task_ids: Vec::new(),
    })?;

    let treatment = compile(
        &mut harness,
        23,
        project_id,
        treatment_task,
        None,
        "src/net/session.rs",
    )?;
    assert_eq!(treatment["ul_experiment"]["arm"], "treatment");
    assert!(
        treatment.get("ul_fired").is_none(),
        "compile_packet_l3 is the sealed, budgeted cognitive surface; generic UL delivery must remain pending"
    );
    let delivery = harness.client.tool_call(
        24,
        "eliot_task_state",
        &json!({"project_id": project_id, "task_id": treatment_task}),
    )?;
    let items = delivery["ul_fired"]["items"]
        .as_array()
        .ok_or("pending treatment ul_fired.items missing from the next tool response")?;
    for item_ref in [
        "failure:u9-handles-negative".to_owned(),
        format!("claim:{claim_id}"),
    ] {
        assert!(
            items
                .iter()
                .any(|item| item["item_ref"] == item_ref && item["payload"].is_null())
        );
    }
    let receipts: Vec<InjectionReceipt> = harness.observability_records(
        project_id,
        Some(treatment_task),
        ObservabilityKind::InjectionReceipt,
    )?;
    assert!(
        receipts.iter().any(|receipt| {
            receipt.item_ref == "failure:u9-handles-negative"
                && receipt.render_form == "handle"
                && receipt.policy_reason.as_deref() == Some("task_class_handles_only")
        }) && receipts.iter().any(|receipt| {
            receipt.item_ref == format!("claim:{claim_id}")
                && receipt.render_form == "handle"
                && receipt.policy_reason.as_deref() == Some("task_class_handles_only")
        }),
        "persisted injection receipts: {receipts:#?}"
    );
    Ok(())
}

#[test]
fn u9_6_invariant_gate_prefills_requires_and_accepts_an_explicit_waiver() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate(
        "u9_6_invariant_gate_prefills_requires_and_accepts_an_explicit_waiver",
    )? {
        return Ok(());
    }
    let project_id = ProjectId::new_v7();
    let mut prepared = Harness::prepare("u9-invariant")?;
    seed_invariant_capsule(&mut prepared, project_id)?;
    let mut harness = prepared.launch()?;
    let control_task = TaskId::new_v7();
    let treatment_task = TaskId::new_v7();
    harness.create_task(30, project_id, control_task)?;
    harness.create_task(31, project_id, treatment_task)?;

    let control = compile_with_memory_mode(
        &mut harness,
        32,
        project_id,
        control_task,
        Some(material_frame(&[], &[])),
        "src/invariant/lib.rs",
        "memory_free_control",
    )?;
    assert_eq!(control["ul_experiment"]["arm"], "control");
    assert_eq!(control["packet_admission"]["active_allowed"], true);
    let active_path = harness
        .runtime_path()
        .join("reports")
        .join("context-packets")
        .join("tasks")
        .join(treatment_task.to_string())
        .join("active")
        .join("latest.json");
    assert!(!active_path.exists());

    let baseline = compile(
        &mut harness,
        33,
        project_id,
        treatment_task,
        Some(material_frame(
            &[],
            &[json!({
                "invariant_ref": "invariant:preserve-order",
                "reason": "verified by the focused deterministic fixture"
            })],
        )),
        "src/invariant/lib.rs",
    )?;
    assert_eq!(baseline["packet_admission"]["status"], "admitted_degraded");
    assert!(active_path.is_file());
    let baseline_active = std::fs::read(&active_path)?;
    let baseline_assignment = harness
        .ul_assignment(project_id, treatment_task)?
        .ok_or("admitted baseline did not persist its post-commit measurement")?;

    let rejected = compile(
        &mut harness,
        34,
        project_id,
        treatment_task,
        Some(material_frame(&[], &[])),
        "src/invariant/lib.rs",
    )?;
    assert_eq!(rejected["ul_experiment"]["arm"], "treatment");
    assert_eq!(
        rejected["ul_experiment"]["assignment_status"],
        "not_assigned_rejected"
    );
    assert_eq!(rejected["packet_admission"]["status"], "rejected");
    assert_eq!(rejected["packet_admission"]["active_allowed"], false);
    assert_eq!(rejected["ul_gate"]["status"], "require_packet_refresh");
    assert_eq!(
        rejected["ul_gate"]["missing_invariant_refs"],
        json!(["invariant:preserve-order"])
    );
    assert_eq!(std::fs::read(&active_path)?, baseline_active);
    assert_eq!(
        harness.ul_assignment(project_id, treatment_task)?,
        Some(baseline_assignment.clone()),
        "a rejected packet changed the prior admitted measurement"
    );
    let attempts_root = active_path
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("task packet root missing")?
        .join("attempts");
    assert_eq!(std::fs::read_dir(&attempts_root)?.count(), 1);

    let rejected_replay = compile(
        &mut harness,
        35,
        project_id,
        treatment_task,
        Some(material_frame(&[], &[])),
        "src/invariant/lib.rs",
    )?;
    assert_eq!(rejected_replay["packet_id"], rejected["packet_id"]);
    assert_eq!(
        rejected_replay["packet_budget_decision"]["mandatory_floor_tokens"],
        rejected["packet_budget_decision"]["mandatory_floor_tokens"]
    );
    assert_eq!(rejected_replay["exact_handles"], rejected["exact_handles"]);
    assert_eq!(std::fs::read(&active_path)?, baseline_active);
    assert_eq!(std::fs::read_dir(&attempts_root)?.count(), 1);
    assert_eq!(
        harness.ul_assignment(project_id, treatment_task)?,
        Some(baseline_assignment),
        "replaying a rejected packet changed the prior admitted measurement"
    );
    assert_eq!(
        rejected["frame_stub"]["invariant_refs"],
        json!(["invariant:preserve-order"])
    );

    let accepted = compile(
        &mut harness,
        36,
        project_id,
        treatment_task,
        Some(material_frame(
            &[],
            &[json!({
                "invariant_ref": "invariant:preserve-order",
                "reason": "verified by the focused deterministic fixture"
            })],
        )),
        "src/invariant/lib.rs",
    )?;
    assert_eq!(accepted["packet_admission"]["status"], "admitted_degraded");
    assert!(active_path.is_file());
    assert_eq!(accepted["ul_gate"]["status"], "require_probe");
    assert_eq!(accepted["ul_gate"]["reason"], "blind_subsystem");
    assert!(
        accepted["ul_gate"].get("missing_invariant_refs").is_none(),
        "the explicit bounded waiver must clear only the invariant gate"
    );
    assert!(
        accepted["ul_gate"]["suggested_probe"]
            .as_str()
            .is_some_and(|probe| !probe.trim().is_empty()),
        "blind subsystem coverage still requires a discriminative probe"
    );

    let schema = harness.tool_schema(37, "eliot_compile_packet_l3")?;
    let serialized = serde_json::to_string(&schema)?;
    assert!(serialized.contains("invariant_refs"));
    assert!(serialized.contains("waived_invariants"));
    assert!(serialized.contains("prediction_confidence"));
    Ok(())
}

#[test]
fn u9_7_hard_ceiling_failure_has_zero_authoritative_writes() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("u9_7_hard_ceiling_failure_has_zero_authoritative_writes")? {
        return Ok(());
    }
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut harness = Harness::prepare("u9-hard-ceiling")?.launch()?;
    harness.create_task(40, project_id, task_id)?;
    let before_revision = harness.current_revision(project_id)?;
    let before_predictions: Vec<eliot_types::PredictionRecord> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::PredictionRecord,
    )?;
    let task_root = harness
        .runtime_path()
        .join("reports")
        .join("context-packets")
        .join("tasks")
        .join(task_id.to_string());
    let codecortex_latest = harness
        .runtime_path()
        .join("reports")
        .join("codecortex")
        .join("latest.json");
    assert!(!task_root.exists());
    assert!(!codecortex_latest.exists());
    assert!(harness.ul_assignment(project_id, task_id)?.is_none());

    let mut frame = material_frame(&[], &[]);
    frame["killed_paths"] = Value::Array(
        (0..192)
            .map(|index| {
                Value::String(format!(
                    "src/forbidden/{index:03}/{}",
                    "load-bearing-hard-ceiling-evidence-".repeat(5)
                ))
            })
            .collect(),
    );
    let response = harness.client.tool_call_response(
        41,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "change src/hard_ceiling.rs without crossing the Governor ceiling",
            "candidate_handles": ["file:src/hard_ceiling.rs"],
            "max_tokens": 4_000,
            "memory_mode": "include_case_candidates",
            "material_frame": frame,
        }),
    )?;
    assert_eq!(response["error"]["code"], -32602, "{response}");
    assert_eq!(
        response["error"]["data"]["code"], "PACKET_HARD_CEILING_EXCEEDED",
        "{response}"
    );
    assert!(
        response["error"]["data"]["mandatory_floor_tokens"]
            .as_u64()
            .is_some_and(|floor| floor > 4_096),
        "{response}"
    );

    let after_revision = harness.current_revision(project_id)?;
    let after_predictions: Vec<eliot_types::PredictionRecord> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::PredictionRecord,
    )?;
    assert_eq!(after_revision, before_revision);
    assert_eq!(after_predictions.len(), before_predictions.len());
    assert!(harness.ul_assignment(project_id, task_id)?.is_none());
    assert!(!task_root.join("active").exists());
    assert!(!task_root.join("attempts").exists());
    assert!(!codecortex_latest.exists());
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn u9_8_packet_startup_recovery_is_complete_isolated_and_effects_once() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate(
        "u9_8_packet_startup_recovery_is_complete_isolated_and_effects_once",
    )? {
        return Ok(());
    }
    let mut harness = Harness::start("packet-startup-recovery")?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    harness.create_task(40, project_id, task_id)?;
    let frame = material_frame(&[], &[]);
    let canonical_response = compile(
        &mut harness,
        41,
        project_id,
        task_id,
        Some(frame.clone()),
        "src/invariant/lib.rs",
    )?;
    assert_eq!(
        canonical_response["packet_admission"]["active_allowed"],
        true
    );

    let legacy_task_handle = "legacy-packet-startup-recovery";
    let mut legacy_frame = frame;
    legacy_frame["expected_observable"] = json!("observe packet startup recovery");
    let legacy_response = harness.client.tool_call(
        42,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": legacy_task_handle,
            "goal": "change src/invariant/lib.rs",
            "candidate_handles": ["file:src/invariant/lib.rs"],
            "max_tokens": 1_200,
            "memory_mode": "include_case_candidates",
            "material_frame": legacy_frame,
        }),
    )?;
    assert_eq!(legacy_response["packet_admission"]["active_allowed"], true);

    let tasks_root = harness
        .runtime_path()
        .join("reports")
        .join("context-packets")
        .join("tasks");
    let canonical_task_root = tasks_root.join(task_id.to_string());
    let legacy_task_root = tasks_root.join(
        blake3::hash(legacy_task_handle.as_bytes())
            .to_hex()
            .to_string(),
    );
    let canonical_authority_path = canonical_task_root.join("active").join("authority.json");
    let legacy_authority_path = legacy_task_root.join("active").join("authority.json");
    let canonical_authority_bytes = std::fs::read(&canonical_authority_path)?;
    let legacy_authority_bytes = std::fs::read(&legacy_authority_path)?;
    let canonical_authority: Value = serde_json::from_slice(&canonical_authority_bytes)?;
    let legacy_authority: Value = serde_json::from_slice(&legacy_authority_bytes)?;
    let canonical_operation_id = canonical_authority["operation_id"]
        .as_str()
        .ok_or("canonical authority operation_id missing")?;
    let legacy_operation_id = legacy_authority["operation_id"]
        .as_str()
        .ok_or("legacy authority operation_id missing")?;
    let canonical_outbox = canonical_task_root
        .join("outbox")
        .join(canonical_operation_id);
    let legacy_outbox = legacy_task_root.join("outbox").join(legacy_operation_id);
    let canonical_intent: Value =
        serde_json::from_slice(&std::fs::read(canonical_outbox.join("intent.json"))?)?;
    let canonical_response_bytes = serde_json::to_vec_pretty(&canonical_intent["response"])?;
    let canonical_latest_path = canonical_task_root.join("active").join("latest.json");
    let canonical_revision_path =
        canonical_task_root
            .join("active")
            .join("revisions")
            .join(format!(
                "{}-{canonical_operation_id}.json",
                canonical_authority["material"]["at_revision"]
                    .as_u64()
                    .ok_or("canonical authority revision missing")?
            ));
    let baseline_assignment = harness.ul_assignment(project_id, task_id)?;
    let baseline_predictions: Vec<eliot_types::PredictionRecord> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::PredictionRecord,
    )?;
    let baseline_revision = harness.current_revision(project_id)?;

    harness.stop_daemon()?;
    remove_terminal_packet_event(&canonical_outbox.join("events"))?;
    remove_terminal_packet_event(&legacy_outbox.join("events"))?;
    std::fs::remove_file(&canonical_latest_path)?;
    std::fs::remove_file(&canonical_revision_path)?;
    for index in 0..300 {
        let corrupt_authority = tasks_root
            .join(format!("0000-corrupt-authority-{index:04}"))
            .join("active")
            .join("authority.json");
        std::fs::create_dir_all(
            corrupt_authority
                .parent()
                .ok_or("corrupt authority parent missing")?,
        )?;
        std::fs::write(corrupt_authority, b"{not-json")?;
    }
    let last_corrupt_authority = tasks_root
        .join("0000-corrupt-authority-0299")
        .join("active")
        .join("authority.json");
    let misplaced_task_root = tasks_root.join("0001-misplaced-authority");
    let misplaced_authority = misplaced_task_root.join("active").join("authority.json");
    std::fs::create_dir_all(
        misplaced_authority
            .parent()
            .ok_or("misplaced authority parent missing")?,
    )?;
    std::fs::write(&misplaced_authority, &canonical_authority_bytes)?;

    harness.restart_daemon()?;

    assert_eq!(
        std::fs::read(&canonical_authority_path)?,
        canonical_authority_bytes
    );
    assert_eq!(
        std::fs::read(&legacy_authority_path)?,
        legacy_authority_bytes
    );
    assert_eq!(
        std::fs::read(&canonical_latest_path)?,
        canonical_response_bytes
    );
    assert_eq!(
        std::fs::read(&canonical_revision_path)?,
        canonical_response_bytes
    );
    let canonical_events = packet_event_snapshot(&canonical_outbox.join("events"))?;
    let legacy_events = packet_event_snapshot(&legacy_outbox.join("events"))?;
    assert_eq!(canonical_events.len(), 3);
    assert_eq!(legacy_events.len(), 3);
    assert_eq!(
        serde_json::from_slice::<Value>(&canonical_events[2].1)?["status"],
        "complete"
    );
    let legacy_terminal: Value = serde_json::from_slice(&legacy_events[2].1)?;
    assert_eq!(
        legacy_terminal["status"], "complete",
        "legacy terminal replay event: {legacy_terminal:#}"
    );
    assert_eq!(
        packet_outbox_operation_count(&canonical_task_root.join("outbox"))?,
        1
    );
    assert_eq!(
        packet_outbox_operation_count(&legacy_task_root.join("outbox"))?,
        1
    );
    assert_eq!(
        harness.ul_assignment(project_id, task_id)?,
        baseline_assignment
    );
    let recovered_predictions: Vec<eliot_types::PredictionRecord> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::PredictionRecord,
    )?;
    assert_eq!(recovered_predictions, baseline_predictions);
    assert_eq!(harness.current_revision(project_id)?, baseline_revision);

    harness.restart_daemon()?;

    assert_eq!(
        packet_event_snapshot(&canonical_outbox.join("events"))?,
        canonical_events
    );
    assert_eq!(
        packet_event_snapshot(&legacy_outbox.join("events"))?,
        legacy_events
    );
    assert_eq!(
        std::fs::read(&canonical_authority_path)?,
        canonical_authority_bytes
    );
    assert_eq!(
        std::fs::read(&legacy_authority_path)?,
        legacy_authority_bytes
    );
    assert_eq!(
        harness.ul_assignment(project_id, task_id)?,
        baseline_assignment
    );
    let replayed_predictions: Vec<eliot_types::PredictionRecord> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::PredictionRecord,
    )?;
    assert_eq!(replayed_predictions, baseline_predictions);
    assert_eq!(harness.current_revision(project_id)?, baseline_revision);
    assert!(last_corrupt_authority.is_file());
    assert_eq!(
        std::fs::read(&misplaced_authority)?,
        canonical_authority_bytes
    );
    assert!(!misplaced_task_root.join("outbox").exists());
    Ok(())
}

fn compile(
    harness: &mut Harness,
    request_id: u64,
    project_id: ProjectId,
    task_id: TaskId,
    material_frame: Option<Value>,
    path: &str,
) -> TestResult<Value> {
    compile_with_memory_mode(
        harness,
        request_id,
        project_id,
        task_id,
        material_frame,
        path,
        "include_case_candidates",
    )
}

fn compile_with_memory_mode(
    harness: &mut Harness,
    request_id: u64,
    project_id: ProjectId,
    task_id: TaskId,
    material_frame: Option<Value>,
    path: &str,
    memory_mode: &str,
) -> TestResult<Value> {
    let mut input = json!({
        "project_id": project_id,
        "task_id": task_id,
        "goal": format!("change {path}"),
        "candidate_handles": [format!("file:{path}")],
        "max_tokens": 1_200,
        "memory_mode": memory_mode
    });
    if let Some(frame) = material_frame {
        input["material_frame"] = frame;
    }
    harness
        .client
        .tool_call(request_id, "eliot_compile_packet_l3", &input)
}

fn packet_event_snapshot(root: &std::path::Path) -> TestResult<Vec<(String, Vec<u8>)>> {
    let mut snapshot = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_file() {
            snapshot.push((
                path.file_name()
                    .ok_or("packet event file name missing")?
                    .to_string_lossy()
                    .into_owned(),
                std::fs::read(path)?,
            ));
        }
    }
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(snapshot)
}

fn packet_outbox_operation_count(root: &std::path::Path) -> TestResult<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir(root)? {
        if entry?.path().is_dir() {
            count += 1;
        }
    }
    Ok(count)
}

fn remove_terminal_packet_event(events_root: &std::path::Path) -> TestResult {
    let events = packet_event_snapshot(events_root)?;
    let (file_name, bytes) = events.last().ok_or("packet terminal event missing")?;
    let terminal: Value = serde_json::from_slice(bytes)?;
    if terminal["status"] != "complete" {
        return Err("packet terminal event is not complete".into());
    }
    std::fs::remove_file(events_root.join(file_name))?;
    Ok(())
}

fn material_frame(invariant_refs: &[String], waived_invariants: &[Value]) -> Value {
    json!({
        "acceptance_items": ["UL invariant gate is enforced"],
        "environment": ["windows-x64"],
        "active_plan": ["edit one governed file"],
        "completed_work": [],
        "killed_paths": [],
        "causal_bridge": [],
        "negative_memory_checked": true,
        "exact_load_bearing_atoms": ["file:src/invariant/lib.rs"],
        "cheapest_discriminative_probes": ["cargo test --test ul_control_treatment"],
        "responsibility_contour_route_refs": [],
        "next_allowed_action": "edit src/invariant/lib.rs",
        "expected_observable": "verifier:ul-invariant=pass",
        "verifier": "cargo test --test ul_control_treatment",
        "stop_condition": "stop on verifier failure",
        "tool_schema_bytes_visible": 1024,
        "instruction_hotset_size": 4,
        "invariant_refs": invariant_refs,
        "waived_invariants": waived_invariants,
        "prediction_confidence": "high"
    })
}

fn failure_command(project_id: ProjectId) -> SemanticCommand {
    SemanticCommand::FailureRecord(eliot_types::FailureRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None,
            scope: "ul-u9-test".to_owned(),
            authority: "test".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        fingerprint: "u9-handles-negative".to_owned(),
        summary: "negative memory payload must become handle-only".to_owned(),
        payload: json!({
            "cue_bindings": [CueBinding {
                cue_kind: CueKind::FilePath,
                cue_value: "src/net/session.rs".to_owned(),
                match_mode: CueMatchMode::Exact,
                strength: CueStrength::Primary,
                expected_reuse_note: "reuse when this exact file is touched".to_owned(),
            }]
        }),
    })
}

fn claim_command(project_id: ProjectId, claim_id: ClaimId) -> SemanticCommand {
    SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None,
            scope: "ul-u9-test".to_owned(),
            authority: "test".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        claim: ClaimCardInput {
            claim_id,
            statement: "The network session uses the governed reconnect path.".to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({
                "cue_bindings": [CueBinding {
                    cue_kind: CueKind::FilePath,
                    cue_value: "src/net/session.rs".to_owned(),
                    match_mode: CueMatchMode::Exact,
                    strength: CueStrength::Primary,
                    expected_reuse_note: "reuse when this exact file is touched".to_owned(),
                }],
                "normal_claim_payload": "must be suppressed in handles-only mode"
            }),
        },
    })
}

fn seed_invariant_capsule(prepared: &mut PreparedHarness, project_id: ProjectId) -> TestResult {
    let concept_id = format!("concept-invariant-{project_id}");
    let capsule_id = format!("capsule-invariant-{project_id}");
    let build_id = format!("build-invariant-{project_id}");
    let concept = ConceptNode {
        concept_id: concept_id.clone(),
        project_id,
        name: "invariant-subsystem".to_owned(),
        kind: ConceptKind::Subsystem,
        purpose: "Own invariant-sensitive code.".to_owned(),
        boundary_paths: vec!["src/invariant".to_owned()],
        invariant_refs: vec!["invariant:preserve-order".to_owned()],
        hotspot_refs: Vec::new(),
        entrypoint_refs: vec!["file:src/invariant/lib.rs".to_owned()],
        parent_concept_id: None,
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::Subsystem,
            cue_value: "invariant-subsystem".to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "reuse for invariant subsystem work".to_owned(),
        }],
        source_refs: Vec::new(),
    };
    let capsule = SubsystemCapsule {
        capsule_id: capsule_id.clone(),
        project_id,
        concept_id: concept_id.clone(),
        body_md: "PURPOSE\nOwn invariant-sensitive code.\n\nBOUNDARIES\n- src/invariant\n\nKEY ENTRYPOINTS\n- file:src/invariant/lib.rs\n\nINVARIANTS\n- preserve order [invariant:preserve-order]\n\nDRAGONS\n- none\n\nKEY DECISIONS\n- none\n\nVERIFIERS\n- cargo test"
            .to_owned(),
        dependency_manifest: DependencyManifest {
            project_root: std::env::current_dir()?.to_string_lossy().into_owned(),
            ..DependencyManifest::default()
        },
        build_id: build_id.clone(),
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::FilePath,
            cue_value: "src/invariant/lib.rs".to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "reuse for the invariant entrypoint".to_owned(),
        }],
        source_refs: Vec::new(),
    };
    let build = CapsuleBuild {
        build_id,
        project_id,
        target_kind: PyramidTargetKind::SubsystemCapsule,
        target_id: capsule_id.clone(),
        inputs_hash: "b".repeat(64),
        anchor_validation: vec!["test:ok".to_owned()],
        budget_limit: 1_200,
        token_estimate: ul_token_estimate(&capsule.body_md),
        status: PyramidBuildStatus::Promoted,
        previous_build_id: None,
    };
    prepared.seed(&SemanticCommand::UlArtifactBatchRecord(
        UlArtifactBatchRecordCommand {
            context: CommandContext {
                write_id: WriteId::new_v7(),
                agent_id: AgentId::new_v7(),
                session_id: None,
                project_id,
                task_id: None,
                scope: format!("project:{project_id}:ul-artifacts"),
                authority: "local-ul-builder".to_owned(),
                visibility: Visibility::Project,
                taint: TaintClass::LocalTool,
                lifecycle_status: LifecycleStatus::Active,
            },
            artifacts: vec![
                UlArtifact::ConceptNode(concept),
                UlArtifact::SubsystemCapsule(capsule),
                UlArtifact::CapsuleBuild(build),
            ],
            relations: vec![
                RelationInput {
                    relation_type: RelationType::ConceptImplementedBy,
                    from: format!("concept:{concept_id}"),
                    to: "file:src/invariant".to_owned(),
                },
                RelationInput {
                    relation_type: RelationType::CapsuleCovers,
                    from: format!("capsule:{capsule_id}"),
                    to: format!("concept:{concept_id}"),
                },
            ],
        },
    ))?;
    Ok(())
}
