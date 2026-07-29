#[path = "support/ul_t04.rs"]
mod support;

use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, CommandContext, CueBinding, CueStrength, EpistemicStatus,
    InjectionReceipt, LifecycleStatus, MaterialPacketFrame, MemoryInfluenceTrace,
    ObservabilityKind, ProjectId, SemanticCommand, TaintClass, TaskId, VerificationResult,
    VerificationRunInput, Visibility, WriteId,
};
use serde_json::json;
use support::{Harness, TestResult, rerun_with_credential_gate, test_guard};

#[test]
fn t04_auto_bind_uses_touched_path() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("t04_auto_bind_uses_touched_path")? {
        return Ok(());
    }
    let mut harness = Harness::start("auto-bind")?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    harness.create_task(40, project_id, task_id)?;
    harness.client.tool_call(
        41,
        "eliot_current_state",
        &json!({"project_id": project_id, "path": "src/other/cache.rs"}),
    )?;
    harness.client.tool_call(
        42,
        "eliot_current_state",
        &json!({"project_id": project_id, "path": "src/net/session.rs"}),
    )?;
    let write_id = WriteId::new_v7();
    let response = harness.client.tool_call(
        43,
        "eliot_agent_candidate_submit",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": write_id,
            "topic": "network session ownership",
            "statement": "The implementation in src/net/session.rs owns reconnection.",
            "where_applicable": [],
            "where_not_applicable": [],
            "negative_constraints": [],
            "provenance_refs": ["task:t04:auto-bind"],
            "freshness_rule": "recheck after network layout changes",
            "expected_reuse_note": "Reuse when network session code is active."
        }),
    )?;

    assert_eq!(response["cue_binding_summary"]["source"], "auto");
    assert_eq!(response["cue_binding_summary"]["primary"], 1);
    assert_eq!(response["cue_binding_summary"]["secondary"], 1);
    let claim_id = ClaimId::from_uuid(write_id.as_uuid());
    let claim = harness
        .claim(project_id, claim_id)?
        .ok_or("auto-bound candidate missing")?;
    let bindings: Vec<CueBinding> = serde_json::from_value(claim.payload["cue_bindings"].clone())?;
    let primary = bindings
        .iter()
        .find(|binding| binding.strength == CueStrength::Primary)
        .ok_or("primary binding missing")?;
    assert_eq!(primary.cue_value, "src/net/session.rs");
    assert!(bindings.iter().any(|binding| {
        binding.strength == CueStrength::Secondary && binding.cue_value == "src/other/cache.rs"
    }));
    let rows = harness.cue_rows(project_id)?;
    assert!(rows.iter().any(|row| {
        row.record_ref == format!("claim:{claim_id}") && row.cue_value_norm == "src/net/session.rs"
    }));
    assert!(rows.iter().any(|row| {
        row.record_ref == format!("claim:{claim_id}") && row.cue_value_norm == "src/other/cache.rs"
    }));
    Ok(())
}

#[test]
fn t04_minimal_ack_derives_full_trace() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("t04_minimal_ack_derives_full_trace")? {
        return Ok(());
    }
    let mut harness = Harness::start("minimal-ack")?;
    let project_id = ProjectId::new_v7();
    let task_id = create_treatment_task(&mut harness, 50, project_id)?;
    let claim_id = ClaimId::new_v7();
    let handle = format!("claim:{claim_id}");
    harness.seed(&claim_propose(project_id, task_id, claim_id))?;
    harness.seed(&claim_verify(project_id, task_id, claim_id))?;
    let packet = harness.client.tool_call(
        53,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "use the verified network claim",
            "candidate_handles": [handle],
            "max_tokens": 1200
        }),
    )?;
    let packet_id = packet["packet_id"]
        .as_str()
        .ok_or("compiled packet id missing")?
        .to_owned();
    assert!(
        packet["exact_handles"]
            .as_array()
            .is_some_and(|handles| handles.iter().any(|candidate| candidate == &json!(handle)))
    );

    let response = harness.client.tool_call(
        54,
        "eliot_memory_influence_trace",
        &json!({
            "project_id": project_id,
            "memory_handle": handle,
            "influence_class": "used_and_changed_action",
            "downstream_outcome_ref": "outcome:t04:minimal-ack"
        }),
    )?;
    assert_eq!(response["observability_receipt"]["status"], "committed");
    let traces: Vec<MemoryInfluenceTrace> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::MemoryInfluenceTrace,
    )?;
    assert_eq!(traces.len(), 1);
    let trace = &traces[0];
    assert_eq!(trace.task_id, task_id);
    assert_eq!(trace.memory_handle, handle);
    assert_eq!(trace.packet_id, packet_id);
    assert_eq!(
        trace.admission_decision,
        eliot_types::MemoryAdmissionDecision::IncludeVerified
    );
    assert_eq!(
        trace.inclusion_or_suppression_reason,
        "ack:used_and_changed_action"
    );
    assert_eq!(trace.epistemic_status_at_use, "verified");
    assert!(trace.cited_in_understanding_proof);
    assert!(trace.action_or_probe_changed);
    assert!(!trace.write_set_changed);
    assert!(!trace.verifier_changed);
    assert!(!trace.repeated_failure_prevented);
    assert!(!trace.suppressed_as_stale_or_wrong_scope);
    assert_eq!(
        trace.downstream_outcome_ref.as_deref(),
        Some("outcome:t04:minimal-ack")
    );
    assert_eq!(
        trace.influence_class,
        eliot_types::MemoryInfluenceClass::UsedAndChangedAction
    );
    assert!(trace.canonical_receipt.is_none());

    let rejected = harness.client.tool_call_response(
        55,
        "eliot_memory_influence_trace",
        &json!({
            "project_id": project_id,
            "memory_handle": handle,
            "influence_class": "used_and_changed_action"
        }),
    )?;
    assert_eq!(
        rejected["error"]["message"],
        "write rejected: claimed memory influence requires a downstream outcome reference"
    );
    let after: Vec<MemoryInfluenceTrace> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::MemoryInfluenceTrace,
    )?;
    assert_eq!(after.len(), 1);
    Ok(())
}

#[test]
fn t04_frame_stub_and_boot() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("t04_frame_stub_and_boot")? {
        return Ok(());
    }
    let mut harness = Harness::start("frame-boot")?;
    let project_id = ProjectId::new_v7();
    let first = harness.client.tool_call(
        60,
        "eliot_current_state",
        &json!({"project_id": project_id}),
    )?;
    assert_eq!(first["ul_boot"]["status"], "not_onboarded");
    let second = harness.client.tool_call(
        61,
        "eliot_current_state",
        &json!({"project_id": project_id}),
    )?;
    assert!(second.get("ul_boot").is_none());
    let boot_receipts: Vec<InjectionReceipt> =
        harness.observability_records(project_id, None, ObservabilityKind::InjectionReceipt)?;
    assert_eq!(
        boot_receipts
            .iter()
            .filter(|receipt| receipt.item_ref == "ul_boot:not_onboarded")
            .count(),
        1
    );

    let task_id = create_treatment_task(&mut harness, 62, project_id)?;
    let packet = harness.client.tool_call(
        65,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "compile a complete material frame stub",
            "candidate_handles": [],
            "max_tokens": 1200
        }),
    )?;
    let mut frame: MaterialPacketFrame = serde_json::from_value(packet["frame_stub"].clone())?;
    assert!(frame.expected_observable.is_empty());
    assert!(frame.predicted_failing_verifiers.is_empty());
    assert_eq!(
        packet["frame_stub_required_edits"],
        json!(["material_frame.expected_observable"])
    );
    assert_eq!(packet["frame_stub_ready"], false);
    let rejected = harness.client.tool_call_response(
        66,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "compile a complete material frame stub",
            "candidate_handles": [],
            "max_tokens": 1200,
            "material_frame": frame.clone()
        }),
    )?;
    assert_eq!(rejected["error"]["code"], -32602);
    assert_eq!(
        rejected["error"]["data"]["invalid"],
        json!([{
            "field": "material_frame.expected_observable",
            "reason": "material work requires a machine-checkable expected observable"
        }])
    );
    assert!(
        rejected["error"]["data"]["minimal_valid_example"]["material_frame"]["expected_observable"]
            .as_str()
            .is_some_and(|value| value.starts_with("verifier:") && value.ends_with("=pass"))
    );
    frame.expected_observable = format!("verifier:{}=pass", frame.verifier);
    let resubmitted = harness.client.tool_call(
        67,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "compile a complete material frame stub",
            "candidate_handles": [],
            "max_tokens": 1200,
            "material_frame": frame
        }),
    )?;
    assert!(
        resubmitted["prediction_refs"]
            .as_array()
            .is_some_and(|references| !references.is_empty())
    );
    assert!(resubmitted["packet_id"].is_string());
    Ok(())
}

fn create_treatment_task(
    harness: &mut Harness,
    request_id: u64,
    project_id: ProjectId,
) -> TestResult<TaskId> {
    let control_task_id = TaskId::new_v7();
    harness.create_task(request_id, project_id, control_task_id)?;
    harness.client.tool_call(
        request_id + 1,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": control_task_id,
            "goal": "reserve the deterministic memory-free control arm",
            "candidate_handles": [],
            "max_tokens": 500
        }),
    )?;
    let treatment_task_id = TaskId::new_v7();
    harness.create_task(request_id + 2, project_id, treatment_task_id)?;
    Ok(treatment_task_id)
}

fn command_context(project_id: ProjectId, task_id: TaskId) -> CommandContext {
    CommandContext {
        write_id: WriteId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(task_id),
        scope: "ul-t04-test".to_owned(),
        authority: "test".to_owned(),
        visibility: Visibility::Project,
        taint: TaintClass::LocalVerified,
        lifecycle_status: LifecycleStatus::Active,
    }
}

fn claim_propose(project_id: ProjectId, task_id: TaskId, claim_id: ClaimId) -> SemanticCommand {
    SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: command_context(project_id, task_id),
        claim: ClaimCardInput {
            claim_id,
            statement: "The network session owns verified reconnection behavior.".to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({"source": "t04"}),
        },
    })
}

fn claim_verify(project_id: ProjectId, task_id: TaskId, claim_id: ClaimId) -> SemanticCommand {
    SemanticCommand::ClaimVerify(eliot_types::ClaimVerifyCommand {
        context: command_context(project_id, task_id),
        claim_id,
        verification: VerificationRunInput {
            verification_id: eliot_types::VerificationId::new_v7(),
            claim_id: Some(claim_id),
            verifier: "t04-verifier".to_owned(),
            result: VerificationResult::Passed,
            summary: "verified for minimal acknowledgement".to_owned(),
            payload: json!({"verified": true}),
        },
        statement: Some("The network session owns verified reconnection behavior.".to_owned()),
        payload: json!({"source": "t04", "state": "verified"}),
    })
}
