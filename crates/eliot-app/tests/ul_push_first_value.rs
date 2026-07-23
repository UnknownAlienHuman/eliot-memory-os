#[path = "support/ul_t04.rs"]
mod support;

use eliot_types::{
    AgentId, CommandContext, CueBinding, CueKind, CueMatchMode, CueStrength, InjectionReceipt,
    LifecycleStatus, ObservabilityKind, ProjectId, SemanticCommand, TaintClass, Visibility,
    WriteId, WriteStatus,
};
use serde_json::{Value, json};
use support::{Harness, TestResult, rerun_with_credential_gate, test_guard};

#[test]
fn t04_first_value_piggyback() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("t04_first_value_piggyback")? {
        return Ok(());
    }
    let mut harness = Harness::start("first-value")?;
    let project_id = ProjectId::new_v7();
    let fingerprint = "t04-first-value";
    let receipt = harness.seed(&failure_command(
        project_id,
        fingerprint,
        "network session repeatedly drops",
        1,
    ))?;
    assert!(matches!(
        receipt.status,
        WriteStatus::Committed | WriteStatus::IdempotentReplay
    ));
    let revision_before = harness.current_revision(project_id)?;

    let response = harness.client.tool_call(
        10,
        "eliot_current_state",
        &json!({
            "project_id": project_id,
            "path": "src/net/session.rs"
        }),
    )?;
    let revision_after = harness.current_revision(project_id)?;
    let items = response["ul_fired"]["items"]
        .as_array()
        .ok_or("ul_fired.items missing")?;

    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["item_ref"], format!("failure:{fingerprint}"));
    assert!(items[0]["payload"].is_object());
    assert_eq!(revision_before, revision_after);
    let receipts: Vec<InjectionReceipt> =
        harness.observability_records(project_id, None, ObservabilityKind::InjectionReceipt)?;
    assert!(receipts.iter().any(|receipt| {
        receipt.item_ref == format!("failure:{fingerprint}")
            && receipt.surface == "mcp_response_piggyback"
            && receipt.render_form == "payload"
    }));
    Ok(())
}

#[test]
fn t04_session_dedup_and_revision_reinject() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("t04_session_dedup_and_revision_reinject")? {
        return Ok(());
    }
    let mut harness = Harness::start("reinject")?;
    let project_id = ProjectId::new_v7();
    let fingerprint = "t04-revision";
    harness.seed(&failure_command(project_id, fingerprint, "revision one", 1))?;

    let first = touch(&mut harness, 20, project_id)?;
    let second = touch(&mut harness, 21, project_id)?;
    assert_eq!(first["ul_fired"]["items"].as_array().map(Vec::len), Some(1));
    assert!(second.get("ul_fired").is_none());

    harness.seed(&failure_command(project_id, fingerprint, "revision two", 2))?;
    let third = touch(&mut harness, 22, project_id)?;
    assert_eq!(
        third["ul_fired"]["items"][0]["payload"]["source_revision"],
        json!(2)
    );
    let receipts: Vec<InjectionReceipt> =
        harness.observability_records(project_id, None, ObservabilityKind::InjectionReceipt)?;
    let delivered = receipts
        .iter()
        .filter(|receipt| receipt.item_ref == format!("failure:{fingerprint}"))
        .collect::<Vec<_>>();
    assert_eq!(delivered.len(), 2);
    assert_ne!(
        delivered[0].source_fingerprint,
        delivered[1].source_fingerprint
    );
    Ok(())
}

#[test]
fn t04_control_mode_is_clean() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("t04_control_mode_is_clean")? {
        return Ok(());
    }
    let mut harness = Harness::start("control")?;
    let project_id = ProjectId::new_v7();
    let task_id = eliot_types::TaskId::new_v7();
    let response = harness.client.tool_call(
        30,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "compile a memory-free control packet",
            "candidate_handles": [],
            "max_tokens": 800,
            "memory_mode": "memory_free_control"
        }),
    )?;

    assert!(response.get("ul_boot").is_none());
    assert!(response.get("ul_fired").is_none());
    let receipts: Vec<InjectionReceipt> =
        harness.observability_records(project_id, None, ObservabilityKind::InjectionReceipt)?;
    assert!(receipts.is_empty());
    Ok(())
}

fn touch(harness: &mut Harness, id: u64, project_id: ProjectId) -> TestResult<Value> {
    harness.client.tool_call(
        id,
        "eliot_current_state",
        &json!({
            "project_id": project_id,
            "file_path": "src/net/session.rs"
        }),
    )
}

fn failure_command(
    project_id: ProjectId,
    fingerprint: &str,
    summary: &str,
    source_revision: u64,
) -> SemanticCommand {
    SemanticCommand::FailureRecord(eliot_types::FailureRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None,
            scope: "ul-t04-test".to_owned(),
            authority: "test".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        fingerprint: fingerprint.to_owned(),
        summary: summary.to_owned(),
        payload: json!({
            "source_revision": source_revision,
            "cue_bindings": [CueBinding {
                cue_kind: CueKind::FilePath,
                cue_value: "src/net/session.rs".to_owned(),
                match_mode: CueMatchMode::Exact,
                strength: CueStrength::Primary,
                expected_reuse_note: "Reuse when the network session implementation is touched."
                    .to_owned(),
            }]
        }),
    })
}
