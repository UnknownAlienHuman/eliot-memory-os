#[path = "support/ul_t04.rs"]
mod support;

use eliot_engine::{GitMiningService, ModuleCardService};
use eliot_types::{
    AgentId, CoChangeEdge, CommandContext, CueBinding, CueKind, CueMatchMode, CueStrength,
    FailureRecordCommand, LifecycleStatus, ProjectId, RelationInput, RelationType, SemanticCommand,
    TaintClass, UlArtifact, UlArtifactBatchRecordCommand, Visibility, WriteId, WriteStatus,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use support::{Harness, TestResult, rerun_with_credential_gate, test_guard};

#[test]
fn t05_touching_hotspot_fires_card_and_danger() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("t05_touching_hotspot_fires_card_and_danger")? {
        return Ok(());
    }
    let help = Command::new(env!("CARGO_BIN_EXE_eliot-governor"))
        .args(["ul", "mine-git", "--help"])
        .output()?;
    assert!(help.status.success());
    let help_text = String::from_utf8(help.stdout)?;
    assert!(help_text.contains("--project"));
    assert!(help_text.contains("--root"));

    let mut harness = Harness::start("t05-card-danger")?;
    let project_id = ProjectId::new_v7();
    let target_path = "crates/demo/src/lib.rs";
    harness.seed(&failure_command(project_id, target_path, 1))?;
    let initial = harness.client.tool_call(
        500,
        "eliot_current_state",
        &json!({
            "project_id": project_id,
            "file_path": target_path,
        }),
    )?;
    assert_eq!(
        initial["ul_fired"]["items"][0]["item_ref"],
        "failure:t05-hotspot-danger"
    );

    let failure_ref = "failure:t05-hotspot-danger";
    let card = build_card(project_id, target_path, failure_ref)?;
    let card_command = SemanticCommand::UlArtifactBatchRecord(UlArtifactBatchRecordCommand {
        context: ul_context(project_id),
        artifacts: vec![UlArtifact::ModuleCard(card.clone())],
        relations: vec![RelationInput {
            relation_type: RelationType::CardCovers,
            from: format!("card:{}", card.card_id),
            to: format!("file:{}", card.path),
        }],
    });
    harness.seed_many(&[failure_command(project_id, target_path, 2), card_command])?;
    harness.replace_cue_record(
        project_id,
        &format!("card:{}", card.card_id),
        "module_card",
        &card.body_md,
        &card.cue_bindings,
    )?;
    let card_ref = format!("card:{}", card.card_id);
    let cue_rows_before_touch = harness.cue_rows(project_id)?;
    assert!(
        cue_rows_before_touch
            .iter()
            .any(|row| row.record_ref == card_ref)
    );
    assert!(
        cue_rows_before_touch
            .iter()
            .any(|row| row.record_ref == failure_ref),
        "failure cue row disappeared before touch: {cue_rows_before_touch:#?}"
    );
    let cue_records_before_touch = harness.cue_records(project_id)?;
    let failure_source = cue_records_before_touch
        .iter()
        .find(|source| source.record_ref == failure_ref)
        .ok_or("failure cue source disappeared before touch")?;
    assert!(
        failure_source.preview_text.ends_with("revision 2"),
        "failure cue source was not refreshed: {failure_source:#?}"
    );
    let response = harness.client.tool_call(
        501,
        "eliot_current_state",
        &json!({
            "project_id": project_id,
            "file_path": target_path,
        }),
    )?;
    let items = response["ul_fired"]["items"]
        .as_array()
        .ok_or("ul_fired.items missing")?;
    let failure_position = items
        .iter()
        .position(|item| item["item_ref"] == failure_ref)
        .ok_or_else(|| format!("bound failure was not fired: {items:#?}"))?;
    let card_position = items
        .iter()
        .position(|item| item["item_ref"] == card_ref)
        .ok_or("module card was not fired")?;

    assert!(failure_position < card_position);
    assert!(items[failure_position]["payload"].is_object());
    assert_eq!(items[card_position]["kind"], "module_card");
    assert!(
        items[card_position]["line"]
            .as_str()
            .is_some_and(|line| line.starts_with("PURPOSE:"))
    );
    Ok(())
}

#[test]
fn h6_co_change_is_reachable_from_canonical_file_handle() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("h6_co_change_is_reachable_from_canonical_file_handle")? {
        return Ok(());
    }
    let mut harness = Harness::start("h6-file-handle")?;
    let project_id = ProjectId::new_v7();
    let receipt = harness.seed(&SemanticCommand::UlArtifactBatchRecord(
        UlArtifactBatchRecordCommand {
            context: ul_context(project_id),
            artifacts: vec![UlArtifact::CoChangeEdge(CoChangeEdge {
                edge_id: "h6-direct-edge".to_owned(),
                project_id,
                path_a: "src/a.rs".to_owned(),
                path_b: "src/b.rs".to_owned(),
                support: 1,
                confidence_ab: 1.0,
                confidence_ba: 1.0,
                last_cochange_at_unix: 0,
                static_edge_exists: None,
                mining_run_ref: "h6-direct-seed".to_owned(),
                cue_bindings: Vec::new(),
            })],
            relations: vec![RelationInput {
                relation_type: RelationType::CoChange,
                from: "file:src/a.rs".to_owned(),
                to: "file:src/b.rs".to_owned(),
            }],
        },
    ))?;
    assert_eq!(receipt.status, WriteStatus::Committed);
    assert!(
        receipt
            .created_relations
            .iter()
            .any(|kind| kind == "co_change")
    );
    let exact = harness.client.tool_call(
        510,
        "eliot_fetch_l2",
        &json!({
            "project_id": project_id,
            "handles": ["file:src/a.rs"]
        }),
    )?;
    let relations = exact["relations"]
        .as_array()
        .ok_or("L2 relations missing")?;
    assert!(
        relations.iter().any(|relation| {
            relation["relation_type"] == json!(RelationType::CoChange)
                && relation["from"] == "file:src/a.rs"
                && relation["to"] == "file:src/b.rs"
        }),
        "canonical co-change relation missing: {relations:#?}"
    );
    assert_eq!(exact["requested_handles"], json!(["file:src/a.rs"]));
    assert_eq!(exact["returned_handles"], json!(["file:src/a.rs"]));
    assert_eq!(exact["missing_handles"], json!([]));
    assert!(relations.iter().all(|relation| {
        relation["relation_type"] != json!(RelationType::CoChange)
            || (relation["from"]
                .as_str()
                .is_some_and(|value| value.starts_with("file:"))
                && relation["to"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("file:")))
    }));
    Ok(())
}

fn synthetic_history(path: &str) -> String {
    (0..4)
        .map(|index| {
            let timestamp = 1_760_100_000_i64 - i64::from(index) * 3_600;
            format!(
                "@@ELIOT@@hash{index}\u{1f}UL Test\u{1f}{timestamp}\u{1f}fix hotspot\n{path}\ncrates/demo/src/peer.rs\n"
            )
        })
        .collect::<Vec<_>>()
        .concat()
}

fn build_card(
    project_id: ProjectId,
    target_path: &str,
    failure_ref: &str,
) -> TestResult<eliot_types::ModuleCard> {
    let failure_refs = BTreeMap::from([(target_path.to_owned(), vec![failure_ref.to_owned()])]);
    let failure_density = BTreeMap::from([(target_path.to_owned(), 1)]);
    let mined = GitMiningService::default().mine_history(
        project_id,
        &synthetic_history(target_path),
        &failure_density,
    )?;
    ModuleCardService::build(
        project_id,
        Path::new("."),
        &mined.hotspots,
        &mined.edges,
        &failure_refs,
        &BTreeMap::new(),
    )?
    .into_iter()
    .find(|card| card.path == target_path)
    .ok_or_else(|| "target module card missing".into())
}

fn failure_command(project_id: ProjectId, path: &str, source_revision: u64) -> SemanticCommand {
    SemanticCommand::FailureRecord(FailureRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None,
            scope: format!("project:{project_id}:t05-failure"),
            authority: "t05-test".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        fingerprint: "t05-hotspot-danger".to_owned(),
        summary: format!("Known regression when editing the hotspot at revision {source_revision}"),
        payload: json!({
            "source_revision": source_revision,
            "cue_bindings": [CueBinding {
                cue_kind: CueKind::FilePath,
                cue_value: path.to_owned(),
                match_mode: CueMatchMode::Exact,
                strength: CueStrength::Primary,
                expected_reuse_note:
                    "when editing this module or investigating its failures".to_owned(),
            }],
        }),
    })
}

fn ul_context(project_id: ProjectId) -> CommandContext {
    CommandContext {
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
    }
}
