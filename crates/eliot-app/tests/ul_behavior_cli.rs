#[path = "support/ul_t04.rs"]
mod support;

use eliot_engine::{GitMiningService, ModuleCardService};
use eliot_types::{
    AgentId, CoChangeEdge, CommandContext, CueBinding, CueKind, CueMatchMode, CueStrength,
    FailureRecordCommand, LifecycleStatus, ModuleCard, ProjectId, RelationInput, RelationType,
    SemanticCommand, TaintClass, UlArtifact, UlArtifactBatchRecordCommand, Visibility, WriteId,
    WriteStatus,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
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
fn h5_card_batches_replay_repair_and_heal_interrupted_mining() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("h5_card_batches_replay_repair_and_heal_interrupted_mining")? {
        return Ok(());
    }
    let harness = Harness::start("h5-card-repair")?;
    let project_id = ProjectId::new_v7();
    let cards = (0..51)
        .map(|index| replay_card(project_id, index))
        .collect::<Vec<_>>();
    let first = harness.write_module_cards("h5-run", &cards)?;
    let row_count = harness
        .ul_artifacts::<ModuleCard>(project_id, &["module_card"])?
        .len();
    let replay = harness.write_module_cards("h5-run", &cards)?;
    let replay_row_count = harness
        .ul_artifacts::<ModuleCard>(project_id, &["module_card"])?
        .len();

    assert_eq!(first.artifacts_written, 51);
    assert_eq!(first.receipts.len(), 2);
    assert_eq!(replay.artifacts_written, 0);
    assert!(
        replay
            .receipts
            .iter()
            .all(|receipt| receipt.status == WriteStatus::IdempotentReplay)
    );
    assert_eq!(row_count, replay_row_count);

    let mut changed = cards.clone();
    changed[0].failure_refs = vec!["failure:h5-new-binding".to_owned()];
    changed[0]
        .body_md
        .push_str("\nDRAGONS: failure:h5-new-binding");
    changed[0].build_fingerprint = "h5-changed".to_owned();
    let repaired = harness.write_module_cards("h5-run", &changed)?;
    assert!(
        repaired
            .receipts
            .iter()
            .any(|receipt| receipt.status == WriteStatus::Committed)
    );
    assert!(
        repaired
            .receipts
            .iter()
            .any(|receipt| receipt.status == WriteStatus::IdempotentReplay)
    );
    let canonical = harness
        .ul_artifacts::<ModuleCard>(project_id, &["module_card"])?
        .into_iter()
        .filter(|record| record.receipt_body.card_id == changed[0].card_id)
        .max_by_key(|record| {
            (
                record
                    .memory_revision
                    .map_or(0, eliot_types::MemoryRevision::value),
                record
                    .project_sequence
                    .map_or(0, eliot_types::ProjectSequence::value),
            )
        })
        .ok_or("changed canonical card missing")?;
    assert!(
        canonical
            .receipt_body
            .failure_refs
            .contains(&"failure:h5-new-binding".to_owned())
    );

    let repository = TempGitRepo::new("h5-interrupted")?;
    repository.commit(0, &["src/a.rs", "src/b.rs"], "paired files")?;
    repository.commit(1, &["src/a.rs", "src/b.rs"], "paired files")?;
    repository.commit(2, &["src/a.rs", "src/b.rs"], "paired files")?;
    repository.commit(3, &["src/a.rs", "src/b.rs"], "paired files")?;
    let interrupted_project = ProjectId::new_v7();
    let mined = GitMiningService::default().mine(
        interrupted_project,
        repository.path(),
        &BTreeMap::new(),
    )?;
    harness.seed(&mining_only_command(interrupted_project, &mined))?;
    let healed = harness.run_ul_mine_git(interrupted_project, repository.path())?;
    let healed_cards = harness.ul_artifacts::<ModuleCard>(interrupted_project, &["module_card"])?;

    assert_eq!(healed["status"], "repaired");
    assert_eq!(healed["mining_status"], "noop");
    assert_eq!(healed["card_status"], "repaired");
    assert!(!healed_cards.is_empty());
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

fn replay_card(project_id: ProjectId, index: usize) -> ModuleCard {
    ModuleCard {
        card_id: format!("h5-card-{index:03}"),
        project_id,
        path: format!("src/module-{index:03}.rs"),
        body_md: format!("PURPOSE: deterministic replay card {index}"),
        verifier: "cargo test".to_owned(),
        hotspot_ref: None,
        co_change_refs: Vec::new(),
        failure_refs: Vec::new(),
        source_refs: vec![format!("file:src/module-{index:03}.rs")],
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::FilePath,
            cue_value: format!("src/module-{index:03}.rs"),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "when editing this deterministic replay module".to_owned(),
        }],
        build_fingerprint: format!("h5-fingerprint-{index:03}"),
    }
}

fn mining_only_command(
    project_id: ProjectId,
    mined: &eliot_engine::GitMiningArtifacts,
) -> SemanticCommand {
    let mut artifacts = vec![UlArtifact::MiningRun(mined.run.clone())];
    artifacts.extend(mined.edges.iter().cloned().map(UlArtifact::CoChangeEdge));
    artifacts.extend(mined.hotspots.iter().cloned().map(UlArtifact::HotspotScore));
    let relations = mined
        .edges
        .iter()
        .map(|edge| RelationInput {
            relation_type: RelationType::CoChange,
            from: format!("file:{}", edge.path_a),
            to: format!("file:{}", edge.path_b),
        })
        .collect();
    SemanticCommand::UlArtifactBatchRecord(UlArtifactBatchRecordCommand {
        context: ul_context(project_id),
        artifacts,
        relations,
    })
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

struct TempGitRepo {
    root: PathBuf,
}

impl TempGitRepo {
    fn new(name: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root =
            std::env::temp_dir().join(format!("eliot-ul-pr-{name}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        git(&root, &["config", "core.autocrlf", "false"])?;
        git(&root, &["config", "user.name", "UL Test"])?;
        git(&root, &["config", "user.email", "ul-test@example.invalid"])?;
        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn commit(&self, index: usize, paths: &[&str], subject: &str) -> TestResult {
        for path in paths {
            let target = self.root.join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(target, format!("{subject}-{index}\n"))?;
        }
        git(&self.root, &["add", "--all"])?;
        let status = Command::new("git")
            .args(["-C"])
            .arg(&self.root)
            .args(["commit", "--quiet", "-m", subject])
            .status()?;
        if !status.success() {
            return Err(format!("git commit failed with {status}").into());
        }
        Ok(())
    }
}

impl Drop for TempGitRepo {
    fn drop(&mut self) {
        if self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-pr-"))
            && self.root.starts_with(std::env::temp_dir())
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn git(root: &Path, args: &[&str]) -> TestResult {
    let status = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!("git {args:?} failed with {status}").into());
    }
    Ok(())
}
