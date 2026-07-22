use eliot_engine::{
    DoctorService, SkillCurationGate, SkillCuratorMemoryWriter, SkillCuratorRunInput,
    SkillCuratorService, SkillPatchService, WriteAdmissionService, WriterActor, WriterConfig,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    ControlWalConfig, GovernorConfig, ProjectId, SkillCardV2, SkillCurationAction,
    SkillCurationDecisionKind, SkillCurationGateReason, SkillCurationProposal, SkillCurationReason,
    SkillFailureMode, SkillId, SkillInputRequirement, SkillInputSource, SkillLevel,
    SkillLifecycleState, SkillOutputSpec, SkillPatchProposal, SkillReplayRequirement,
    SkillScopeRule, SkillStep, SkillToolRequirement, VerifierCommandKind, VerifierPlan,
    VerifierRequirement,
};
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn skill_curator_run_created() {
    let project_id = ProjectId::new_v7();
    let run = SkillCuratorService::run(SkillCuratorRunInput {
        project_id,
        project: "eliot-governor".to_owned(),
        dry_run: true,
        skills: vec![active_skill("stable")],
    });

    assert_eq!(run.project_id, project_id);
    assert!(run.run_id.starts_with("skill-curator-run-"));
    assert!(run.dry_run);
    assert!(!run.proposals.is_empty());
}

#[test]
fn skill_curator_collects_usage_data() {
    let run = SkillCuratorService::run(SkillCuratorRunInput {
        project_id: ProjectId::new_v7(),
        project: "eliot-governor".to_owned(),
        dry_run: true,
        skills: vec![active_skill("usage")],
    });

    assert!(
        run.usage_sources
            .iter()
            .any(|source| source.contains("success_count"))
    );
    assert!(
        run.usage_sources
            .iter()
            .any(|source| source.contains("context_cost"))
    );
}

#[test]
fn skill_curator_proposes_keep_for_repeated_success() {
    let proposals =
        SkillCuratorService::proposals_for_skill(ProjectId::new_v7(), &active_skill("keep"));
    assert!(has_reason(&proposals, SkillCurationReason::RepeatedSuccess));
}

#[test]
fn skill_curator_proposes_patch_for_missing_where_not_apply() {
    let mut skill = active_skill("missing anti scope");
    skill.does_not_apply_when.clear();
    let proposals = SkillCuratorService::proposals_for_skill(ProjectId::new_v7(), &skill);
    let proposal = proposal_with_action(&proposals, SkillCurationAction::Patch);
    assert_eq!(proposal.reason, SkillCurationReason::MissingWhereNotApply);
    assert!(
        proposal
            .patch
            .as_ref()
            .is_some_and(|patch| patch.narrows_scope)
    );
}

#[test]
fn skill_curator_proposes_archive_for_low_utility_high_cost() {
    let mut skill = active_skill("archive");
    skill.success_count = 0;
    skill.failure_count = 5;
    skill.ordered_steps.extend((0..20).map(|index| SkillStep {
        step_id: format!("expensive-{index}"),
        order: index + 10,
        instruction: "large context cost step with repeated low utility".repeat(4),
        expected_observation: None,
        required_tool_or_capability: None,
        stop_if_fails: false,
    }));

    let proposals = SkillCuratorService::proposals_for_skill(ProjectId::new_v7(), &skill);
    assert!(has_action(&proposals, SkillCurationAction::Archive));
}

#[test]
fn skill_curator_proposes_quarantine_for_negative_transfer() {
    let mut skill = active_skill("quarantine");
    skill.success_count = 0;
    skill.failure_count = 2;
    skill.known_failure_modes.push(SkillFailureMode {
        failure_id: "negative-transfer".to_owned(),
        description: "negative transfer into unrelated task".to_owned(),
        detection_signal: "negative-transfer".to_owned(),
        mitigation: "quarantine and retain audit trail".to_owned(),
        negative_memory_refs: vec!["failure:negative-transfer".to_owned()],
    });

    let proposals = SkillCuratorService::proposals_for_skill(ProjectId::new_v7(), &skill);
    assert!(has_action(&proposals, SkillCurationAction::Quarantine));
}

#[test]
fn skill_curator_proposes_split_for_overbroad_skill() {
    let mut skill = active_skill("split");
    skill.applies_when.push(scope_rule("any project rust task"));
    skill.applies_when.push(scope_rule("all tasks with tools"));

    let proposals = SkillCuratorService::proposals_for_skill(ProjectId::new_v7(), &skill);
    let proposal = proposal_with_action(&proposals, SkillCurationAction::Split);
    assert!(proposal.replay_requirement.required);
}

#[test]
fn skill_curator_proposes_merge_for_duplicate_skills() {
    let first = active_skill("duplicate");
    let mut second = first.clone();
    second.skill_id = SkillId::new_v7();
    let proposals =
        SkillCuratorService::proposals_for_skills(ProjectId::new_v7(), &[first, second]);

    assert!(has_action(&proposals, SkillCurationAction::Merge));
}

#[test]
fn curation_gate_denies_auto_promotion() {
    let proposal = proposal_for_action(SkillCurationAction::Promote);
    let decision = SkillCurationGate::decide(&proposal, false);

    assert_eq!(decision.decision, SkillCurationDecisionKind::Deny);
    assert!(
        decision
            .reasons
            .contains(&SkillCurationGateReason::AutoPromotionDenied)
    );
}

#[test]
fn curation_gate_requires_replay_for_scope_broadening() {
    let mut proposal = proposal_for_action(SkillCurationAction::Patch);
    proposal.patch = Some(SkillPatchProposal {
        broadens_scope: true,
        ..safe_patch(proposal.skill_ref)
    });
    proposal.replay_requirement = SkillReplayRequirement {
        required: true,
        reason: "scope broadening".to_owned(),
        replay_marker: None,
        verifier_refs: vec!["just verify".to_owned()],
    };

    let decision = SkillCurationGate::decide(&proposal, false);
    assert_eq!(decision.decision, SkillCurationDecisionKind::RequireReplay);
}

#[test]
fn curation_gate_denies_removing_anti_scope_without_evidence() {
    let mut proposal = proposal_for_action(SkillCurationAction::Patch);
    proposal.patch = Some(SkillPatchProposal {
        removes_anti_scope: true,
        reviewer_refs: Vec::new(),
        ..safe_patch(proposal.skill_ref)
    });

    let decision = SkillCurationGate::decide(&proposal, false);
    assert_eq!(decision.decision, SkillCurationDecisionKind::Deny);
    assert!(
        decision
            .reasons
            .contains(&SkillCurationGateReason::RemovingAntiScopeDenied)
    );
}

#[test]
fn curation_gate_denies_verifier_weakening_without_review() {
    let mut proposal = proposal_for_action(SkillCurationAction::Patch);
    proposal.patch = Some(SkillPatchProposal {
        weakens_verifier: true,
        reviewer_refs: Vec::new(),
        ..safe_patch(proposal.skill_ref)
    });

    let decision = SkillCurationGate::decide(&proposal, false);
    assert_eq!(decision.decision, SkillCurationDecisionKind::Deny);
    assert!(
        decision
            .reasons
            .contains(&SkillCurationGateReason::VerifierWeakeningDenied)
    );
}

#[test]
fn curation_gate_allows_safe_archive() {
    let proposal = proposal_for_action(SkillCurationAction::Archive);
    let decision = SkillCurationGate::decide(&proposal, false);

    assert_eq!(decision.decision, SkillCurationDecisionKind::Allow);
    assert_eq!(decision.allowed_action, Some(SkillCurationAction::Archive));
}

#[test]
fn curation_gate_allows_safe_quarantine() {
    let proposal = proposal_for_action(SkillCurationAction::Quarantine);
    let decision = SkillCurationGate::decide(&proposal, false);

    assert_eq!(decision.decision, SkillCurationDecisionKind::Allow);
    assert_eq!(
        decision.allowed_action,
        Some(SkillCurationAction::Quarantine)
    );
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn skill_patch_candidate_written_through_writer_actor() -> TestResult {
    let harness = Harness::new("patch-candidate").await?;
    let (handle, actor) = harness.writer_pair("patch-candidate")?;
    let actor_task = tokio::spawn(actor.run());
    let mut proposal = proposal_for_action(SkillCurationAction::Patch);
    proposal.patch = Some(safe_patch(proposal.skill_ref));
    let receipt = SkillCuratorMemoryWriter::write_candidate_patch(
        &handle,
        &WriteAdmissionService,
        &mut proposal,
    )
    .await?;

    drop(handle);
    actor_task.await?;

    assert_eq!(
        proposal.write_receipt.as_ref().map(|r| r.write_id),
        Some(receipt.write_id)
    );
    Ok(())
}

#[test]
fn skill_safe_narrow_patch_apply_when_allowed() {
    let skill = active_skill("patch apply");
    let mut proposal = proposal_for_action(SkillCurationAction::Patch);
    proposal.patch = Some(safe_patch(skill.skill_id));

    let patched = match SkillPatchService::apply_narrow_patch(&skill, &proposal) {
        Ok(patched) => patched,
        Err(decision) => panic!("patch allowed: {decision:?}"),
    };
    assert!(
        patched
            .source_trace_refs
            .iter()
            .any(|reference| reference.starts_with("skill-curation-patch:"))
    );
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn skill_archive_receipt_written_through_writer_actor() -> TestResult {
    let harness = Harness::new("archive-receipt").await?;
    let (handle, actor) = harness.writer_pair("archive-receipt")?;
    let actor_task = tokio::spawn(actor.run());
    let proposal = proposal_for_action(SkillCurationAction::Archive);
    let receipt =
        SkillCuratorMemoryWriter::write_archive_receipt(&handle, &WriteAdmissionService, &proposal)
            .await?;

    drop(handle);
    actor_task.await?;

    assert!(receipt.write_receipt.is_some());
    Ok(())
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn skill_quarantine_receipt_written_through_writer_actor() -> TestResult {
    let harness = Harness::new("quarantine-receipt").await?;
    let (handle, actor) = harness.writer_pair("quarantine-receipt")?;
    let actor_task = tokio::spawn(actor.run());
    let proposal = proposal_for_action(SkillCurationAction::Quarantine);
    let receipt = SkillCuratorMemoryWriter::write_quarantine_receipt(
        &handle,
        &WriteAdmissionService,
        &proposal,
    )
    .await?;

    drop(handle);
    actor_task.await?;

    assert!(receipt.write_receipt.is_some());
    Ok(())
}

#[test]
fn archived_skill_excluded_from_normal_l3() {
    let archived = skill_with_state("archived", SkillLifecycleState::Archived);
    let active = active_skill("active");
    let visible = SkillCuratorService::visible_for_normal_l3(&[archived, active]);

    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].name, "active");
}

#[test]
fn quarantined_skill_excluded_from_normal_l3() {
    let quarantined = skill_with_state("quarantined", SkillLifecycleState::Quarantined);
    let active = active_skill("active");
    let visible = SkillCuratorService::visible_for_normal_l3(&[quarantined, active]);

    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].name, "active");
}

#[test]
fn candidate_patch_not_in_normal_l3() {
    let skill = active_skill("base");
    let proposal = proposal_for_action(SkillCurationAction::Patch);
    let candidate = SkillPatchService::candidate_patch_skill(&skill, &proposal);
    let visible = SkillCuratorService::visible_for_normal_l3(&[skill, candidate]);

    assert_eq!(visible.len(), 1);
    assert_ne!(visible[0].owner, "skill-curator-candidate");
}

#[test]
fn doctor_reports_open_curation_proposals() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "eliot-skill-curation-doctor-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("reports/skill-curation-proposals"))?;
    fs::write(
        root.join("reports/skill-curation-proposals/latest.json"),
        r#"{"open_proposals":[{"id":"one"},{"id":"two"}]}"#,
    )?;
    let report = DoctorService::new(&root, repo_root()).report()?;

    assert_eq!(report.open_skill_curation_proposals, 2);
    Ok(())
}

#[test]
fn incident_lockdown_blocks_skill_patch_apply() {
    let mut proposal = proposal_for_action(SkillCurationAction::Patch);
    proposal.patch = Some(safe_patch(proposal.skill_ref));

    let decision = SkillCurationGate::decide(&proposal, true);
    assert_eq!(decision.decision, SkillCurationDecisionKind::Deny);
    assert!(
        decision
            .reasons
            .contains(&SkillCurationGateReason::IncidentLockdown)
    );
}

#[test]
fn accumulated_capabilities_non_regression() {
    let project_id = ProjectId::new_v7();
    let task_id = eliot_types::TaskId::new_v7();
    let active = active_skill("skill curation skill lifecycle");
    let archived = skill_with_state("archived", SkillLifecycleState::Archived);
    let packet = SkillCuratorService::procedural_packet(
        project_id,
        task_id,
        &[active, archived],
        &eliot_engine::SkillActivationContext {
            goal: "skill curation skill lifecycle".to_owned(),
            evidence_refs: vec!["runbook:skill-curation".to_owned()],
            available_input_sources: vec![SkillInputSource::UserPrompt],
            available_input_names: vec!["task_goal".to_owned()],
            available_capabilities: vec!["rust-toolchain".to_owned()],
            available_tools: vec!["cargo".to_owned()],
            verifier_refs: vec!["just verify".to_owned()],
            active_negative_signals: Vec::new(),
            conflicting_skill_refs: Vec::new(),
            audit_mode: false,
        },
    );
    assert_eq!(packet.activation_decisions.len(), 1);
}

fn has_reason(proposals: &[SkillCurationProposal], reason: SkillCurationReason) -> bool {
    proposals.iter().any(|proposal| proposal.reason == reason)
}

fn has_action(proposals: &[SkillCurationProposal], action: SkillCurationAction) -> bool {
    proposals.iter().any(|proposal| proposal.action == action)
}

fn proposal_with_action(
    proposals: &[SkillCurationProposal],
    action: SkillCurationAction,
) -> &SkillCurationProposal {
    match proposals.iter().find(|proposal| proposal.action == action) {
        Some(proposal) => proposal,
        None => panic!("proposal present for action {action:?}"),
    }
}

fn proposal_for_action(action: SkillCurationAction) -> SkillCurationProposal {
    let skill = active_skill("proposal");
    SkillCuratorService::proposals_for_skill(ProjectId::new_v7(), &skill)
        .into_iter()
        .find(|proposal| proposal.action == action)
        .unwrap_or_else(|| {
            let mut skill = match action {
                SkillCurationAction::Archive => {
                    let mut skill = active_skill("archive");
                    skill.success_count = 0;
                    skill.failure_count = 5;
                    skill.ordered_steps.extend((0..20).map(|index| SkillStep {
                        step_id: format!("expensive-{index}"),
                        order: index + 10,
                        instruction: "large context cost step".repeat(4),
                        expected_observation: None,
                        required_tool_or_capability: None,
                        stop_if_fails: false,
                    }));
                    skill
                }
                SkillCurationAction::Quarantine => {
                    let mut skill = active_skill("quarantine");
                    skill.success_count = 0;
                    skill.failure_count = 2;
                    skill.known_failure_modes.push(SkillFailureMode {
                        failure_id: "negative-transfer".to_owned(),
                        description: "negative transfer".to_owned(),
                        detection_signal: "negative-transfer".to_owned(),
                        mitigation: "quarantine".to_owned(),
                        negative_memory_refs: Vec::new(),
                    });
                    skill
                }
                _ => active_skill("manual"),
            };
            if action == SkillCurationAction::Patch {
                skill.does_not_apply_when.clear();
            }
            let mut proposal =
                SkillCuratorService::proposals_for_skill(ProjectId::new_v7(), &skill)
                    .into_iter()
                    .find(|proposal| proposal.action == action)
                    .unwrap_or_else(|| {
                        let mut proposal = SkillCuratorService::proposals_for_skill(
                            ProjectId::new_v7(),
                            &active_skill("keep"),
                        )
                        .remove(0);
                        proposal.action = action;
                        proposal
                    });
            proposal.evidence_refs = vec!["evidence:skill-curation".to_owned()];
            proposal
        })
}

fn safe_patch(skill_id: SkillId) -> SkillPatchProposal {
    SkillPatchProposal {
        target_skill: skill_id,
        patch_summary: "safe narrow anti-scope patch".to_owned(),
        candidate_content_ref: "skill-patch-candidate:test".to_owned(),
        narrows_scope: true,
        broadens_scope: false,
        removes_anti_scope: false,
        weakens_verifier: false,
        reviewer_refs: Vec::new(),
    }
}

fn active_skill(name: &str) -> SkillCardV2 {
    skill_with_state(name, SkillLifecycleState::Active)
}

fn skill_with_state(name: &str, state: SkillLifecycleState) -> SkillCardV2 {
    let now = time::OffsetDateTime::now_utc();
    SkillCardV2 {
        skill_id: SkillId::new_v7(),
        name: name.to_owned(),
        purpose: "skill curation skill lifecycle curation".to_owned(),
        level: SkillLevel::Procedure,
        lifecycle_state: state,
        applies_when: vec![scope_rule("skill curation skill lifecycle")],
        does_not_apply_when: vec![scope_rule("unrelated task")],
        required_inputs: vec![SkillInputRequirement {
            name: "task_goal".to_owned(),
            description: "current governed task goal".to_owned(),
            required: true,
            source: SkillInputSource::UserPrompt,
        }],
        ordered_steps: vec![SkillStep {
            step_id: "ground-skill".to_owned(),
            order: 1,
            instruction: "Check scope, anti-scope, and verifier plan.".to_owned(),
            expected_observation: Some("scope grounded".to_owned()),
            required_tool_or_capability: Some("rust-toolchain".to_owned()),
            stop_if_fails: true,
        }],
        required_tools_and_capabilities: vec![SkillToolRequirement {
            capability: "rust-toolchain".to_owned(),
            required: true,
            allowed_tools: vec!["cargo".to_owned()],
            forbidden_tools: vec!["raw sql".to_owned()],
        }],
        expected_outputs: vec![SkillOutputSpec {
            name: "curation_evidence".to_owned(),
            description: "curation evidence".to_owned(),
            evidence_required: true,
            verifier_required: true,
        }],
        verification_plan: verifier_plan(),
        stop_conditions: vec!["missing verifier".to_owned()],
        known_failure_modes: vec![SkillFailureMode {
            failure_id: "scope-drift".to_owned(),
            description: "scope drift".to_owned(),
            detection_signal: "scope-drift".to_owned(),
            mitigation: "exclude skill".to_owned(),
            negative_memory_refs: Vec::new(),
        }],
        rollback_or_recovery: Some("restore previous SkillCardV2".to_owned()),
        source_trace_refs: vec!["runbook:skill-curation".to_owned()],
        replay_result_refs: vec!["replay:skill-curation".to_owned()],
        success_count: 3,
        failure_count: 0,
        last_verified_at: Some(now),
        version: "0.1.0".to_owned(),
        owner: "skill-curation-test".to_owned(),
        created_at: now,
        updated_at: now,
    }
}

fn scope_rule(description: &str) -> SkillScopeRule {
    SkillScopeRule {
        rule_id: description.replace(' ', "-"),
        description: description.to_owned(),
        positive_examples: vec![description.to_owned()],
        negative_examples: Vec::new(),
        required_evidence_refs: Vec::new(),
    }
}

fn verifier_plan() -> VerifierPlan {
    VerifierPlan {
        required: vec![VerifierRequirement {
            name: "just-verify".to_owned(),
            command_kind: VerifierCommandKind::CargoTest,
            command_display: "just verify".to_owned(),
            scope: vec!["crates/eliot-engine/src/skill_curator.rs".to_owned()],
            required_for_done: true,
            expected_signal: "passes".to_owned(),
        }],
        optional: Vec::new(),
        acceptance_items: vec!["skill curator proposal remains governed".to_owned()],
    }
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
}

impl Harness {
    async fn new(name: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "eliot-skill-curation-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let mut config = GovernorConfig::default();
        let repo = repo_root();
        config.db.surreal.password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")
            .unwrap_or_else(|_| {
                repo.join(".eliot-governor/secrets/surreal_root_password.txt")
                    .display()
                    .to_string()
            });
        config.db.surreal.storage =
            std::env::var("ELIOT_TEST_SURREAL_STORAGE").unwrap_or_else(|_| {
                format!(
                    "rocksdb:{}",
                    repo.join(".eliot-governor/surrealdb-rocks").display()
                )
            });
        if let Ok(bind) = std::env::var("ELIOT_TEST_SURREAL_BIND") {
            config.db.surreal.bind = bind;
        }
        if let Ok(endpoint) = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT") {
            config.db.surreal.endpoint = endpoint;
        }
        let store = CanonicalStore::new(config.db.surreal);
        migrate_schema_locked(&store).await?;
        Ok(Self { root, store })
    }

    fn writer_pair(&self, name: &str) -> TestResult<(eliot_engine::WriterHandle, WriterActor)> {
        let path = self.root.join(name).join("control.redb");
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        Ok(WriterActor::channel(
            wal,
            self.store.clone(),
            &WriterConfig::default(),
        ))
    }
}

async fn migrate_schema_locked(store: &CanonicalStore) -> TestResult {
    static MIGRATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _guard = MIGRATION_LOCK.lock().await;
    store.migrate_schema().await?;
    Ok(())
}

fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| manifest_dir.to_path_buf(), Path::to_path_buf)
}
