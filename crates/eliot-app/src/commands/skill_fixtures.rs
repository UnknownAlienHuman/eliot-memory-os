//! Fixtures for the skill and curator smoke commands.
//!
//! These build the skill cards, contexts and curator runs that the smoke
//! commands exercise. They are deterministic sample data, not product
//! behaviour, and they were named after the milestones that first needed them.

// Fixtures are built from the parent's private command types; keeping that
// vocabulary in the parent avoids a second public API just for test data.
#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn smoke_skill_cards() -> Vec<SkillCardV2> {
    vec![
        SkillRegistryService::create_candidate("skill smoke candidate", "codex"),
        smoke_active_skill(),
        smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Stale),
        smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Archived),
        smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Quarantined),
    ]
}

pub(super) fn smoke_filter_skill_cards() -> Vec<SkillCardV2> {
    vec![
        smoke_active_skill(),
        smoke_irrelevant_skill(),
        smoke_rare_skill(),
        SkillRegistryService::create_candidate("skill smoke candidate", "codex"),
    ]
}

pub(super) fn smoke_active_skill() -> SkillCardV2 {
    smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active)
}

pub(super) fn smoke_rare_skill() -> SkillCardV2 {
    let mut skill = smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "rare verifier routing".clone_into(&mut skill.name);
    skill.success_count = 0;
    skill.failure_count = 0;
    skill.source_trace_refs = vec!["evidence:rare-skill-protected".to_owned()];
    skill
}

pub(super) fn smoke_irrelevant_skill() -> SkillCardV2 {
    let mut skill = smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "Irrelevant release-note writing".clone_into(&mut skill.name);
    skill.applies_when = vec![SkillScopeRule {
        rule_id: "release-notes".to_owned(),
        description: "release note drafting".to_owned(),
        positive_examples: vec!["release notes".to_owned()],
        negative_examples: vec!["skill lifecycle smoke".to_owned()],
        required_evidence_refs: Vec::new(),
    }];
    skill
}

pub(super) fn smoke_active_skill_with_id(skill_id: SkillId, state: SkillState) -> SkillCardV2 {
    let now = time::OffsetDateTime::now_utc();
    SkillCardV2 {
        skill_id,
        name: "skill lifecycle smoke".to_owned(),
        purpose: "govern procedural skill activation, L3 inclusion, and execution proof".to_owned(),
        level: eliot_types::SkillLevel::Procedure,
        lifecycle_state: state,
        applies_when: vec![SkillScopeRule {
            rule_id: "skill-smoke-scope".to_owned(),
            description: "skill lifecycle smoke".to_owned(),
            positive_examples: vec!["skill-smoke".to_owned(), "skill lifecycle".to_owned()],
            negative_examples: vec!["release notes".to_owned()],
            required_evidence_refs: vec!["evidence:skill-smoke".to_owned()],
        }],
        does_not_apply_when: vec![SkillScopeRule {
            rule_id: "skill-smoke-anti-scope".to_owned(),
            description: "raw sql or external agent bypass".to_owned(),
            positive_examples: vec!["raw sql".to_owned(), "external agent".to_owned()],
            negative_examples: vec!["governed skill proof".to_owned()],
            required_evidence_refs: Vec::new(),
        }],
        required_inputs: vec![
            SkillInputRequirement {
                name: "task_goal".to_owned(),
                description: "current user task".to_owned(),
                required: true,
                source: SkillInputSource::UserPrompt,
            },
            SkillInputRequirement {
                name: "verifier_plan".to_owned(),
                description: "required verifier plan for completion".to_owned(),
                required: true,
                source: SkillInputSource::VerifierPlan,
            },
        ],
        ordered_steps: vec![
            SkillStep {
                step_id: "inspect-scope".to_owned(),
                order: 1,
                instruction: "Confirm scope, anti-scope, required inputs, and lifecycle state."
                    .to_owned(),
                expected_observation: Some("activation gate decision is explicit".to_owned()),
                required_tool_or_capability: None,
                stop_if_fails: true,
            },
            SkillStep {
                step_id: "run-verifier".to_owned(),
                order: 2,
                instruction: "Run required verifier and attach refs to SkillExecutionProof."
                    .to_owned(),
                expected_observation: Some("verifier refs are present".to_owned()),
                required_tool_or_capability: Some("rust-verifier".to_owned()),
                stop_if_fails: true,
            },
        ],
        required_tools_and_capabilities: vec![SkillToolRequirement {
            capability: "rust-verifier".to_owned(),
            required: true,
            allowed_tools: vec!["cargo".to_owned(), "just".to_owned()],
            forbidden_tools: vec!["surreal sql".to_owned(), "external-agent".to_owned()],
        }],
        expected_outputs: vec![SkillOutputSpec {
            name: "SkillExecutionProof".to_owned(),
            description: "proof with steps, outputs, and verifier refs".to_owned(),
            evidence_required: true,
            verifier_required: true,
        }],
        verification_plan: smoke_verifier_plan(),
        stop_conditions: vec![
            "anti-scope matches".to_owned(),
            "required verifier unavailable".to_owned(),
        ],
        known_failure_modes: vec![SkillFailureMode {
            failure_id: "skill-smoke-known-failure".to_owned(),
            description: "negative transfer from irrelevant procedural recall".to_owned(),
            detection_signal: "skill-smoke-known-failure".to_owned(),
            mitigation: "exclude or quarantine skill".to_owned(),
            negative_memory_refs: vec!["failure:skill-smoke-known-failure".to_owned()],
        }],
        rollback_or_recovery: Some("archive or quarantine the skill with evidence".to_owned()),
        source_trace_refs: vec!["evidence:skill-smoke".to_owned()],
        replay_result_refs: vec!["replay:skill-smoke".to_owned()],
        success_count: 1,
        failure_count: 0,
        last_verified_at: Some(now),
        version: "1.0.0".to_owned(),
        owner: "eliot-governor".to_owned(),
        created_at: now,
        updated_at: now,
    }
}

pub(super) fn smoke_verifier_plan() -> VerifierPlan {
    VerifierPlan {
        required: vec![VerifierRequirement {
            name: "just_verify".to_owned(),
            command_kind: VerifierCommandKind::DomainVerifier,
            command_display: "just verify".to_owned(),
            scope: vec!["eliot-governor".to_owned()],
            required_for_done: true,
            expected_signal: "exit code 0".to_owned(),
        }],
        optional: Vec::new(),
        acceptance_items: vec!["skill execution proof has verifier refs".to_owned()],
    }
}

pub(super) fn smoke_skill_context(task: &str) -> SkillActivationContext {
    SkillActivationContext {
        goal: format!("skill lifecycle smoke task {task}"),
        evidence_refs: vec!["evidence:skill-smoke".to_owned()],
        available_input_sources: vec![
            SkillInputSource::UserPrompt,
            SkillInputSource::CurrentState,
            SkillInputSource::VerifierPlan,
        ],
        available_input_names: vec!["task_goal".to_owned(), "verifier_plan".to_owned()],
        available_capabilities: vec!["rust-verifier".to_owned()],
        available_tools: vec!["cargo".to_owned(), "just".to_owned()],
        verifier_refs: vec!["just verify".to_owned()],
        active_negative_signals: Vec::new(),
        conflicting_skill_refs: Vec::new(),
        audit_mode: false,
    }
}

pub(super) fn smoke_curator_run(project: &str, dry_run: bool) -> SkillCuratorRun {
    SkillCuratorService::run(SkillCuratorRunInput {
        project_id: project_id_from_label(project),
        project: project.to_owned(),
        dry_run,
        skills: smoke_curator_skill_cards(),
    })
}

pub(super) fn smoke_curator_gate_decisions(
    run: &SkillCuratorRun,
) -> Vec<SkillCurationGateDecision> {
    run.proposals
        .iter()
        .map(|proposal| SkillCurationGate::decide(proposal, false))
        .collect()
}

pub(super) fn smoke_curator_skill_cards() -> Vec<SkillCardV2> {
    let mut repeated_success = smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "curator smoke repeated success skill".clone_into(&mut repeated_success.name);
    repeated_success.success_count = 3;
    repeated_success.failure_count = 0;

    let mut missing_anti_scope = smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "curator smoke missing anti-scope skill".clone_into(&mut missing_anti_scope.name);
    missing_anti_scope.does_not_apply_when.clear();

    let mut low_utility = smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "curator smoke low utility high cost skill".clone_into(&mut low_utility.name);
    low_utility.success_count = 0;
    low_utility.failure_count = 5;
    low_utility
        .ordered_steps
        .extend((0..20).map(|index| SkillStep {
            step_id: format!("curator-smoke-expensive-{index}"),
            order: index + 20,
            instruction: "large context cost step with repeated low utility".repeat(4),
            expected_observation: None,
            required_tool_or_capability: None,
            stop_if_fails: false,
        }));

    let mut negative_transfer = smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "curator smoke negative transfer skill".clone_into(&mut negative_transfer.name);
    negative_transfer.success_count = 0;
    negative_transfer.failure_count = 3;
    negative_transfer
        .known_failure_modes
        .push(SkillFailureMode {
            failure_id: "curator-smoke-negative-transfer".to_owned(),
            description: "negative transfer into unrelated procedural task".to_owned(),
            detection_signal: "negative-transfer".to_owned(),
            mitigation: "quarantine and retain audit trail".to_owned(),
            negative_memory_refs: vec!["failure:curator-smoke-negative-transfer".to_owned()],
        });

    let mut overbroad = smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "curator smoke overbroad skill".clone_into(&mut overbroad.name);
    overbroad.applies_when.extend([
        SkillScopeRule {
            rule_id: "curator-smoke-any-project".to_owned(),
            description: "any project task".to_owned(),
            positive_examples: vec!["any project".to_owned()],
            negative_examples: Vec::new(),
            required_evidence_refs: Vec::new(),
        },
        SkillScopeRule {
            rule_id: "curator-smoke-all-tasks".to_owned(),
            description: "all tasks with tools".to_owned(),
            positive_examples: vec!["all tasks".to_owned()],
            negative_examples: Vec::new(),
            required_evidence_refs: Vec::new(),
        },
    ]);

    let duplicate_a = {
        let mut skill = smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
        "curator smoke duplicate skill".clone_into(&mut skill.name);
        "duplicate procedural skill routing".clone_into(&mut skill.purpose);
        skill
    };
    let mut duplicate_b = duplicate_a.clone();
    duplicate_b.skill_id = SkillId::new_v7();

    let mut rare = smoke_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "curator smoke rare protected skill".clone_into(&mut rare.name);
    rare.success_count = 1;
    rare.failure_count = 0;
    rare.source_trace_refs
        .push("evidence:curator-smoke-rare-important".to_owned());

    vec![
        repeated_success,
        missing_anti_scope,
        low_utility,
        negative_transfer,
        overbroad,
        duplicate_a,
        duplicate_b,
        rare,
    ]
}

pub(super) fn skill_curation_receipt(
    proposal: &SkillCurationProposal,
    applied: bool,
    summary: &str,
) -> SkillCurationReceipt {
    SkillCurationReceipt {
        receipt_id: format!("skill-curation-receipt-{}", TaskId::new_v7()),
        proposal_id: proposal.proposal_id.clone(),
        project_id: proposal.project_id,
        skill_ref: proposal.skill_ref,
        action: proposal.action,
        applied,
        summary: summary.to_owned(),
        rollback_plan: proposal.rollback_plan.clone(),
        created_at: time::OffsetDateTime::now_utc(),
        write_receipt: None,
    }
}
