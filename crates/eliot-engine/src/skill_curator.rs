use crate::{
    EngineError, ForgettingPolicyService, SkillActivationContext, SkillDistractorFilterService,
    SkillLifecycleService, WriteAdmissionService, WriterHandle,
};
use eliot_types::{
    AgentId, CommandContext, ForgettingOperator, ForgettingReason, LifecycleStatus, ProjectId,
    SemanticCommand, SkillArchiveProposal, SkillCardV2, SkillCurationAction,
    SkillCurationDecisionKind, SkillCurationExpectedEffect, SkillCurationGateDecision,
    SkillCurationGateReason, SkillCurationProposal, SkillCurationReason, SkillCurationReceipt,
    SkillCurationRisk, SkillCurationRollbackPlan, SkillCuratorRun, SkillCuratorRunStatus, SkillId,
    SkillLifecycleState, SkillMergeProposal, SkillPatchProposal, SkillQuarantineProposal,
    SkillReplayRequirement, SkillScopeRule, SkillSplitProposal, TaintClass, TaskId,
    ToolObservationRecordCommand, Visibility, WriteId, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct SkillCuratorRunInput {
    pub project_id: ProjectId,
    pub project: String,
    pub dry_run: bool,
    pub skills: Vec<SkillCardV2>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkillCurationReport {
    pub component: String,
    pub run: SkillCuratorRun,
    pub open_proposals: Vec<SkillCurationProposal>,
    pub gate_decisions: Vec<SkillCurationGateDecision>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Default)]
pub struct SkillCuratorService;

impl SkillCuratorService {
    pub fn run(input: SkillCuratorRunInput) -> SkillCuratorRun {
        let proposals = Self::proposals_for_skills(input.project_id, &input.skills);
        SkillCuratorRun {
            run_id: format!("skill-curator-run-{}", WriteId::new_v7()),
            project_id: input.project_id,
            project: input.project,
            status: if input.dry_run {
                SkillCuratorRunStatus::DryRunComplete
            } else {
                SkillCuratorRunStatus::Complete
            },
            dry_run: input.dry_run,
            skills_scanned: input.skills.iter().map(|skill| skill.skill_id).collect(),
            usage_sources: vec![
                "skill_lifecycle_record.success_count".to_owned(),
                "skill_lifecycle_record.failure_count".to_owned(),
                "skill_context_cost_estimate".to_owned(),
                "skill_scope_rules".to_owned(),
            ],
            proposals,
            rejected_actions: Vec::new(),
            generated_at: OffsetDateTime::now_utc(),
            write_receipt: None,
        }
    }

    pub fn proposals_for_skills(
        project_id: ProjectId,
        skills: &[SkillCardV2],
    ) -> Vec<SkillCurationProposal> {
        let mut proposals = Vec::new();
        let duplicate_groups = duplicate_skill_groups(skills);
        for skill in skills {
            proposals.extend(Self::proposals_for_skill(project_id, skill));
        }
        for group in duplicate_groups {
            if let Some(first) = group.first().copied()
                && group.len() > 1
                && let Some(skill) = skills.iter().find(|skill| skill.skill_id == first)
            {
                proposals.push(merge_proposal(project_id, skill, &group));
            }
        }
        proposals
    }

    pub fn proposals_for_skill(
        project_id: ProjectId,
        skill: &SkillCardV2,
    ) -> Vec<SkillCurationProposal> {
        let mut proposals = Vec::new();
        if skill.success_count >= 2 && skill.failure_count == 0 {
            proposals.push(keep_proposal(project_id, skill));
        }
        if skill.does_not_apply_when.is_empty() {
            proposals.push(patch_where_not_apply_proposal(project_id, skill));
        }
        if low_utility_high_cost(skill) {
            proposals.push(archive_proposal(project_id, skill));
        }
        if negative_transfer(skill) {
            proposals.push(quarantine_proposal(project_id, skill));
        }
        if overbroad_skill(skill) {
            proposals.push(split_proposal(project_id, skill));
        }
        proposals
    }

    pub fn visible_for_normal_l3(skills: &[SkillCardV2]) -> Vec<SkillCardV2> {
        skills
            .iter()
            .filter(|skill| {
                skill.lifecycle_state == SkillLifecycleState::Active
                    && !candidate_patch_skill(skill)
            })
            .cloned()
            .collect()
    }

    pub fn procedural_packet(
        project_id: ProjectId,
        task_id: TaskId,
        skills: &[SkillCardV2],
        context: &SkillActivationContext,
    ) -> eliot_types::ProceduralSkillPacketView {
        SkillDistractorFilterService::procedural_packet(
            project_id,
            task_id,
            &Self::visible_for_normal_l3(skills),
            context,
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillCurationGate;

impl SkillCurationGate {
    pub fn decide(
        proposal: &SkillCurationProposal,
        incident_lockdown_active: bool,
    ) -> SkillCurationGateDecision {
        let mut reasons = BTreeSet::new();
        let mut reviewer_required = false;
        let mut replay_required = proposal.replay_requirement.required;
        let decision = match proposal.action {
            SkillCurationAction::Promote => {
                reasons.insert(SkillCurationGateReason::AutoPromotionDenied);
                SkillCurationDecisionKind::Deny
            }
            SkillCurationAction::Keep => {
                reasons.insert(SkillCurationGateReason::ReadOnlyReportAllowed);
                SkillCurationDecisionKind::AllowReadOnly
            }
            SkillCurationAction::Patch => {
                if incident_lockdown_active {
                    reasons.insert(SkillCurationGateReason::IncidentLockdown);
                    SkillCurationDecisionKind::Deny
                } else {
                    decide_patch(
                        proposal,
                        &mut reasons,
                        &mut reviewer_required,
                        &mut replay_required,
                    )
                }
            }
            SkillCurationAction::Archive => {
                if proposal.evidence_refs.is_empty() {
                    reasons.insert(SkillCurationGateReason::MissingEvidence);
                    SkillCurationDecisionKind::RequireReview
                } else {
                    reasons.insert(SkillCurationGateReason::SafeArchiveAllowed);
                    SkillCurationDecisionKind::Allow
                }
            }
            SkillCurationAction::Quarantine => {
                if proposal.evidence_refs.is_empty() {
                    reasons.insert(SkillCurationGateReason::MissingEvidence);
                    SkillCurationDecisionKind::RequireReview
                } else {
                    reasons.insert(SkillCurationGateReason::SafeQuarantineAllowed);
                    SkillCurationDecisionKind::Allow
                }
            }
            SkillCurationAction::Merge | SkillCurationAction::Split => {
                if proposal
                    .replay_requirement
                    .replay_marker
                    .as_deref()
                    .is_none_or(str::is_empty)
                {
                    reasons.insert(SkillCurationGateReason::MissingReplayForScopeBroadening);
                    replay_required = true;
                    SkillCurationDecisionKind::RequireReplay
                } else {
                    reasons.insert(SkillCurationGateReason::ActionAllowed);
                    SkillCurationDecisionKind::Allow
                }
            }
        };
        let allowed_action = (matches!(
            decision,
            SkillCurationDecisionKind::Allow | SkillCurationDecisionKind::AllowReadOnly
        ))
        .then_some(proposal.action);
        SkillCurationGateDecision {
            proposal_id: proposal.proposal_id.clone(),
            decision,
            reasons: reasons.into_iter().collect(),
            allowed_action,
            reviewer_required,
            replay_required,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillPatchService;

impl SkillPatchService {
    pub fn candidate_patch_skill(
        skill: &SkillCardV2,
        proposal: &SkillCurationProposal,
    ) -> SkillCardV2 {
        let mut candidate = skill.clone();
        candidate.skill_id = SkillId::new_v7();
        candidate.lifecycle_state = SkillLifecycleState::Candidate;
        "skill-curator-candidate".clone_into(&mut candidate.owner);
        candidate.source_trace_refs.push(format!(
            "skill-curation-candidate-patch:{}",
            proposal.proposal_id
        ));
        candidate.updated_at = OffsetDateTime::now_utc();
        candidate
    }

    pub fn apply_narrow_patch(
        skill: &SkillCardV2,
        proposal: &SkillCurationProposal,
    ) -> Result<SkillCardV2, SkillCurationGateDecision> {
        let decision = SkillCurationGate::decide(proposal, false);
        if decision.decision != SkillCurationDecisionKind::Allow
            || proposal.action != SkillCurationAction::Patch
        {
            return Err(decision);
        }
        let Some(patch) = &proposal.patch else {
            return Err(decision_with_reason(
                proposal,
                SkillCurationDecisionKind::Deny,
                SkillCurationGateReason::UnsupportedAction,
            ));
        };
        if !patch.narrows_scope || patch.broadens_scope || patch.weakens_verifier {
            return Err(decision_with_reason(
                proposal,
                SkillCurationDecisionKind::Deny,
                SkillCurationGateReason::UnsupportedAction,
            ));
        }
        let mut patched = skill.clone();
        if patched.does_not_apply_when.is_empty() {
            patched.does_not_apply_when.push(SkillScopeRule {
                rule_id: "curator-added-anti-scope".to_owned(),
                description: "exclude tasks outside the replayed scope".to_owned(),
                positive_examples: vec!["unrelated task".to_owned()],
                negative_examples: vec![patched.purpose.clone()],
                required_evidence_refs: proposal.evidence_refs.clone(),
            });
        }
        patched
            .source_trace_refs
            .push(format!("skill-curation-patch:{}", proposal.proposal_id));
        patched.updated_at = OffsetDateTime::now_utc();
        Ok(patched)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillMergeSplitService;

impl SkillMergeSplitService {
    pub fn duplicate_groups(skills: &[SkillCardV2]) -> Vec<Vec<SkillId>> {
        duplicate_skill_groups(skills)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillArchiveQuarantineService;

impl SkillArchiveQuarantineService {
    pub fn safe_archive(skill: &SkillCardV2, reason: &str) -> SkillCardV2 {
        SkillLifecycleService::archive(skill, reason).0
    }

    pub fn safe_quarantine(skill: &SkillCardV2, reason: &str) -> SkillCardV2 {
        SkillLifecycleService::quarantine(skill, reason).0
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillCurationReportService;

impl SkillCurationReportService {
    pub fn report(run: SkillCuratorRun) -> SkillCurationReport {
        let gate_decisions = run
            .proposals
            .iter()
            .map(|proposal| SkillCurationGate::decide(proposal, false))
            .collect::<Vec<_>>();
        SkillCurationReport {
            component: "skill_curator".to_owned(),
            open_proposals: run.proposals.clone(),
            run,
            gate_decisions,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct SkillCuratorMemoryWriter;

impl SkillCuratorMemoryWriter {
    pub async fn write_run(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        run: &mut SkillCuratorRun,
    ) -> Result<WriteReceiptRef, EngineError> {
        let receipt =
            write_curator_observation(handle, admission, "skill_curator_run", &*run).await?;
        run.write_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    pub async fn write_proposal(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        proposal: &mut SkillCurationProposal,
    ) -> Result<WriteReceiptRef, EngineError> {
        let receipt =
            write_curator_observation(handle, admission, "skill_curation_proposal", &*proposal)
                .await?;
        proposal.write_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    pub async fn write_candidate_patch(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        proposal: &mut SkillCurationProposal,
    ) -> Result<WriteReceiptRef, EngineError> {
        let receipt =
            write_curator_observation(handle, admission, "skill_patch_candidate", &*proposal)
                .await?;
        proposal.write_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    pub async fn write_receipt(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        receipt: &mut SkillCurationReceipt,
    ) -> Result<WriteReceiptRef, EngineError> {
        let write_receipt =
            write_curator_observation(handle, admission, "skill_curation_receipt", &*receipt)
                .await?;
        receipt.write_receipt = Some(write_receipt.clone());
        Ok(write_receipt)
    }

    pub async fn write_archive_receipt(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        proposal: &SkillCurationProposal,
    ) -> Result<SkillCurationReceipt, EngineError> {
        let mut receipt = curation_receipt(proposal, true, "safe archive retained for audit");
        Self::write_receipt(handle, admission, &mut receipt).await?;
        Ok(receipt)
    }

    pub async fn write_quarantine_receipt(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        proposal: &SkillCurationProposal,
    ) -> Result<SkillCurationReceipt, EngineError> {
        let mut receipt = curation_receipt(proposal, true, "safe quarantine retained for audit");
        Self::write_receipt(handle, admission, &mut receipt).await?;
        Ok(receipt)
    }
}

fn decide_patch(
    proposal: &SkillCurationProposal,
    reasons: &mut BTreeSet<SkillCurationGateReason>,
    reviewer_required: &mut bool,
    replay_required: &mut bool,
) -> SkillCurationDecisionKind {
    let Some(patch) = &proposal.patch else {
        reasons.insert(SkillCurationGateReason::UnsupportedAction);
        return SkillCurationDecisionKind::Deny;
    };
    if patch.broadens_scope
        && proposal
            .replay_requirement
            .replay_marker
            .as_deref()
            .is_none_or(str::is_empty)
    {
        reasons.insert(SkillCurationGateReason::MissingReplayForScopeBroadening);
        *replay_required = true;
        return SkillCurationDecisionKind::RequireReplay;
    }
    if patch.removes_anti_scope && patch.reviewer_refs.is_empty() {
        reasons.insert(SkillCurationGateReason::RemovingAntiScopeDenied);
        *reviewer_required = true;
        return SkillCurationDecisionKind::Deny;
    }
    if patch.weakens_verifier && patch.reviewer_refs.is_empty() {
        reasons.insert(SkillCurationGateReason::VerifierWeakeningDenied);
        *reviewer_required = true;
        return SkillCurationDecisionKind::Deny;
    }
    if proposal.evidence_refs.is_empty() {
        reasons.insert(SkillCurationGateReason::MissingEvidence);
        *reviewer_required = true;
        return SkillCurationDecisionKind::RequireReview;
    }
    reasons.insert(SkillCurationGateReason::SafePatchAllowed);
    SkillCurationDecisionKind::Allow
}

fn keep_proposal(project_id: ProjectId, skill: &SkillCardV2) -> SkillCurationProposal {
    base_proposal(
        project_id,
        skill,
        SkillCurationAction::Keep,
        SkillCurationReason::RepeatedSuccess,
        "keep skill active after repeated verified success",
        vec![format!("skill-success-count:{}", skill.success_count)],
    )
}

fn patch_where_not_apply_proposal(
    project_id: ProjectId,
    skill: &SkillCardV2,
) -> SkillCurationProposal {
    let mut proposal = base_proposal(
        project_id,
        skill,
        SkillCurationAction::Patch,
        SkillCurationReason::MissingWhereNotApply,
        "add anti-scope rule before normal L3 use",
        vec!["skill-missing-where-not-apply".to_owned()],
    );
    proposal.patch = Some(SkillPatchProposal {
        target_skill: skill.skill_id,
        patch_summary: "candidate patch adds a conservative does_not_apply_when rule".to_owned(),
        candidate_content_ref: format!("skill-patch-candidate:{}", proposal.proposal_id),
        narrows_scope: true,
        broadens_scope: false,
        removes_anti_scope: false,
        weakens_verifier: false,
        reviewer_refs: Vec::new(),
    });
    proposal
}

fn archive_proposal(project_id: ProjectId, skill: &SkillCardV2) -> SkillCurationProposal {
    let policy = ForgettingPolicyService::propose(
        project_id,
        &format!("skill:{}", skill.skill_id),
        ForgettingOperator::Archive,
        ForgettingReason::LowUtility,
        vec!["skill-low-utility-high-cost".to_owned()],
        None,
        None,
    );
    let mut proposal = base_proposal(
        project_id,
        skill,
        SkillCurationAction::Archive,
        SkillCurationReason::LowUtilityHighCost,
        "archive low utility high context cost skill but retain audit trail",
        policy.evidence_refs.clone(),
    );
    proposal.archive = Some(SkillArchiveProposal {
        target_skill: skill.skill_id,
        retained_for_audit: true,
        memory_policy_ref: Some(policy.policy_id),
    });
    proposal
}

fn quarantine_proposal(project_id: ProjectId, skill: &SkillCardV2) -> SkillCurationProposal {
    let policy = SkillLifecycleService::negative_transfer_policy(
        project_id,
        skill.skill_id,
        vec!["skill-negative-transfer".to_owned()],
    );
    let mut proposal = base_proposal(
        project_id,
        skill,
        SkillCurationAction::Quarantine,
        SkillCurationReason::NegativeTransfer,
        "quarantine skill after negative transfer evidence",
        policy.evidence_refs.clone(),
    );
    proposal.quarantine = Some(SkillQuarantineProposal {
        target_skill: skill.skill_id,
        negative_transfer_refs: policy.evidence_refs,
        memory_policy_ref: Some(policy.policy_id),
    });
    proposal
}

fn split_proposal(project_id: ProjectId, skill: &SkillCardV2) -> SkillCurationProposal {
    let mut proposal = base_proposal(
        project_id,
        skill,
        SkillCurationAction::Split,
        SkillCurationReason::OverbroadSkill,
        "split overbroad skill into narrower scopes after replay",
        vec!["skill-overbroad-scope".to_owned()],
    );
    proposal.replay_requirement = SkillReplayRequirement {
        required: true,
        reason: "split changes scope routing and requires replay evidence".to_owned(),
        replay_marker: None,
        verifier_refs: verifier_refs(skill),
    };
    proposal.split = Some(SkillSplitProposal {
        source_skill: skill.skill_id,
        split_names: vec![
            format!("{} / narrow scope A", skill.name),
            format!("{} / narrow scope B", skill.name),
        ],
        scope_boundaries: skill
            .applies_when
            .iter()
            .map(|rule| rule.description.clone())
            .collect(),
    });
    proposal
}

fn merge_proposal(
    project_id: ProjectId,
    skill: &SkillCardV2,
    group: &[SkillId],
) -> SkillCurationProposal {
    let mut proposal = base_proposal(
        project_id,
        skill,
        SkillCurationAction::Merge,
        SkillCurationReason::DuplicateSkill,
        "merge duplicate skill cards after replay",
        vec!["skill-duplicate-scope".to_owned()],
    );
    proposal.replay_requirement = SkillReplayRequirement {
        required: true,
        reason: "merge changes skill identity and requires replay evidence".to_owned(),
        replay_marker: None,
        verifier_refs: verifier_refs(skill),
    };
    proposal.merge = Some(SkillMergeProposal {
        source_skills: group.to_vec(),
        merged_skill_name: skill.name.clone(),
        duplicate_evidence_refs: proposal.evidence_refs.clone(),
    });
    proposal
}

fn base_proposal(
    project_id: ProjectId,
    skill: &SkillCardV2,
    action: SkillCurationAction,
    reason: SkillCurationReason,
    summary: &str,
    evidence_refs: Vec<String>,
) -> SkillCurationProposal {
    SkillCurationProposal {
        proposal_id: format!("skill-curation-proposal-{}", WriteId::new_v7()),
        project_id,
        skill_ref: skill.skill_id,
        skill_name: skill.name.clone(),
        action,
        reason,
        expected_effect: SkillCurationExpectedEffect {
            summary: summary.to_owned(),
            utility_delta: expected_utility_delta(action),
            context_cost_delta_tokens: expected_context_delta(action, skill),
            risk_delta: expected_risk_delta(action),
        },
        risks: vec![SkillCurationRisk {
            severity: "low".to_owned(),
            description: "proposal is non-executing until gate and receipt write succeed"
                .to_owned(),
            mitigation: "retain audit trail and rollback plan".to_owned(),
        }],
        rollback_plan: SkillCurationRollbackPlan {
            steps: vec![
                "retain previous SkillCardV2".to_owned(),
                "restore prior lifecycle state from audit receipt".to_owned(),
            ],
            restores_previous_skill: true,
            retained_audit_ref: Some(format!("skill:{}", skill.skill_id)),
        },
        replay_requirement: SkillReplayRequirement {
            required: false,
            reason: "safe narrow or read-only proposal does not broaden scope".to_owned(),
            replay_marker: None,
            verifier_refs: verifier_refs(skill),
        },
        patch: None,
        merge: None,
        split: None,
        archive: None,
        quarantine: None,
        evidence_refs,
        gate_decision: None,
        created_at: OffsetDateTime::now_utc(),
        write_receipt: None,
    }
}

fn duplicate_skill_groups(skills: &[SkillCardV2]) -> Vec<Vec<SkillId>> {
    let mut by_signature: BTreeMap<String, Vec<SkillId>> = BTreeMap::new();
    for skill in skills {
        let signature = format!(
            "{}|{}",
            skill.name.to_ascii_lowercase(),
            skill.purpose.to_ascii_lowercase()
        );
        by_signature
            .entry(signature)
            .or_default()
            .push(skill.skill_id);
    }
    by_signature
        .into_values()
        .filter(|group| group.len() > 1)
        .collect()
}

fn low_utility_high_cost(skill: &SkillCardV2) -> bool {
    skill.failure_count > skill.success_count && estimated_skill_context_cost(skill) >= 180
}

fn negative_transfer(skill: &SkillCardV2) -> bool {
    skill.failure_count > skill.success_count
        && skill.known_failure_modes.iter().any(|failure| {
            let text = format!("{} {}", failure.description, failure.detection_signal)
                .to_ascii_lowercase();
            text.contains("negative") || text.contains("transfer")
        })
}

fn overbroad_skill(skill: &SkillCardV2) -> bool {
    skill.applies_when.len() >= 3
        || skill.applies_when.iter().any(|rule| {
            let text = format!("{} {}", rule.description, rule.positive_examples.join(" "))
                .to_ascii_lowercase();
            text.contains("all tasks")
                || text.contains("any project")
                || text.contains("everything")
        })
}

fn candidate_patch_skill(skill: &SkillCardV2) -> bool {
    skill.owner == "skill-curator-candidate"
        || skill
            .source_trace_refs
            .iter()
            .any(|reference| reference.starts_with("skill-curation-candidate-patch:"))
}

fn expected_utility_delta(action: SkillCurationAction) -> f64 {
    match action {
        SkillCurationAction::Keep => 0.05,
        SkillCurationAction::Patch | SkillCurationAction::Split | SkillCurationAction::Merge => {
            0.15
        }
        SkillCurationAction::Archive | SkillCurationAction::Quarantine => 0.10,
        SkillCurationAction::Promote => 0.0,
    }
}

fn expected_context_delta(action: SkillCurationAction, skill: &SkillCardV2) -> i64 {
    let cost = i64::try_from(estimated_skill_context_cost(skill)).unwrap_or(i64::MAX);
    match action {
        SkillCurationAction::Keep | SkillCurationAction::Promote => 0,
        SkillCurationAction::Patch => -cost / 10,
        SkillCurationAction::Merge | SkillCurationAction::Split => -cost / 4,
        SkillCurationAction::Archive | SkillCurationAction::Quarantine => -cost,
    }
}

fn expected_risk_delta(action: SkillCurationAction) -> f64 {
    match action {
        SkillCurationAction::Keep => 0.0,
        SkillCurationAction::Patch => -0.05,
        SkillCurationAction::Merge | SkillCurationAction::Split => -0.10,
        SkillCurationAction::Archive | SkillCurationAction::Quarantine => -0.20,
        SkillCurationAction::Promote => 0.40,
    }
}

fn verifier_refs(skill: &SkillCardV2) -> Vec<String> {
    skill
        .verification_plan
        .required
        .iter()
        .map(|verifier| verifier.command_display.clone())
        .collect()
}

fn estimated_skill_context_cost(skill: &SkillCardV2) -> u64 {
    serde_json::to_string(skill).map_or(0, |text| text.len().div_ceil(4) as u64)
}

fn decision_with_reason(
    proposal: &SkillCurationProposal,
    decision: SkillCurationDecisionKind,
    reason: SkillCurationGateReason,
) -> SkillCurationGateDecision {
    SkillCurationGateDecision {
        proposal_id: proposal.proposal_id.clone(),
        decision,
        reasons: vec![reason],
        allowed_action: None,
        reviewer_required: false,
        replay_required: false,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn curation_receipt(
    proposal: &SkillCurationProposal,
    applied: bool,
    summary: &str,
) -> SkillCurationReceipt {
    SkillCurationReceipt {
        receipt_id: format!("skill-curation-receipt-{}", WriteId::new_v7()),
        proposal_id: proposal.proposal_id.clone(),
        project_id: proposal.project_id,
        skill_ref: proposal.skill_ref,
        action: proposal.action,
        applied,
        summary: summary.to_owned(),
        rollback_plan: proposal.rollback_plan.clone(),
        created_at: OffsetDateTime::now_utc(),
        write_receipt: None,
    }
}

async fn write_curator_observation<T>(
    handle: &WriterHandle,
    admission: &WriteAdmissionService,
    kind: &str,
    body: &T,
) -> Result<WriteReceiptRef, EngineError>
where
    T: Serialize,
{
    let body_value = serde_json::to_value(body)?;
    let project_id = body_value
        .get("project_id")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_else(ProjectId::new_v7);
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None::<TaskId>,
            scope: "skill-curator-i2".to_owned(),
            authority: "local-skill-curator".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot_skill_curator".to_owned(),
        observation: format!("Skill curator {kind} written through WriterActor"),
        payload: json!({
            "curation_kind": kind,
            "body": body_value,
            "writer_path": "semantic_command_writer_actor"
        }),
    });
    let envelope = admission.admit(&command)?;
    let receipt = handle.submit(envelope).await?;
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}
