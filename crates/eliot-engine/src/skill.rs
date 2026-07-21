use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_types::{
    AgentId, CommandContext, EpistemicStatus, ExperienceMaturityState, ExperiencePattern,
    ForgettingOperator, ForgettingPolicy, ForgettingReason, LifecycleStatus, MemoryEcologyDecision,
    MemoryLifecycleState, ProcedurePromotionOutcome, ProjectId, SemanticCommand,
    SkillActivationDecision, SkillActivationRecord, SkillCardV2, SkillDistractorFilter,
    SkillExecutionOutcome, SkillExecutionProof, SkillId, SkillInfluenceReport, SkillInputSource,
    SkillLifecycleRecord, SkillLifecycleState, SkillNeedEstimate, SkillNeedVerdict, TaintClass,
    TaskId, ToolObservationRecordCommand, VerifierPlan, Visibility, WriteId, WriteReceiptRef,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;

#[derive(Clone, Debug, Default)]
pub struct SkillRegistryService {
    skills: BTreeMap<SkillId, SkillCardV2>,
    lifecycle: BTreeMap<SkillId, SkillLifecycleRecord>,
}

impl SkillRegistryService {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_skill(mut self, skill: SkillCardV2) -> Self {
        let record = SkillLifecycleService::record_for(&skill, None);
        self.lifecycle.insert(skill.skill_id, record);
        self.skills.insert(skill.skill_id, skill);
        self
    }

    pub fn create_candidate(name: impl Into<String>, owner: impl Into<String>) -> SkillCardV2 {
        let now = OffsetDateTime::now_utc();
        SkillCardV2 {
            skill_id: SkillId::new_v7(),
            name: name.into(),
            purpose: "candidate procedural skill seed; audit only until activated".to_owned(),
            level: eliot_types::SkillLevel::Procedure,
            lifecycle_state: SkillLifecycleState::Candidate,
            applies_when: vec![eliot_types::SkillScopeRule {
                rule_id: "candidate-scope".to_owned(),
                description: "manual audit asks to inspect this candidate skill".to_owned(),
                positive_examples: vec!["skill audit".to_owned()],
                negative_examples: vec!["normal recall".to_owned()],
                required_evidence_refs: vec!["manual:create".to_owned()],
            }],
            does_not_apply_when: vec![eliot_types::SkillScopeRule {
                rule_id: "candidate-not-normal".to_owned(),
                description: "normal L3 recall without explicit audit request".to_owned(),
                positive_examples: vec!["normal recall".to_owned()],
                negative_examples: vec!["explicit skill audit".to_owned()],
                required_evidence_refs: Vec::new(),
            }],
            required_inputs: vec![eliot_types::SkillInputRequirement {
                name: "task_goal".to_owned(),
                description: "current user task goal".to_owned(),
                required: true,
                source: SkillInputSource::UserPrompt,
            }],
            ordered_steps: vec![eliot_types::SkillStep {
                step_id: "inspect-scope".to_owned(),
                order: 1,
                instruction: "Inspect scope, anti-scope, required inputs, and verifier plan."
                    .to_owned(),
                expected_observation: Some("candidate remains audit-only".to_owned()),
                required_tool_or_capability: None,
                stop_if_fails: true,
            }],
            required_tools_and_capabilities: Vec::new(),
            expected_outputs: vec![eliot_types::SkillOutputSpec {
                name: "skill_audit_note".to_owned(),
                description: "bounded audit note with evidence refs".to_owned(),
                evidence_required: true,
                verifier_required: false,
            }],
            verification_plan: VerifierPlan {
                required: Vec::new(),
                optional: Vec::new(),
                acceptance_items: vec!["candidate is not active by default".to_owned()],
            },
            stop_conditions: vec!["missing explicit audit request".to_owned()],
            known_failure_modes: Vec::new(),
            rollback_or_recovery: Some("archive or reject the candidate".to_owned()),
            source_trace_refs: vec!["manual:create".to_owned()],
            replay_result_refs: Vec::new(),
            success_count: 0,
            failure_count: 0,
            last_verified_at: None,
            version: "0.1.0".to_owned(),
            owner: owner.into(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn insert(&mut self, skill: SkillCardV2) -> Result<(), EngineError> {
        validate_skill_card(&skill)?;
        let record = SkillLifecycleService::record_for(&skill, None);
        self.lifecycle.insert(skill.skill_id, record);
        self.skills.insert(skill.skill_id, skill);
        Ok(())
    }

    pub fn load(&self, skill_id: SkillId) -> Option<&SkillCardV2> {
        self.skills.get(&skill_id)
    }

    pub fn list_by_lifecycle(&self, state: Option<SkillLifecycleState>) -> Vec<SkillCardV2> {
        self.skills
            .values()
            .filter(|skill| state.is_none_or(|expected| skill.lifecycle_state == expected))
            .cloned()
            .collect()
    }

    pub fn lifecycle_record(&self, skill_id: SkillId) -> Option<&SkillLifecycleRecord> {
        self.lifecycle.get(&skill_id)
    }

    pub async fn write_skill_card(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        skill: &SkillCardV2,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_skill_observation(writer, admission, skill.skill_id, "skill_card_v2", skill).await
    }

    pub async fn write_lifecycle_record(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        record: &SkillLifecycleRecord,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_skill_observation(
            writer,
            admission,
            record.skill_ref,
            "skill_lifecycle_record",
            record,
        )
        .await
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillLifecycleService;

impl SkillLifecycleService {
    pub fn activate(
        skill: &SkillCardV2,
        evidence_refs: Vec<String>,
    ) -> Result<(SkillCardV2, SkillLifecycleRecord), SkillActivationDecision> {
        if matches!(
            skill.lifecycle_state,
            SkillLifecycleState::Archived
                | SkillLifecycleState::Quarantined
                | SkillLifecycleState::Rejected
        ) {
            return Err(SkillActivationDecision::ExcludeLifecycleState);
        }
        if evidence_refs.is_empty()
            || skill.does_not_apply_when.is_empty()
            || skill.verification_plan.required.is_empty()
        {
            return Err(SkillActivationDecision::AuditOnly);
        }
        let mut activated = skill.clone();
        activated.lifecycle_state = SkillLifecycleState::Active;
        activated.source_trace_refs.extend(evidence_refs);
        activated.updated_at = OffsetDateTime::now_utc();
        activated.last_verified_at = Some(OffsetDateTime::now_utc());
        let record = Self::record_for(&activated, None);
        Ok((activated, record))
    }

    pub fn stale(
        skill: &SkillCardV2,
        reason: impl Into<String>,
    ) -> (SkillCardV2, SkillLifecycleRecord) {
        Self::transition(skill, SkillLifecycleState::Stale, Some(reason.into()))
    }

    pub fn archive(
        skill: &SkillCardV2,
        reason: impl Into<String>,
    ) -> (SkillCardV2, SkillLifecycleRecord) {
        Self::transition(skill, SkillLifecycleState::Archived, Some(reason.into()))
    }

    pub fn quarantine(
        skill: &SkillCardV2,
        reason: impl Into<String>,
    ) -> (SkillCardV2, SkillLifecycleRecord) {
        Self::transition(skill, SkillLifecycleState::Quarantined, Some(reason.into()))
    }

    pub fn reject(
        skill: &SkillCardV2,
        reason: impl Into<String>,
    ) -> (SkillCardV2, SkillLifecycleRecord) {
        Self::transition(skill, SkillLifecycleState::Rejected, Some(reason.into()))
    }

    pub fn record_for(
        skill: &SkillCardV2,
        demotion_reason: Option<String>,
    ) -> SkillLifecycleRecord {
        SkillLifecycleRecord {
            record_id: format!("skill-lifecycle-{}", WriteId::new_v7()),
            skill_ref: skill.skill_id,
            state: skill.lifecycle_state,
            uses: skill.success_count.saturating_add(skill.failure_count),
            successes: skill.success_count,
            failures: skill.failure_count,
            context_cost: Some(estimated_skill_context_cost(skill)),
            last_verified: skill.last_verified_at,
            where_applies: skill.applies_when.clone(),
            where_not_apply: skill.does_not_apply_when.clone(),
            promotion_evidence: skill.source_trace_refs.clone(),
            source_case_refs: Vec::new(),
            source_pattern_refs: Vec::new(),
            mechanism_refs: Vec::new(),
            local_check_refs: skill
                .applies_when
                .iter()
                .flat_map(|rule| rule.required_evidence_refs.clone())
                .collect(),
            transfer_evidence_refs: skill.replay_result_refs.clone(),
            holdout_evidence_refs: Vec::new(),
            negative_transfer_refs: Vec::new(),
            promotion_outcome: None,
            rollback_ref: skill.rollback_or_recovery.clone(),
            demotion_reason,
            archive_or_restore_receipt: None,
            created_at: OffsetDateTime::now_utc(),
            write_receipt: None,
        }
    }

    /// Produces an evidence-bearing disposition without mutating or activating the candidate.
    ///
    /// A transfer-validated pattern is necessary but not sufficient for a procedure: the
    /// candidate must carry explicit applicability boundaries, ordered mechanics, a stop rule,
    /// a required verifier, rollback, source coverage, and independent holdout evidence.
    pub fn procedure_promotion_disposition(
        pattern: &ExperiencePattern,
        candidate: &SkillCardV2,
        holdout_evidence_refs: &[String],
        negative_transfer_refs: &[String],
    ) -> SkillLifecycleRecord {
        let mut record = Self::record_for(candidate, None);
        record
            .source_case_refs
            .clone_from(&pattern.member_case_refs);
        record.source_pattern_refs = vec![pattern.pattern_id.clone()];
        record.mechanism_refs.clone_from(&pattern.invariant_core);
        if !pattern.required_local_probe.trim().is_empty() {
            record
                .local_check_refs
                .push(pattern.required_local_probe.clone());
        }
        record
            .transfer_evidence_refs
            .clone_from(&pattern.transfer_evidence);
        record.holdout_evidence_refs = holdout_evidence_refs.to_vec();
        record.negative_transfer_refs = negative_transfer_refs.to_vec();

        let source_cases_are_covered = pattern.member_case_refs.len() >= 2
            && pattern.authority.candidate_only
            && !pattern.authority.current_truth
            && pattern
                .member_case_refs
                .iter()
                .all(|case_ref| pattern.authority.exact_source_refs.contains(case_ref))
            && pattern
                .member_case_refs
                .iter()
                .all(|case_ref| candidate.source_trace_refs.contains(case_ref));
        let holdout_is_independent = !holdout_evidence_refs.is_empty()
            && holdout_evidence_refs.iter().all(|holdout_ref| {
                !pattern.transfer_evidence.contains(holdout_ref)
                    && !pattern.member_case_refs.contains(holdout_ref)
            });
        let transfer_is_validated = pattern.maturity.state
            == ExperienceMaturityState::TransferValidated
            && pattern.maturity.cross_host_transfer_count > 0
            && !pattern.transfer_evidence.is_empty();
        let mechanics_are_complete = candidate.level == eliot_types::SkillLevel::Procedure
            && !candidate.applies_when.is_empty()
            && !candidate.does_not_apply_when.is_empty()
            && !candidate.required_inputs.is_empty()
            && !candidate.ordered_steps.is_empty()
            && !candidate.expected_outputs.is_empty()
            && !candidate.stop_conditions.is_empty()
            && !candidate.verification_plan.required.is_empty()
            && candidate
                .verification_plan
                .required
                .iter()
                .all(|verifier| verifier.required_for_done)
            && candidate
                .rollback_or_recovery
                .as_deref()
                .is_some_and(|rollback| !rollback.trim().is_empty())
            && !pattern.invariant_core.is_empty()
            && !pattern.success_conditions.is_empty()
            && !pattern.failure_conditions.is_empty()
            && !pattern.required_local_probe.trim().is_empty();
        let negative_transfer_observed =
            pattern.maturity.negative_transfer_count > 0 || !negative_transfer_refs.is_empty();

        if negative_transfer_observed {
            record.state = SkillLifecycleState::Quarantined;
            record.promotion_outcome = Some(ProcedurePromotionOutcome::Demoted);
            record.demotion_reason = Some("negative_transfer_observed".to_owned());
        } else if transfer_is_validated
            && source_cases_are_covered
            && mechanics_are_complete
            && holdout_is_independent
        {
            record.state = SkillLifecycleState::Active;
            record.promotion_outcome = Some(ProcedurePromotionOutcome::Promoted);
        } else {
            record.state = SkillLifecycleState::Candidate;
            record.promotion_outcome = Some(ProcedurePromotionOutcome::NotReadyForProcedure);
        }

        let mut promotion_evidence = BTreeSet::new();
        promotion_evidence.extend(candidate.source_trace_refs.iter().cloned());
        promotion_evidence.extend(pattern.authority.exact_source_refs.iter().cloned());
        promotion_evidence.extend(pattern.transfer_evidence.iter().cloned());
        promotion_evidence.extend(holdout_evidence_refs.iter().cloned());
        record.promotion_evidence = promotion_evidence.into_iter().collect();
        record
    }

    pub fn update_execution_counters(
        mut record: SkillLifecycleRecord,
        proof: &SkillExecutionProof,
    ) -> SkillLifecycleRecord {
        record.uses = record.uses.saturating_add(1);
        match proof.outcome {
            SkillExecutionOutcome::Succeeded => {
                record.successes = record.successes.saturating_add(1);
                record.last_verified = Some(proof.created_at);
            }
            SkillExecutionOutcome::Failed
            | SkillExecutionOutcome::NegativeTransfer
            | SkillExecutionOutcome::AbortedByStopCondition => {
                record.failures = record.failures.saturating_add(1);
                if proof.outcome == SkillExecutionOutcome::NegativeTransfer {
                    record.state = SkillLifecycleState::Quarantined;
                    record.demotion_reason = Some("negative_transfer".to_owned());
                }
            }
            SkillExecutionOutcome::Partial | SkillExecutionOutcome::NotApplicable => {}
        }
        record
    }

    pub fn repeated_irrelevant_activation_policy(
        project_id: ProjectId,
        skill_id: SkillId,
        evidence_refs: Vec<String>,
    ) -> ForgettingPolicy {
        ForgettingPolicy {
            policy_id: format!("skill-stale-proposal-{}", WriteId::new_v7()),
            project_id,
            target_ref: format!("skill:{skill_id}"),
            reason: ForgettingReason::FalseActivation,
            operator: ForgettingOperator::Demote,
            evidence_refs,
            rollback_or_tombstone_ref: None,
            reactivation_condition: None,
            expected_current_state: MemoryLifecycleState::Active,
            observed_epistemic_status: EpistemicStatus::Observed,
            scope: vec!["skill_activation".to_owned()],
            precondition_refs: Vec::new(),
            effective_at: Some(OffsetDateTime::now_utc()),
            expires_at: None,
            expected_admission_effect: MemoryEcologyDecision::Demote,
            reversible: true,
            requires_admin_approval: false,
            approval_ref: None,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn negative_transfer_policy(
        project_id: ProjectId,
        skill_id: SkillId,
        evidence_refs: Vec<String>,
    ) -> ForgettingPolicy {
        ForgettingPolicy {
            policy_id: format!("skill-quarantine-proposal-{}", WriteId::new_v7()),
            project_id,
            target_ref: format!("skill:{skill_id}"),
            reason: ForgettingReason::NegativeTransfer,
            operator: ForgettingOperator::MarkPoisoned,
            evidence_refs,
            rollback_or_tombstone_ref: None,
            reactivation_condition: None,
            expected_current_state: MemoryLifecycleState::Active,
            observed_epistemic_status: EpistemicStatus::Observed,
            scope: vec!["skill_activation".to_owned()],
            precondition_refs: Vec::new(),
            effective_at: Some(OffsetDateTime::now_utc()),
            expires_at: None,
            expected_admission_effect: MemoryEcologyDecision::Quarantine,
            reversible: true,
            requires_admin_approval: false,
            approval_ref: None,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    fn transition(
        skill: &SkillCardV2,
        state: SkillLifecycleState,
        reason: Option<String>,
    ) -> (SkillCardV2, SkillLifecycleRecord) {
        let mut next = skill.clone();
        next.lifecycle_state = state;
        next.updated_at = OffsetDateTime::now_utc();
        let record = Self::record_for(&next, reason);
        (next, record)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillActivationContext {
    pub goal: String,
    pub evidence_refs: Vec<String>,
    pub available_input_sources: Vec<SkillInputSource>,
    pub available_input_names: Vec<String>,
    pub available_capabilities: Vec<String>,
    pub available_tools: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub active_negative_signals: Vec<String>,
    pub conflicting_skill_refs: Vec<SkillId>,
    pub audit_mode: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SkillActivationGate;

impl SkillActivationGate {
    pub fn decide(skill: &SkillCardV2, context: &SkillActivationContext) -> SkillActivationRecord {
        if skill.lifecycle_state != SkillLifecycleState::Active {
            let decision =
                if context.audit_mode && skill.lifecycle_state == SkillLifecycleState::Candidate {
                    SkillActivationDecision::AuditOnly
                } else {
                    SkillActivationDecision::ExcludeLifecycleState
                };
            return activation_record(skill, decision, "skill is not active");
        }
        if !applies_to_goal(skill, context) {
            return activation_record(
                skill,
                SkillActivationDecision::ExcludeNotApplicable,
                "applies_when did not match task evidence",
            );
        }
        if anti_scope_matches(skill, context) {
            return activation_record(
                skill,
                SkillActivationDecision::ExcludeNotApplicable,
                "does_not_apply_when matched current task",
            );
        }
        if missing_required_inputs(skill, context) {
            return activation_record(
                skill,
                SkillActivationDecision::ExcludeMissingInputs,
                "required skill inputs or capabilities are unavailable",
            );
        }
        if missing_verifier(skill, context) {
            return activation_record(
                skill,
                SkillActivationDecision::ExcludeMissingVerifier,
                "required verifier plan is unavailable",
            );
        }
        if known_failure_active(skill, context) {
            return activation_record(
                skill,
                SkillActivationDecision::ExcludeNegativeMemory,
                "known skill failure mode is active",
            );
        }
        if context.conflicting_skill_refs.contains(&skill.skill_id) {
            return activation_record(
                skill,
                SkillActivationDecision::ExcludeConflict,
                "skill conflicts with selected skill set",
            );
        }
        activation_record(
            skill,
            SkillActivationDecision::Allow,
            "skill activation allowed",
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillNeedEstimator;

impl SkillNeedEstimator {
    pub fn estimate(
        project_id: ProjectId,
        task_id: TaskId,
        skill: &SkillCardV2,
        context: &SkillActivationContext,
    ) -> SkillNeedEstimate {
        let activation = SkillActivationGate::decide(skill, context);
        let scope_match = f64::from(applies_to_goal(skill, context));
        let recent_success = if skill.success_count > skill.failure_count {
            0.15
        } else {
            0.0
        };
        let recent_failure = if skill.failure_count > skill.success_count {
            0.25
        } else {
            0.0
        };
        let context_cost =
            f64::from(u32::try_from(estimated_skill_context_cost(skill)).unwrap_or(u32::MAX));
        let cost_penalty = (context_cost / 2000.0).min(0.25);
        let verifier_bonus = if missing_verifier(skill, context) {
            -0.20
        } else {
            0.15
        };
        let necessity = (0.20 + (0.55 * scope_match) + verifier_bonus).clamp(0.0, 1.0);
        let utility =
            (0.30 + (0.35 * scope_match) + recent_success + verifier_bonus).clamp(0.0, 1.0);
        let distractor_risk = (0.20
            + cost_penalty
            + recent_failure
            + f64::from(activation.decision != SkillActivationDecision::Allow) * 0.30)
            .clamp(0.0, 1.0);
        let verdict = match activation.decision {
            SkillActivationDecision::Allow if necessity >= 0.55 && distractor_risk < 0.65 => {
                SkillNeedVerdict::Include
            }
            SkillActivationDecision::AuditOnly => SkillNeedVerdict::AuditOnly,
            SkillActivationDecision::ExcludeMissingInputs
            | SkillActivationDecision::ExcludeMissingVerifier => {
                SkillNeedVerdict::RequireMoreContext
            }
            _ => SkillNeedVerdict::Exclude,
        };
        SkillNeedEstimate {
            estimate_id: format!("skill-estimate-{}", WriteId::new_v7()),
            project_id,
            task_id,
            candidate_skill: skill.skill_id,
            necessity,
            utility,
            distractor_risk,
            verdict,
            reasons: activation.reasons,
            evidence_refs: context.evidence_refs.clone(),
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillDistractorFilterService;

impl SkillDistractorFilterService {
    pub fn filter(
        project_id: ProjectId,
        task_id: TaskId,
        skills: &[SkillCardV2],
        context: &SkillActivationContext,
    ) -> SkillDistractorFilter {
        let mut included = Vec::new();
        let mut removed = Vec::new();
        let mut reasons = Vec::new();
        for skill in skills {
            let estimate = SkillNeedEstimator::estimate(project_id, task_id, skill, context);
            if estimate.verdict == SkillNeedVerdict::Include {
                included.push(skill.skill_id);
            } else {
                removed.push(skill.skill_id);
            }
            reasons.push(format!(
                "{}:{:?}:{:.2}/{:.2}/{:.2}",
                skill.name,
                estimate.verdict,
                estimate.necessity,
                estimate.utility,
                estimate.distractor_risk
            ));
        }
        SkillDistractorFilter {
            filter_id: format!("skill-filter-{}", WriteId::new_v7()),
            project_id,
            task_id,
            skills_considered: skills.iter().map(|skill| skill.skill_id).collect(),
            skills_included: included,
            distractors_removed: removed,
            reasons,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn procedural_packet(
        project_id: ProjectId,
        task_id: TaskId,
        skills: &[SkillCardV2],
        context: &SkillActivationContext,
    ) -> eliot_types::ProceduralSkillPacketView {
        let filter = Self::filter(project_id, task_id, skills, context);
        let activation_decisions = skills
            .iter()
            .map(|skill| SkillActivationGate::decide(skill, context))
            .collect::<Vec<_>>();
        let included_set = filter
            .skills_included
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let required_verifiers = skills
            .iter()
            .filter(|skill| included_set.contains(&skill.skill_id))
            .flat_map(|skill| {
                skill
                    .verification_plan
                    .required
                    .iter()
                    .map(|verifier| verifier.command_display.clone())
            })
            .collect();
        let anti_scope_warnings = activation_decisions
            .iter()
            .filter(|record| record.decision == SkillActivationDecision::ExcludeNotApplicable)
            .flat_map(|record| record.reasons.clone())
            .collect();
        eliot_types::ProceduralSkillPacketView {
            included_skills: filter.skills_included,
            excluded_skills: filter.distractors_removed.clone(),
            activation_decisions,
            distractors_removed: filter.distractors_removed,
            required_verifiers,
            anti_scope_warnings,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillExecutionProofService;

impl SkillExecutionProofService {
    pub fn proof(
        skill_ref: SkillId,
        project_id: ProjectId,
        task_id: TaskId,
        steps_used: Vec<String>,
        outputs: Vec<String>,
        verifier_refs: Vec<String>,
        outcome: SkillExecutionOutcome,
    ) -> SkillExecutionProof {
        SkillExecutionProof {
            proof_id: format!("skill-execution-proof-{}", WriteId::new_v7()),
            skill_ref,
            project_id,
            task_id,
            steps_used,
            skipped_steps: Vec::new(),
            outputs,
            verifier_refs,
            outcome,
            failure_mode_refs: Vec::new(),
            created_at: OffsetDateTime::now_utc(),
            write_receipt: None,
        }
    }

    pub async fn write_proof(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        proof: &mut SkillExecutionProof,
    ) -> Result<WriteReceiptRef, EngineError> {
        let receipt = write_skill_observation(
            writer,
            admission,
            proof.skill_ref,
            "skill_execution_proof",
            &*proof,
        )
        .await?;
        proof.write_receipt = Some(receipt.clone());
        Ok(receipt)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SkillInfluenceService;

#[derive(Clone, Debug)]
pub struct SkillInfluenceReportInput {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub packet_id: Option<String>,
    pub considered: Vec<SkillId>,
    pub included: Vec<SkillId>,
    pub executed: Vec<SkillId>,
    pub execution_proofs: Vec<String>,
    pub estimated_context_cost: u64,
}

impl SkillInfluenceService {
    pub fn report(input: SkillInfluenceReportInput) -> SkillInfluenceReport {
        let included_set = input.included.iter().copied().collect::<BTreeSet<_>>();
        let excluded = input
            .considered
            .iter()
            .copied()
            .filter(|skill_id| !included_set.contains(skill_id))
            .collect();
        SkillInfluenceReport {
            report_id: format!("skill-influence-{}", WriteId::new_v7()),
            project_id: input.project_id,
            task_id: input.task_id,
            packet_id: input.packet_id,
            skills_considered: input.considered,
            skills_included: input.included,
            skills_excluded: excluded,
            skills_executed: input.executed,
            execution_proofs: input.execution_proofs,
            estimated_context_cost: input.estimated_context_cost,
            observed_decision_delta: None,
            created_at: OffsetDateTime::now_utc(),
            write_receipt: None,
        }
    }

    pub async fn write_report(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        report: &mut SkillInfluenceReport,
    ) -> Result<WriteReceiptRef, EngineError> {
        let first_skill = report
            .skills_included
            .first()
            .copied()
            .or_else(|| report.skills_considered.first().copied())
            .unwrap_or_else(SkillId::new_v7);
        let receipt = write_skill_observation(
            writer,
            admission,
            first_skill,
            "skill_influence_report",
            &*report,
        )
        .await?;
        report.write_receipt = Some(receipt.clone());
        Ok(receipt)
    }
}

fn validate_skill_card(skill: &SkillCardV2) -> Result<(), EngineError> {
    if skill.name.trim().is_empty()
        || skill.purpose.trim().is_empty()
        || skill.version.trim().is_empty()
        || skill.owner.trim().is_empty()
        || skill.applies_when.is_empty()
        || skill.does_not_apply_when.is_empty()
        || skill.required_inputs.is_empty()
        || skill.expected_outputs.is_empty()
    {
        return Err(EngineError::WriteRejected(
            "skill card missing required lifecycle fields".to_owned(),
        ));
    }
    Ok(())
}

fn activation_record(
    skill: &SkillCardV2,
    decision: SkillActivationDecision,
    reason: &str,
) -> SkillActivationRecord {
    SkillActivationRecord {
        skill_ref: skill.skill_id,
        decision,
        reasons: vec![reason.to_owned()],
    }
}

fn applies_to_goal(skill: &SkillCardV2, context: &SkillActivationContext) -> bool {
    !skill.applies_when.is_empty()
        && skill
            .applies_when
            .iter()
            .any(|rule| scope_rule_matches(rule, context))
}

fn anti_scope_matches(skill: &SkillCardV2, context: &SkillActivationContext) -> bool {
    skill
        .does_not_apply_when
        .iter()
        .any(|rule| scope_rule_matches(rule, context))
}

fn scope_rule_matches(
    rule: &eliot_types::SkillScopeRule,
    context: &SkillActivationContext,
) -> bool {
    let text = context.goal.to_ascii_lowercase();
    let examples_match = std::iter::once(&rule.description)
        .chain(rule.positive_examples.iter())
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !value.trim().is_empty())
        .any(|needle| text.contains(&needle));
    let evidence_match = rule.required_evidence_refs.is_empty()
        || rule
            .required_evidence_refs
            .iter()
            .any(|reference| context.evidence_refs.contains(reference));
    examples_match && evidence_match
}

fn missing_required_inputs(skill: &SkillCardV2, context: &SkillActivationContext) -> bool {
    let missing_named_input = skill.required_inputs.iter().any(|input| {
        input.required
            && !context.available_input_sources.contains(&input.source)
            && !context
                .available_input_names
                .iter()
                .any(|name| name == &input.name)
    });
    let missing_required_tool = skill
        .required_tools_and_capabilities
        .iter()
        .any(|requirement| {
            if !requirement.required {
                return false;
            }
            let capability_present = context
                .available_capabilities
                .iter()
                .any(|capability| capability == &requirement.capability);
            let tool_present = requirement.allowed_tools.is_empty()
                || requirement
                    .allowed_tools
                    .iter()
                    .any(|tool| context.available_tools.contains(tool));
            let forbidden_present = requirement
                .forbidden_tools
                .iter()
                .any(|tool| context.available_tools.contains(tool));
            !capability_present || !tool_present || forbidden_present
        });
    missing_named_input || missing_required_tool
}

fn missing_verifier(skill: &SkillCardV2, context: &SkillActivationContext) -> bool {
    if skill.verification_plan.required.is_empty() {
        return true;
    }
    if context.verifier_refs.is_empty() {
        return true;
    }
    skill.verification_plan.required.iter().any(|verifier| {
        !context
            .verifier_refs
            .iter()
            .any(|reference| reference == &verifier.name || reference == &verifier.command_display)
    })
}

fn known_failure_active(skill: &SkillCardV2, context: &SkillActivationContext) -> bool {
    skill.known_failure_modes.iter().any(|failure| {
        context
            .active_negative_signals
            .iter()
            .any(|signal| signal == &failure.detection_signal)
            || context
                .goal
                .to_ascii_lowercase()
                .contains(&failure.detection_signal.to_ascii_lowercase())
    })
}

fn estimated_skill_context_cost(skill: &SkillCardV2) -> u64 {
    serde_json::to_string(skill).map_or(0, |text| text.len().div_ceil(4) as u64)
}

async fn write_skill_observation<T>(
    writer: &WriterHandle,
    admission: &WriteAdmissionService,
    skill_id: SkillId,
    tool_name: &str,
    payload: &T,
) -> Result<WriteReceiptRef, EngineError>
where
    T: Serialize,
{
    let project_id = extract_project(payload).unwrap_or_else(ProjectId::new_v7);
    let task_id = extract_task(payload);
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id,
            scope: "skill-lifecycle".to_owned(),
            authority: "eliot-skill-lifecycle-service".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: tool_name.to_owned(),
        observation: format!("{tool_name} recorded for skill {skill_id}"),
        payload: serde_json::to_value(payload)?,
    });
    let receipt = writer.submit(admission.admit(&command)?).await?;
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

fn extract_project<T>(payload: &T) -> Option<ProjectId>
where
    T: Serialize,
{
    let value = serde_json::to_value(payload).ok()?;
    value
        .get("project_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse().ok())
}

fn extract_task<T>(payload: &T) -> Option<TaskId>
where
    T: Serialize,
{
    let value = serde_json::to_value(payload).ok()?;
    value
        .get("task_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse().ok())
}
