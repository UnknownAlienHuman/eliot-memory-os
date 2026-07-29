use eliot_engine::{
    ActionLeaseEvaluation, ActionLeaseService, CognitiveGate, CompletionGate,
    SkillActivationContext, SkillActivationGate, SkillDistractorFilterService,
    SkillExecutionProofService, SkillInfluenceReportInput, SkillInfluenceService,
    SkillLifecycleService, SkillNeedEstimator, SkillRegistryService, WriteAdmissionService,
    WriterActor, WriterConfig, codecortex_report_ref,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    ActionKind, ActionRequest, AgentId, BlastRadiusView, ChangePlan, CodeCortexReport,
    CodeEvidenceSource, CognitiveGateOutcome, CognitiveGateReason, CognitiveGateRequest,
    CompletionAcceptanceItem, CompletionProof, CompletionStatus, ControlWalConfig,
    DiagnosticEvidence, FileChangeIntent, FileChangeKind, FileEvidence, GovernorConfig,
    InvariantCard, LeaseDecision, LeaseDenyReason, SkillActivationDecision, SkillExecutionOutcome,
    SkillFailureMode, SkillId, SkillInputRequirement, SkillInputSource, SkillLevel,
    SkillLifecycleState, SkillOutputSpec, SkillScopeRule, SkillStep, SkillToolRequirement,
    SymbolChangeIntent, SymbolEvidence, TaskId, UnderstandingProof, UnderstandingProofReceipt,
    VerifierCommandKind, VerifierEvidence, VerifierPlan, VerifierRequirement,
};
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::time::{Duration, Instant, sleep};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn skill_card_v2_defaults_to_candidate_and_is_audit_only() {
    let candidate =
        SkillRegistryService::create_candidate("audit candidate", "skill-lifecycle-test");
    let context = skill_context(candidate.skill_id);
    let activation = SkillActivationGate::decide(&candidate, &context);

    assert_eq!(candidate.lifecycle_state, SkillLifecycleState::Candidate);
    assert_eq!(
        activation.decision,
        SkillActivationDecision::ExcludeLifecycleState
    );
    assert!(candidate.verification_plan.required.is_empty());
}

#[test]
fn candidate_stale_archived_and_quarantined_skills_do_not_activate_by_default() {
    let active = active_skill();
    let context = skill_context(active.skill_id);
    let candidate = skill_with_state(SkillLifecycleState::Candidate);
    let stale = skill_with_state(SkillLifecycleState::Stale);
    let (archived, _) = SkillLifecycleService::archive(&active, "operator archived it");
    let (quarantined, _) = SkillLifecycleService::quarantine(&active, "negative transfer");

    for skill in [candidate, stale, archived, quarantined] {
        let activation = SkillActivationGate::decide(&skill, &context);
        assert_eq!(
            activation.decision,
            SkillActivationDecision::ExcludeLifecycleState
        );
    }
}

#[test]
fn activation_requires_scope_inputs_verifier_and_no_known_failure() {
    let skill = active_skill();
    let mut context = skill_context(skill.skill_id);
    let allowed = SkillActivationGate::decide(&skill, &context);
    assert_eq!(allowed.decision, SkillActivationDecision::Allow);

    context.goal = "inspect unrelated runtime".to_owned();
    assert_eq!(
        SkillActivationGate::decide(&skill, &context).decision,
        SkillActivationDecision::ExcludeNotApplicable
    );

    context = skill_context(skill.skill_id);
    context.available_input_sources.clear();
    context.available_input_names.clear();
    assert_eq!(
        SkillActivationGate::decide(&skill, &context).decision,
        SkillActivationDecision::ExcludeMissingInputs
    );

    context = skill_context(skill.skill_id);
    context.verifier_refs.clear();
    assert_eq!(
        SkillActivationGate::decide(&skill, &context).decision,
        SkillActivationDecision::ExcludeMissingVerifier
    );

    context = skill_context(skill.skill_id);
    context.active_negative_signals = vec!["scope-drift".to_owned()];
    assert_eq!(
        SkillActivationGate::decide(&skill, &context).decision,
        SkillActivationDecision::ExcludeNegativeMemory
    );
}

#[test]
fn skill_need_estimate_and_filter_include_only_allowed_skills() {
    let project_id = eliot_types::ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let included = active_skill();
    let missing_verifier = {
        let mut skill = active_skill();
        skill.skill_id = SkillId::new_v7();
        skill.name = "missing verifier skill".to_owned();
        skill
    };
    let archived = skill_with_state(SkillLifecycleState::Archived);
    let context = skill_context(included.skill_id);
    let mut missing_context = skill_context(missing_verifier.skill_id);
    missing_context.verifier_refs.clear();

    let include_estimate = SkillNeedEstimator::estimate(project_id, task_id, &included, &context);
    let missing_estimate =
        SkillNeedEstimator::estimate(project_id, task_id, &missing_verifier, &missing_context);
    let filter = SkillDistractorFilterService::filter(
        project_id,
        task_id,
        &[included.clone(), archived.clone()],
        &context,
    );

    assert_eq!(
        include_estimate.verdict,
        eliot_types::SkillNeedVerdict::Include
    );
    assert_eq!(
        missing_estimate.verdict,
        eliot_types::SkillNeedVerdict::RequireMoreContext
    );
    assert_eq!(filter.skills_included, vec![included.skill_id]);
    assert!(filter.distractors_removed.contains(&archived.skill_id));
}

#[test]
fn procedural_skill_packet_is_l3_state_not_truth() {
    let project_id = eliot_types::ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let skill = active_skill();
    let archived = skill_with_state(SkillLifecycleState::Archived);
    let packet = SkillDistractorFilterService::procedural_packet(
        project_id,
        task_id,
        &[skill.clone(), archived.clone()],
        &skill_context(skill.skill_id),
    );

    assert_eq!(packet.included_skills, vec![skill.skill_id]);
    assert!(packet.excluded_skills.contains(&archived.skill_id));
    assert!(
        packet
            .activation_decisions
            .iter()
            .any(|decision| decision.decision == SkillActivationDecision::Allow)
    );
    assert_eq!(packet.required_verifiers, vec!["just verify".to_owned()]);
}

#[test]
fn understanding_proof_and_cognitive_gate_block_ungrounded_skill_use() {
    let project_id = eliot_types::ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let skill = active_skill();
    let valid = understanding_proof(project_id, task_id, skill.skill_id, true);
    let mut invalid = valid.clone();
    invalid.skill_verifier_plan_refs.clear();
    invalid.expected_verifiers.clear();

    let mut errors = skill_validation_errors(&invalid);
    let receipt = receipt_from_errors(project_id, task_id, std::mem::take(&mut errors));
    let gate = CognitiveGate::decide(&CognitiveGateRequest {
        receipt,
        requested_action: "apply governed skill".to_owned(),
    });

    assert_eq!(gate.decision, CognitiveGateOutcome::Block);
    assert!(
        gate.reasons
            .contains(&CognitiveGateReason::SkillMissingVerifier)
    );
    assert!(skill_validation_errors(&valid).is_empty());
}

#[test]
fn action_lease_rejects_skills_that_bypass_activation_gate() {
    let project_id = eliot_types::ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let agent_id = AgentId::new_v7();
    let skill = active_skill();
    let report = codecortex_report();
    let report_ref = codecortex_report_ref(&report);
    let proof = understanding_proof(project_id, task_id, skill.skill_id, false);
    let receipt = action_receipt(project_id, task_id, report_ref);
    let gate = CognitiveGate::decide(&CognitiveGateRequest {
        receipt: receipt.clone(),
        requested_action: "inspect skill activation".to_owned(),
    });
    let mut request = action_request(project_id, task_id, agent_id, skill.skill_id);
    request.skill_activation_decisions.clear();

    let lease = ActionLeaseService.evaluate(&ActionLeaseEvaluation {
        request: &request,
        understanding_proof: Some(&proof),
        understanding_receipt: &receipt,
        cognitive_gate_decision: &gate,
        codecortex_reports: &[report],
        current_git_head: Some("skill-lifecycle-head"),
        work_lease: None,
        incident_lockdown_active: false,
    });

    assert_eq!(lease.decision, LeaseDecision::Deny);
    assert!(
        lease
            .denial_reasons
            .contains(&LeaseDenyReason::SkillActivationNotAllowed)
    );
}

#[test]
fn action_lease_allows_governed_skill_activation_for_non_execution_plan() {
    let project_id = eliot_types::ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let agent_id = AgentId::new_v7();
    let skill = active_skill();
    let report = codecortex_report();
    let report_ref = codecortex_report_ref(&report);
    let proof = understanding_proof(project_id, task_id, skill.skill_id, false);
    let receipt = action_receipt(project_id, task_id, report_ref);
    let gate = CognitiveGate::decide(&CognitiveGateRequest {
        receipt: receipt.clone(),
        requested_action: "inspect skill activation".to_owned(),
    });
    let request = action_request(project_id, task_id, agent_id, skill.skill_id);

    let lease = ActionLeaseService.evaluate(&ActionLeaseEvaluation {
        request: &request,
        understanding_proof: Some(&proof),
        understanding_receipt: &receipt,
        cognitive_gate_decision: &gate,
        codecortex_reports: &[report],
        current_git_head: Some("skill-lifecycle-head"),
        work_lease: None,
        incident_lockdown_active: false,
    });

    assert_eq!(lease.decision, LeaseDecision::AllowReadOnly);
    assert_eq!(lease.skill_refs, vec![skill.skill_id]);
    assert!(
        !lease
            .denial_reasons
            .contains(&LeaseDenyReason::SkillWouldBypassGate)
    );
}

#[test]
fn completion_gate_requires_skill_execution_proof_and_failed_skill_blocks_done() {
    let skill = active_skill();
    let project_id = eliot_types::ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut proof = completion_proof(project_id, task_id, skill.skill_id);
    proof.skill_execution_proof_refs.clear();

    let missing = CompletionGate::decide(&proof);
    assert_eq!(missing.final_status, CompletionStatus::PartialProgress);
    assert!(
        missing
            .reasons
            .contains(&"missing_skill_execution_proof".to_owned())
    );

    proof.skill_execution_proof_refs = vec!["failed:skill-execution-proof-i1".to_owned()];
    let failed = CompletionGate::decide(&proof);
    assert_eq!(failed.final_status, CompletionStatus::FailedVerifier);
}

#[test]
fn skill_lifecycle_updates_counters_and_proposes_memory_lifecycle_actions() {
    let project_id = eliot_types::ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let skill = active_skill();
    let record = SkillLifecycleService::record_for(&skill, None);
    let proof = SkillExecutionProofService::proof(
        skill.skill_id,
        project_id,
        task_id,
        vec!["run-step".to_owned()],
        vec!["output".to_owned()],
        vec!["just verify".to_owned()],
        SkillExecutionOutcome::NegativeTransfer,
    );
    let updated = SkillLifecycleService::update_execution_counters(record, &proof);
    let stale_policy = SkillLifecycleService::repeated_irrelevant_activation_policy(
        project_id,
        skill.skill_id,
        vec!["proof:false-activation".to_owned()],
    );
    let quarantine_policy = SkillLifecycleService::negative_transfer_policy(
        project_id,
        skill.skill_id,
        vec!["proof:negative-transfer".to_owned()],
    );

    assert_eq!(updated.state, SkillLifecycleState::Quarantined);
    assert_eq!(
        updated.demotion_reason.as_deref(),
        Some("negative_transfer")
    );
    assert_eq!(stale_policy.target_ref, format!("skill:{}", skill.skill_id));
    assert_eq!(
        quarantine_policy.target_ref,
        format!("skill:{}", skill.skill_id)
    );
}

#[tokio::test]
#[ignore = "requires an authenticated local SurrealDB"]
async fn skill_execution_proof_and_influence_report_write_through_writer_actor() -> TestResult {
    let _guard = lock_tests().await?;
    let harness = Harness::new("skill-proof-writer").await?;
    let (handle, actor) = harness.writer_pair("skill-proof-writer")?;
    let actor_task = tokio::spawn(actor.run());
    let project_id = eliot_types::ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let skill = active_skill();
    let mut proof = SkillExecutionProofService::proof(
        skill.skill_id,
        project_id,
        task_id,
        vec!["run-step".to_owned()],
        vec!["proof-output".to_owned()],
        vec!["just verify".to_owned()],
        SkillExecutionOutcome::Succeeded,
    );
    let proof_receipt =
        SkillExecutionProofService::write_proof(&handle, &WriteAdmissionService, &mut proof)
            .await?;
    let mut influence = SkillInfluenceService::report(SkillInfluenceReportInput {
        project_id,
        task_id,
        packet_id: Some("packet:skill-lifecycle".to_owned()),
        considered: vec![skill.skill_id, SkillId::new_v7()],
        included: vec![skill.skill_id],
        executed: vec![skill.skill_id],
        execution_proofs: vec![proof.proof_id.clone()],
        estimated_context_cost: 128,
    });
    let influence_receipt =
        SkillInfluenceService::write_report(&handle, &WriteAdmissionService, &mut influence)
            .await?;

    drop(handle);
    actor_task.await?;

    assert_eq!(
        proof.write_receipt.as_ref().map(|r| r.write_id),
        Some(proof_receipt.write_id)
    );
    assert_eq!(
        influence.write_receipt.as_ref().map(|r| r.write_id),
        Some(influence_receipt.write_id)
    );
    assert_eq!(influence.skills_excluded.len(), 1);
    Ok(())
}

fn active_skill() -> eliot_types::SkillCardV2 {
    skill_with_state(SkillLifecycleState::Active)
}

fn skill_with_state(state: SkillLifecycleState) -> eliot_types::SkillCardV2 {
    let now = time::OffsetDateTime::now_utc();
    let skill_id = SkillId::new_v7();
    eliot_types::SkillCardV2 {
        skill_id,
        name: "skill lifecycle scoped skill".to_owned(),
        purpose: "apply the verifier-backed procedural path".to_owned(),
        level: SkillLevel::Procedure,
        lifecycle_state: state,
        applies_when: vec![SkillScopeRule {
            rule_id: "skill-lifecycle-scope".to_owned(),
            description: "skill lifecycle skill lifecycle".to_owned(),
            positive_examples: vec!["skill lifecycle skill lifecycle".to_owned()],
            negative_examples: vec!["unrelated runtime".to_owned()],
            required_evidence_refs: vec!["runbook:skill-lifecycle".to_owned()],
        }],
        does_not_apply_when: vec![SkillScopeRule {
            rule_id: "skill-lifecycle-anti-scope".to_owned(),
            description: "unrelated runtime".to_owned(),
            positive_examples: vec!["unrelated runtime".to_owned()],
            negative_examples: vec!["skill lifecycle skill lifecycle".to_owned()],
            required_evidence_refs: Vec::new(),
        }],
        required_inputs: vec![SkillInputRequirement {
            name: "task_goal".to_owned(),
            description: "the governed task goal".to_owned(),
            required: true,
            source: SkillInputSource::UserPrompt,
        }],
        ordered_steps: vec![SkillStep {
            step_id: "ground-scope".to_owned(),
            order: 1,
            instruction: "Confirm scope, anti-scope, and verifier plan before use.".to_owned(),
            expected_observation: Some("scope grounded".to_owned()),
            required_tool_or_capability: Some("rust-toolchain".to_owned()),
            stop_if_fails: true,
        }],
        required_tools_and_capabilities: vec![SkillToolRequirement {
            capability: "rust-toolchain".to_owned(),
            required: true,
            allowed_tools: vec!["cargo".to_owned(), "just".to_owned()],
            forbidden_tools: vec!["surreal sql".to_owned()],
        }],
        expected_outputs: vec![SkillOutputSpec {
            name: "skill_execution_proof".to_owned(),
            description: "proof with verifier refs".to_owned(),
            evidence_required: true,
            verifier_required: true,
        }],
        verification_plan: verifier_plan(),
        stop_conditions: vec!["missing verifier".to_owned()],
        known_failure_modes: vec![SkillFailureMode {
            failure_id: "scope-drift".to_owned(),
            description: "skill selected outside its audited scope".to_owned(),
            detection_signal: "scope-drift".to_owned(),
            mitigation: "exclude the skill and record false activation evidence".to_owned(),
            negative_memory_refs: vec!["failure:scope-drift".to_owned()],
        }],
        rollback_or_recovery: Some("archive or quarantine the skill".to_owned()),
        source_trace_refs: vec!["runbook:skill-lifecycle".to_owned()],
        replay_result_refs: vec!["replay:skill-lifecycle".to_owned()],
        success_count: 2,
        failure_count: 0,
        last_verified_at: Some(now),
        version: "1.0.0".to_owned(),
        owner: "skill-lifecycle-test".to_owned(),
        created_at: now,
        updated_at: now,
    }
}

fn skill_context(skill_id: SkillId) -> SkillActivationContext {
    SkillActivationContext {
        goal: "skill lifecycle skill lifecycle runbook:skill-lifecycle".to_owned(),
        evidence_refs: vec!["runbook:skill-lifecycle".to_owned()],
        available_input_sources: vec![SkillInputSource::UserPrompt],
        available_input_names: vec!["task_goal".to_owned()],
        available_capabilities: vec!["rust-toolchain".to_owned()],
        available_tools: vec!["cargo".to_owned(), "just".to_owned()],
        verifier_refs: vec!["just verify".to_owned()],
        active_negative_signals: Vec::new(),
        conflicting_skill_refs: Vec::new(),
        audit_mode: false,
    }
    .with_conflict_guard(skill_id)
}

trait SkillContextFixture {
    fn with_conflict_guard(self, _skill_id: SkillId) -> Self;
}

impl SkillContextFixture for SkillActivationContext {
    fn with_conflict_guard(self, _skill_id: SkillId) -> Self {
        self
    }
}

fn verifier_plan() -> VerifierPlan {
    VerifierPlan {
        required: vec![VerifierRequirement {
            name: "just verify".to_owned(),
            command_kind: VerifierCommandKind::CargoTest,
            command_display: "just verify".to_owned(),
            scope: vec![".".to_owned()],
            required_for_done: true,
            expected_signal: "exit code 0".to_owned(),
        }],
        optional: Vec::new(),
        acceptance_items: vec!["skill proof is verifier-backed".to_owned()],
    }
}

fn understanding_proof(
    project_id: eliot_types::ProjectId,
    task_id: TaskId,
    skill_id: SkillId,
    include_skill_grounding: bool,
) -> UnderstandingProof {
    UnderstandingProof {
        task_id: task_id.to_string(),
        project_id,
        goal: "skill lifecycle skill lifecycle".to_owned(),
        code_task: true,
        current_truth_refs: Vec::new(),
        evidence_refs: Vec::new(),
        codecortex_report_refs: vec![codecortex_report_ref(&codecortex_report())],
        files_to_change: vec!["crates/eliot-engine/src/skill.rs".to_owned()],
        files_to_inspect: Vec::new(),
        causal_bridge: "skill use is grounded in runbook requirements".to_owned(),
        causal_bridge_from_goal_to_code:
            "the skill lifecycle is implemented in engine skill services".to_owned(),
        invariants: vec!["skills cannot bypass gates".to_owned()],
        negative_memory_checked: true,
        unknowns: Vec::new(),
        planned_action: "inspect governed skill path".to_owned(),
        expected_verifiers: if include_skill_grounding {
            vec!["just verify".to_owned()]
        } else {
            Vec::new()
        },
        blast_radius_acknowledged: true,
        skill_refs: vec![skill_id],
        skill_application_rationales: if include_skill_grounding {
            vec!["task matches skill lifecycle scope".to_owned()]
        } else {
            Vec::new()
        },
        skill_anti_scope_acknowledgements: if include_skill_grounding {
            vec!["anti-scope did not match".to_owned()]
        } else {
            Vec::new()
        },
        skill_required_inputs: if include_skill_grounding {
            vec!["task_goal".to_owned()]
        } else {
            Vec::new()
        },
        skill_verifier_plan_refs: if include_skill_grounding {
            vec!["just verify".to_owned()]
        } else {
            Vec::new()
        },
        risk_level: "low".to_owned(),
    }
}

fn skill_validation_errors(proof: &UnderstandingProof) -> Vec<CognitiveGateReason> {
    let mut errors = Vec::new();
    if !proof.skill_refs.is_empty()
        && (proof.skill_application_rationales.is_empty()
            || proof.skill_anti_scope_acknowledgements.is_empty())
    {
        errors.push(CognitiveGateReason::SkillNotApplicable);
    }
    if !proof.skill_refs.is_empty() && proof.skill_required_inputs.is_empty() {
        errors.push(CognitiveGateReason::SkillMissingInputs);
    }
    if !proof.skill_refs.is_empty()
        && (proof.skill_verifier_plan_refs.is_empty() || proof.expected_verifiers.is_empty())
    {
        errors.push(CognitiveGateReason::SkillMissingVerifier);
    }
    errors
}

fn receipt_from_errors(
    project_id: eliot_types::ProjectId,
    task_id: TaskId,
    validation_errors: Vec<CognitiveGateReason>,
) -> UnderstandingProofReceipt {
    UnderstandingProofReceipt {
        task_id: task_id.to_string(),
        project_id,
        accepted: validation_errors.is_empty(),
        validation_errors,
        checked_refs: vec!["skill:skill-lifecycle".to_owned()],
        code_task: false,
        codecortex_report_refs: Vec::new(),
        files_to_change: Vec::new(),
        files_to_inspect: Vec::new(),
    }
}

fn action_receipt(
    project_id: eliot_types::ProjectId,
    task_id: TaskId,
    report_ref: String,
) -> UnderstandingProofReceipt {
    UnderstandingProofReceipt {
        task_id: task_id.to_string(),
        project_id,
        accepted: true,
        validation_errors: Vec::new(),
        checked_refs: vec![report_ref.clone(), "skill:skill-lifecycle".to_owned()],
        code_task: true,
        codecortex_report_refs: vec![report_ref],
        files_to_change: vec!["crates/eliot-engine/src/skill.rs".to_owned()],
        files_to_inspect: Vec::new(),
    }
}

fn action_request(
    project_id: eliot_types::ProjectId,
    task_id: TaskId,
    agent_id: AgentId,
    skill_id: SkillId,
) -> ActionRequest {
    let report = codecortex_report();
    ActionRequest {
        request_id: eliot_types::ActionRequestId::new_v7(),
        project_id,
        task_id,
        agent_id,
        goal: "inspect governed skill path".to_owned(),
        requested_action_kind: ActionKind::ReadOnlyInspect,
        understanding_proof_ref: "understanding_proof:skill-lifecycle".to_owned(),
        cognitive_gate_ref: "cognitive_gate:skill-lifecycle".to_owned(),
        codecortex_report_refs: vec![codecortex_report_ref(&report)],
        skill_refs: vec![skill_id],
        skill_activation_decisions: vec![eliot_types::SkillActivationRecord {
            skill_ref: skill_id,
            decision: SkillActivationDecision::Allow,
            reasons: vec!["skill activation allowed".to_owned()],
        }],
        proposed_change_plan: ChangePlan {
            summary: "Read-only skill lifecycle inspection".to_owned(),
            files: vec![FileChangeIntent {
                path: "crates/eliot-engine/src/skill.rs".to_owned(),
                reason: "engine skill service owns lifecycle decisions".to_owned(),
                expected_change_kind: FileChangeKind::ReadOnly,
                code_evidence_refs: vec!["file:crates/eliot-engine/src/skill.rs".to_owned()],
            }],
            symbols: vec![SymbolChangeIntent {
                symbol: "SkillActivationGate".to_owned(),
                reason: "activation gate owns skill admission".to_owned(),
                expected_change_kind: FileChangeKind::ReadOnly,
                code_evidence_refs: vec!["symbol:SkillActivationGate".to_owned()],
            }],
            invariants_to_preserve: vec!["skills do not bypass gates".to_owned()],
            risks: Vec::new(),
            rollback_plan: None,
        },
        proposed_verifier_plan: verifier_plan(),
        created_at: time::OffsetDateTime::now_utc(),
    }
}

fn completion_proof(
    project_id: eliot_types::ProjectId,
    task_id: TaskId,
    skill_id: SkillId,
) -> CompletionProof {
    CompletionProof {
        task_id: task_id.to_string(),
        project_id,
        goal: "skill lifecycle skill lifecycle".to_owned(),
        changed_files: vec!["crates/eliot-engine/src/skill.rs".to_owned()],
        memory_refs_used: vec!["skill:skill-lifecycle".to_owned()],
        evidence: vec!["proof:skill-lifecycle".to_owned()],
        checks_run: vec!["just verify".to_owned()],
        checks_not_run: Vec::new(),
        acceptance_items: vec![CompletionAcceptanceItem {
            item: "skill proof is verifier-backed".to_owned(),
            status: "verified".to_owned(),
            evidence: "proof:skill-lifecycle".to_owned(),
            verifier: "just verify".to_owned(),
            residual_uncertainty: "none".to_owned(),
        }],
        skill_refs: vec![skill_id],
        skill_execution_proof_refs: vec!["skill-execution-proof:skill-lifecycle".to_owned()],
        residual_uncertainty: "none".to_owned(),
        known_risks: Vec::new(),
    }
}

fn codecortex_report() -> CodeCortexReport {
    let file = FileEvidence {
        path: "crates/eliot-engine/src/skill.rs".to_owned(),
        content_hash: Some("hash-skill-lifecycle-skill".to_owned()),
        line_start: Some(1),
        line_end: Some(120),
        excerpt: "pub struct SkillActivationGate".to_owned(),
        source: CodeEvidenceSource::Rg,
    };
    CodeCortexReport {
        project: "eliot-governor".to_owned(),
        task: "skill-lifecycle".to_owned(),
        goal: "skill lifecycle skill lifecycle".to_owned(),
        generated_at: time::OffsetDateTime::now_utc(),
        repo_root: repo_root().display().to_string(),
        git_head: Some("skill-lifecycle-head".to_owned()),
        dirty: false,
        scope_binding: eliot_types::CodeCortexScopeBinding::default(),
        tracked_files: vec![file.clone()],
        workspace_members: vec!["eliot-engine".to_owned()],
        crates: vec!["eliot-engine".to_owned()],
        targets: vec!["eliot-engine".to_owned()],
        file_evidence: vec![file],
        symbol_evidence: vec![SymbolEvidence {
            name: "SkillActivationGate".to_owned(),
            kind: "struct".to_owned(),
            path: "crates/eliot-engine/src/skill.rs".to_owned(),
            line: Some(308),
            source: CodeEvidenceSource::Rg,
        }],
        diagnostic_evidence: vec![DiagnosticEvidence {
            source: CodeEvidenceSource::Diagnostics,
            status: "clean".to_owned(),
            path: Some("crates/eliot-engine/src/skill.rs".to_owned()),
            line: None,
            severity: "info".to_owned(),
            message: "cargo check passed".to_owned(),
        }],
        verifier_evidence: vec![VerifierEvidence {
            name: "just verify".to_owned(),
            command: "just verify".to_owned(),
            status: "passed".to_owned(),
            summary: "exit code 0".to_owned(),
            source: CodeEvidenceSource::Diagnostics,
        }],
        blast_radius: BlastRadiusView {
            files: vec!["crates/eliot-engine/src/skill.rs".to_owned()],
            crates: vec!["eliot-engine".to_owned()],
            reasons: vec!["Skill lifecycle service coverage".to_owned()],
        },
        invariant_cards: vec![InvariantCard {
            name: "skills_do_not_bypass_gates".to_owned(),
            status: "enforced".to_owned(),
            evidence: "ActionLease and CompletionGate check skill refs".to_owned(),
        }],
        evidence_sources: vec![CodeEvidenceSource::Rg, CodeEvidenceSource::Diagnostics],
        adapter_notes: Vec::new(),
        memory_receipt: None,
        final_status: "ready".to_owned(),
    }
}

async fn lock_tests() -> TestResult<TestLock> {
    let lock_path = repo_root().join("target/eliot-governor-shared-db-test.lock");
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let started = Instant::now();
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_file) => return Ok(TestLock { lock_path }),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                if started.elapsed() > Duration::from_secs(600) {
                    return Err("timed out waiting for shared DB test lock".into());
                }
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

struct TestLock {
    lock_path: PathBuf,
}

impl Drop for TestLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
}

impl Harness {
    async fn new(name: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "eliot-skill-lifecycle-{name}-{}",
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
    if let Some(root) = manifest_dir.parent().and_then(Path::parent) {
        root.to_path_buf()
    } else {
        manifest_dir.to_path_buf()
    }
}
