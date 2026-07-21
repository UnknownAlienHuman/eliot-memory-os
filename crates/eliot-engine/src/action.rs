use crate::{
    EngineError, WriteAdmissionService, WriterHandle, codecortex_report_ref,
    guard_work_lease_for_files, work::WorkLeaseGuardError,
};
use eliot_types::{
    ActionKind, ActionLease, ActionLeaseId, ActionLeaseRecord, ActionRequest, ActionScope,
    CodeCortexReport, CognitiveGateDecision, CognitiveGateOutcome, CognitiveGateReason,
    CommandContext, FileChangeKind, LeaseDecision, LeaseDenyReason, LeaseStatus, LifecycleStatus,
    SemanticCommand, SkillActivationDecision, TaintClass, ToolObservationRecordCommand,
    UnderstandingProof, UnderstandingProofReceipt, Visibility, WorkLease, WriteId, WriteReceiptRef,
};
use std::collections::{BTreeSet, HashSet};
use time::{Duration, OffsetDateTime};

const MAX_E1_FILES: usize = 12;
const MAX_E1_VERIFIERS: usize = 12;

#[derive(Clone, Copy, Debug, Default)]
pub struct ActionLeaseService;

pub struct ActionLeaseEvaluation<'a> {
    pub request: &'a ActionRequest,
    pub understanding_proof: Option<&'a UnderstandingProof>,
    pub understanding_receipt: &'a UnderstandingProofReceipt,
    pub cognitive_gate_decision: &'a CognitiveGateDecision,
    pub codecortex_reports: &'a [CodeCortexReport],
    pub current_git_head: Option<&'a str>,
    pub work_lease: Option<&'a WorkLease>,
    pub incident_lockdown_active: bool,
}

impl ActionLeaseService {
    pub fn evaluate(&self, input: &ActionLeaseEvaluation<'_>) -> ActionLease {
        let mut denial_reasons = BTreeSet::new();
        validate_required_refs(input, &mut denial_reasons);
        validate_gate(input, &mut denial_reasons);
        validate_codecortex(input, &mut denial_reasons);
        validate_change_plan(input, &mut denial_reasons);
        validate_verifier_plan(input, &mut denial_reasons);
        validate_work_lease(input, &mut denial_reasons);
        validate_action_kind(input.request.requested_action_kind, &mut denial_reasons);
        validate_incident_lockdown(input, &mut denial_reasons);
        validate_skill_activation(input, &mut denial_reasons);

        let denial_reasons: Vec<_> = denial_reasons.into_iter().collect();
        let (decision, status) =
            lease_decision(input.request.requested_action_kind, &denial_reasons);
        let allowed_scope = if denial_reasons.is_empty() {
            Some(action_scope(input))
        } else {
            None
        };

        ActionLease {
            lease_id: ActionLeaseId::new_v7(),
            request_id: input.request.request_id,
            project_id: input.request.project_id,
            task_id: input.request.task_id,
            agent_id: input.request.agent_id,
            decision,
            status,
            allowed_scope,
            change_plan: Some(input.request.proposed_change_plan.clone()),
            verifier_plan: Some(input.request.proposed_verifier_plan.clone()),
            skill_refs: input.request.skill_refs.clone(),
            denial_reasons,
            expires_at: lease_expiry(status),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub async fn write_lease(
        &self,
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        lease: ActionLease,
    ) -> Result<ActionLeaseRecord, EngineError> {
        let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
            context: CommandContext {
                write_id: WriteId::new_v7(),
                agent_id: lease.agent_id,
                session_id: None,
                project_id: lease.project_id,
                task_id: Some(lease.task_id),
                scope: "action-lease".to_owned(),
                authority: "eliot-action-lease-service".to_owned(),
                visibility: Visibility::Internal,
                taint: TaintClass::LocalVerified,
                lifecycle_status: LifecycleStatus::Active,
            },
            tool_name: "eliot_action_lease".to_owned(),
            observation: format!(
                "ActionLease {} decision {:?} status {:?}",
                lease.lease_id, lease.decision, lease.status
            ),
            payload: serde_json::json!({ "lease": lease }),
        });
        let receipt = writer.submit(admission.admit(&command)?).await?;
        let write_receipt = Some(WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        });
        let lease = match command {
            SemanticCommand::ToolObservationRecord(record) => {
                serde_json::from_value(record.payload["lease"].clone())?
            }
            _ => unreachable!("command is constructed as ToolObservationRecord"),
        };
        Ok(ActionLeaseRecord {
            lease,
            write_receipt,
        })
    }
}

fn validate_required_refs(
    input: &ActionLeaseEvaluation<'_>,
    reasons: &mut BTreeSet<LeaseDenyReason>,
) {
    if input.understanding_proof.is_none()
        || input.request.understanding_proof_ref.trim().is_empty()
    {
        reasons.insert(LeaseDenyReason::MissingUnderstandingProof);
    }
    if input.request.cognitive_gate_ref.trim().is_empty() {
        reasons.insert(LeaseDenyReason::MissingCognitiveGateDecision);
    }
    if input
        .understanding_proof
        .is_none_or(|proof| proof.causal_bridge_from_goal_to_code.trim().is_empty())
    {
        reasons.insert(LeaseDenyReason::MissingCausalBridge);
    }
    if input
        .understanding_receipt
        .validation_errors
        .contains(&CognitiveGateReason::WeakClaimUsedAsTruth)
        || input
            .cognitive_gate_decision
            .reasons
            .contains(&CognitiveGateReason::WeakClaimUsedAsTruth)
    {
        reasons.insert(LeaseDenyReason::WeakClaimUsedAsTruth);
    }
}

fn validate_gate(input: &ActionLeaseEvaluation<'_>, reasons: &mut BTreeSet<LeaseDenyReason>) {
    let gate_allows = matches!(
        input.cognitive_gate_decision.decision,
        CognitiveGateOutcome::Allow | CognitiveGateOutcome::AllowReadOnly
    ) || (input.request.requested_action_kind == ActionKind::ProbePlan
        && input.cognitive_gate_decision.decision == CognitiveGateOutcome::RequireProbe);
    if !gate_allows {
        reasons.insert(LeaseDenyReason::CognitiveGateNotAllowingAction);
    }
    if input.cognitive_gate_decision.task_id != input.understanding_receipt.task_id
        || input.cognitive_gate_decision.project_id != input.understanding_receipt.project_id
    {
        reasons.insert(LeaseDenyReason::MissingCognitiveGateDecision);
    }
}

fn validate_codecortex(input: &ActionLeaseEvaluation<'_>, reasons: &mut BTreeSet<LeaseDenyReason>) {
    if input.request.codecortex_report_refs.is_empty()
        || input
            .understanding_receipt
            .codecortex_report_refs
            .is_empty()
        || input.codecortex_reports.is_empty()
    {
        reasons.insert(LeaseDenyReason::MissingCodeCortexReport);
        return;
    }

    let Some(report) = input.codecortex_reports.last() else {
        reasons.insert(LeaseDenyReason::MissingCodeCortexReport);
        return;
    };
    let expected_ref = codecortex_report_ref(report);
    if !input
        .request
        .codecortex_report_refs
        .iter()
        .any(|reference| reference == &expected_ref)
        || !input
            .understanding_receipt
            .codecortex_report_refs
            .iter()
            .any(|reference| reference == &expected_ref)
    {
        reasons.insert(LeaseDenyReason::StaleGitHead);
    }
    if let (Some(current), Some(report_head)) = (input.current_git_head, report.git_head.as_deref())
        && current != report_head
    {
        reasons.insert(LeaseDenyReason::StaleGitHead);
    }

    let known_files = known_report_files(report);
    for file in &input.request.proposed_change_plan.files {
        if !known_files.contains(&normalize_path(&file.path)) {
            reasons.insert(LeaseDenyReason::FileOutsideCodeCortexReport);
        }
    }
    let known_symbols = report
        .symbol_evidence
        .iter()
        .map(|symbol| symbol.name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    for symbol in &input.request.proposed_change_plan.symbols {
        if !known_symbols.contains(&symbol.symbol.to_ascii_lowercase()) {
            reasons.insert(LeaseDenyReason::SymbolOutsideCodeCortexReport);
        }
    }
}

fn validate_change_plan(
    input: &ActionLeaseEvaluation<'_>,
    reasons: &mut BTreeSet<LeaseDenyReason>,
) {
    let plan = &input.request.proposed_change_plan;
    if plan.files.is_empty() || plan.summary.trim().is_empty() {
        reasons.insert(LeaseDenyReason::UnboundedFileScope);
    }
    if plan.files.len() > MAX_E1_FILES {
        reasons.insert(LeaseDenyReason::ScopeTooLarge);
    }
    for file in &plan.files {
        if file.path.trim().is_empty()
            || file.reason.trim().is_empty()
            || file.code_evidence_refs.is_empty()
        {
            reasons.insert(LeaseDenyReason::UnboundedFileScope);
        }
        if input.request.requested_action_kind == ActionKind::ReadOnlyInspect
            && file.expected_change_kind != FileChangeKind::ReadOnly
        {
            reasons.insert(LeaseDenyReason::UnboundedFileScope);
        }
    }
}

fn validate_verifier_plan(
    input: &ActionLeaseEvaluation<'_>,
    reasons: &mut BTreeSet<LeaseDenyReason>,
) {
    let plan = &input.request.proposed_verifier_plan;
    if plan.required.is_empty() || plan.acceptance_items.is_empty() {
        reasons.insert(LeaseDenyReason::MissingVerifierPlan);
    }
    if plan.required.len().saturating_add(plan.optional.len()) > MAX_E1_VERIFIERS {
        reasons.insert(LeaseDenyReason::ScopeTooLarge);
    }
    for verifier in plan.required.iter().chain(plan.optional.iter()) {
        if verifier.name.trim().is_empty()
            || verifier.command_display.trim().is_empty()
            || verifier.expected_signal.trim().is_empty()
        {
            reasons.insert(LeaseDenyReason::MissingVerifierPlan);
        }
    }
}

fn validate_work_lease(input: &ActionLeaseEvaluation<'_>, reasons: &mut BTreeSet<LeaseDenyReason>) {
    if !requires_work_lease(input.request) {
        return;
    }
    let files = work_lease_files(input.request);
    match guard_work_lease_for_files(
        input.work_lease,
        input.request.project_id,
        input.request.task_id,
        input.request.agent_id,
        &files,
    ) {
        Ok(()) => {}
        Err(WorkLeaseGuardError::Missing) => {
            reasons.insert(LeaseDenyReason::MissingWorkLease);
        }
        Err(WorkLeaseGuardError::Inactive) => {
            reasons.insert(LeaseDenyReason::WorkLeaseInactive);
        }
        Err(WorkLeaseGuardError::Mismatch) => {
            reasons.insert(LeaseDenyReason::WorkLeaseMismatch);
        }
        Err(WorkLeaseGuardError::FileOutsideScope) => {
            reasons.insert(LeaseDenyReason::FileOutsideWorkLease);
        }
    }
}

fn validate_action_kind(kind: ActionKind, reasons: &mut BTreeSet<LeaseDenyReason>) {
    match kind {
        ActionKind::ReadOnlyInspect | ActionKind::ProbePlan | ActionKind::ChangePlanOnly => {}
        ActionKind::PatchExecution => {
            reasons.insert(LeaseDenyReason::PatchExecutionNotAllowedInE1);
        }
        ActionKind::ShellExecution => {
            reasons.insert(LeaseDenyReason::RawShellRequested);
        }
        ActionKind::ExternalAgentDelegation => {
            reasons.insert(LeaseDenyReason::ExternalAgentNotAllowedInE1);
        }
    }
}

fn validate_incident_lockdown(
    input: &ActionLeaseEvaluation<'_>,
    reasons: &mut BTreeSet<LeaseDenyReason>,
) {
    if input.incident_lockdown_active {
        reasons.insert(LeaseDenyReason::IncidentLockdown);
    }
}

fn validate_skill_activation(
    input: &ActionLeaseEvaluation<'_>,
    reasons: &mut BTreeSet<LeaseDenyReason>,
) {
    if input.request.skill_refs.is_empty() {
        return;
    }
    let Some(proof) = input.understanding_proof else {
        reasons.insert(LeaseDenyReason::SkillWouldBypassGate);
        return;
    };
    let proof_refs = proof.skill_refs.iter().copied().collect::<HashSet<_>>();
    if input
        .request
        .skill_refs
        .iter()
        .any(|skill_ref| !proof_refs.contains(skill_ref))
    {
        reasons.insert(LeaseDenyReason::SkillWouldBypassGate);
    }
    let allowed_refs = input
        .request
        .skill_activation_decisions
        .iter()
        .filter(|record| record.decision == SkillActivationDecision::Allow)
        .map(|record| record.skill_ref)
        .collect::<HashSet<_>>();
    if input
        .request
        .skill_refs
        .iter()
        .any(|skill_ref| !allowed_refs.contains(skill_ref))
    {
        reasons.insert(LeaseDenyReason::SkillActivationNotAllowed);
    }
}

fn requires_work_lease(request: &ActionRequest) -> bool {
    matches!(
        request.requested_action_kind,
        ActionKind::ChangePlanOnly
            | ActionKind::PatchExecution
            | ActionKind::ShellExecution
            | ActionKind::ExternalAgentDelegation
    ) || request
        .proposed_change_plan
        .files
        .iter()
        .any(|file| file.expected_change_kind != FileChangeKind::ReadOnly)
}

fn work_lease_files(request: &ActionRequest) -> Vec<String> {
    request
        .proposed_change_plan
        .files
        .iter()
        .filter(|file| file.expected_change_kind != FileChangeKind::ReadOnly)
        .map(|file| file.path.clone())
        .collect()
}

fn lease_decision(kind: ActionKind, reasons: &[LeaseDenyReason]) -> (LeaseDecision, LeaseStatus) {
    if !reasons.is_empty() {
        return (LeaseDecision::Deny, LeaseStatus::Denied);
    }
    match kind {
        ActionKind::ReadOnlyInspect => (LeaseDecision::AllowReadOnly, LeaseStatus::ReadOnly),
        ActionKind::ProbePlan => (LeaseDecision::AllowProbePlan, LeaseStatus::ProbeOnly),
        ActionKind::ChangePlanOnly => {
            (LeaseDecision::AllowChangePlanOnly, LeaseStatus::PlannedOnly)
        }
        ActionKind::PatchExecution
        | ActionKind::ShellExecution
        | ActionKind::ExternalAgentDelegation => (LeaseDecision::Deny, LeaseStatus::Denied),
    }
}

fn action_scope(input: &ActionLeaseEvaluation<'_>) -> ActionScope {
    let report = input.codecortex_reports.last();
    ActionScope {
        repo_root: report.map_or_else(String::new, |report| report.repo_root.clone()),
        git_head: report.and_then(|report| report.git_head.clone()),
        allowed_files: input
            .request
            .proposed_change_plan
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
        allowed_symbols: input
            .request
            .proposed_change_plan
            .symbols
            .iter()
            .map(|symbol| symbol.symbol.clone())
            .collect(),
        forbidden_files: Vec::new(),
        max_files: MAX_E1_FILES,
        max_diff_bytes: 0,
        max_runtime_seconds: 0,
    }
}

fn lease_expiry(status: LeaseStatus) -> Option<OffsetDateTime> {
    match status {
        LeaseStatus::Denied
        | LeaseStatus::Expired
        | LeaseStatus::Revoked
        | LeaseStatus::Superseded => None,
        LeaseStatus::PlannedOnly
        | LeaseStatus::ApprovedForExecution
        | LeaseStatus::ReadOnly
        | LeaseStatus::ProbeOnly => Some(OffsetDateTime::now_utc() + Duration::hours(1)),
    }
}

fn known_report_files(report: &CodeCortexReport) -> HashSet<String> {
    report
        .tracked_files
        .iter()
        .chain(report.file_evidence.iter())
        .map(|evidence| normalize_path(&evidence.path))
        .chain(
            report
                .symbol_evidence
                .iter()
                .map(|evidence| normalize_path(&evidence.path)),
        )
        .chain(
            report
                .blast_radius
                .files
                .iter()
                .map(|path| normalize_path(path)),
        )
        .collect()
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .to_ascii_lowercase()
}
