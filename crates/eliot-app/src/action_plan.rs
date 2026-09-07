use anyhow::{Context, Result};
use eliot_engine::{
    ActionLeaseEvaluation, ActionLeaseService, CognitiveGate, ReadService,
    UnderstandingProofValidator, WriteAdmissionService, WriterActor, WriterConfig,
    codecortex_report_ref, default_work_scope,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    ActionKind, ActionLeaseRecord, ActionRequest, AgentId, AgentRole, AgentSessionId, ChangePlan,
    CodeCortexReport, CognitiveGateRequest, ControlWalConfig, FileChangeIntent, FileChangeKind,
    LeaseDecision, OperationStatus, SymbolChangeIntent, TaskId, UnderstandingProof,
    VerifierCommandKind, VerifierPlan, VerifierRequirement, WorkItemId, WorkLease,
    WorkLeaseDecision, WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState,
};
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::process::Command as ProcessCommand;
use std::str::FromStr;
use time::OffsetDateTime;

pub struct ActionPlanInput {
    pub project_label: String,
    pub task_label: String,
    pub goal: String,
    pub requested_action_kind: ActionKind,
    pub change_plan: Option<ChangePlan>,
    pub verifier_plan: Option<VerifierPlan>,
}

pub struct ActionLeaseArtifacts {
    pub record: ActionLeaseRecord,
}

pub async fn create_action_lease_artifacts(
    root: &Path,
    store: CanonicalStore,
    control_wal: &ControlWalConfig,
    input: ActionPlanInput,
) -> Result<ActionLeaseArtifacts> {
    store.migrate_schema().await?;
    let report = latest_codecortex_report(root)?.context("no latest CodeCortex report found")?;
    let report_ref = codecortex_report_ref(&report);
    let project_id = parse_project_or_new(&input.project_label);
    let task_id = parse_task_or_new(&input.task_label);
    let agent_id = AgentId::new_v7();
    let default_file =
        action_file_ref(&report).context("CodeCortex report has no file evidence")?;
    let change_plan = input.change_plan.unwrap_or_else(|| {
        default_change_plan(
            &default_file,
            &input.goal,
            change_kind_for_action(input.requested_action_kind),
        )
    });
    let verifier_plan = input
        .verifier_plan
        .unwrap_or_else(|| default_verifier_plan(&default_file));
    let proof = action_understanding_proof(
        project_id,
        task_id,
        &input.goal,
        &report_ref,
        &change_plan,
        &verifier_plan,
    );
    let receipt = UnderstandingProofValidator::new(ReadService::new(store.clone()))
        .validate_with_codecortex(&proof, std::slice::from_ref(&report))
        .await?;
    let gate_decision = CognitiveGate::decide(&CognitiveGateRequest {
        receipt: receipt.clone(),
        requested_action: requested_action_text(input.requested_action_kind),
    });
    let request = ActionRequest {
        request_id: eliot_types::ActionRequestId::new_v7(),
        project_id,
        task_id,
        agent_id,
        goal: input.goal,
        requested_action_kind: input.requested_action_kind,
        understanding_proof_ref: format!("understanding_proof:{}", receipt.task_id),
        cognitive_gate_ref: format!("cognitive_gate:{:?}", gate_decision.decision),
        codecortex_report_refs: vec![report_ref],
        skill_refs: Vec::new(),
        skill_activation_decisions: Vec::new(),
        proposed_change_plan: change_plan,
        proposed_verifier_plan: verifier_plan,
        created_at: OffsetDateTime::now_utc(),
    };
    let service = ActionLeaseService;
    let current_git_head = current_git_head(&report);
    let work_lease = action_work_lease(&request, &report);
    let lease = service.evaluate(&ActionLeaseEvaluation {
        request: &request,
        understanding_proof: Some(&proof),
        understanding_receipt: &receipt,
        cognitive_gate_decision: &gate_decision,
        codecortex_reports: std::slice::from_ref(&report),
        current_git_head: current_git_head.as_deref(),
        work_lease: Some(&work_lease),
        // An unreadable or malformed incident file must deny the lease, not
        // grant it. Sixteen of the seventeen `lockdown_active` call sites in
        // this crate already propagate; this one swallowed the error and
        // reported "no lockdown", which is fail-open on an `A0.3` boundary.
        incident_lockdown_active: eliot_engine::IncidentService::new(root).lockdown_active()?,
    });
    let wal = ControlWal::open(control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    let record = service.write_lease(&handle, &admission, lease).await?;
    drop(handle);
    actor_task.await?;
    Ok(ActionLeaseArtifacts { record })
}

pub fn latest_codecortex_report(root: &Path) -> Result<Option<CodeCortexReport>> {
    let path = root.join("reports").join("codecortex").join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

pub fn write_action_lease_report(
    root: &Path,
    project: &str,
    task: &str,
    goal: &str,
    record: &ActionLeaseRecord,
) -> Result<()> {
    let report = action_lease_report_value(project, task, goal, record);
    write_report_pair(
        &root
            .join("reports")
            .join("action-lease")
            .join("latest.json"),
        &root.join("reports").join("action-lease").join("latest.md"),
        &report,
        &action_lease_markdown(&report),
    )
}

pub fn latest_action_lease_report(root: &Path) -> Result<Option<Value>> {
    let path = root
        .join("reports")
        .join("action-lease")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

pub fn action_lease_report_value(
    project: &str,
    task: &str,
    goal: &str,
    record: &ActionLeaseRecord,
) -> Value {
    json!({
        "component": "action_lease",
        "project": project,
        "task": task,
        "goal": goal,
        "record": record,
        "operation_status": if record.lease.decision == LeaseDecision::Deny {
            OperationStatus::Blocked
        } else {
            OperationStatus::OperationCompleted
        }
    })
}

pub fn action_file_ref(report: &CodeCortexReport) -> Option<String> {
    let preferred = [
        "crates/eliot-app/src/mcp_stdio.rs",
        "crates/eliot-engine/src/context.rs",
        "crates/eliot-app/src/commands.rs",
        "crates/eliot-types/src/memory.rs",
    ];
    report
        .file_evidence
        .iter()
        .chain(report.tracked_files.iter())
        .find(|evidence| preferred.contains(&evidence.path.as_str()))
        .or_else(|| report.file_evidence.first())
        .or_else(|| report.tracked_files.first())
        .map(|evidence| evidence.path.clone())
}

pub fn default_change_plan(path: &str, goal: &str, kind: FileChangeKind) -> ChangePlan {
    ChangePlan {
        summary: format!("Bounded E1 planning surface for: {goal}"),
        files: vec![FileChangeIntent {
            path: path.to_owned(),
            reason: "CodeCortex grounded this file as part of the planning evidence".to_owned(),
            expected_change_kind: kind,
            code_evidence_refs: vec![format!("file:{path}")],
        }],
        symbols: Vec::<SymbolChangeIntent>::new(),
        invariants_to_preserve: vec![
            "no patch execution in E1".to_owned(),
            "all ActionLease reports are written through WriterActor".to_owned(),
            "no raw shell/git/rg/ast-grep/file tools are exposed through MCP".to_owned(),
        ],
        risks: vec![
            "planning report can become stale if git_head changes before execution".to_owned(),
        ],
        rollback_plan: Some("Discard the plan; E1 grants no patch or action permission".to_owned()),
    }
}

pub fn default_verifier_plan(path: &str) -> VerifierPlan {
    VerifierPlan {
        required: vec![
            VerifierRequirement {
                name: "cargo-check".to_owned(),
                command_kind: VerifierCommandKind::CargoCheck,
                command_display: "cargo check --workspace --all-targets --all-features".to_owned(),
                scope: vec![path.to_owned()],
                required_for_done: true,
                expected_signal: "workspace type-checks".to_owned(),
            },
            VerifierRequirement {
                name: "workspace-tests".to_owned(),
                command_kind: VerifierCommandKind::DomainVerifier,
                command_display: "cargo test --workspace".to_owned(),
                scope: vec![path.to_owned()],
                required_for_done: true,
                expected_signal: "workspace tests pass".to_owned(),
            },
        ],
        optional: vec![VerifierRequirement {
            name: "just-verify".to_owned(),
            command_kind: VerifierCommandKind::DomainVerifier,
            command_display: "just verify".to_owned(),
            scope: vec![path.to_owned()],
            required_for_done: false,
            expected_signal: "full workspace verifier passes".to_owned(),
        }],
        acceptance_items: vec![
            "ActionLease decision is plan-only or read-only".to_owned(),
            "ActionLease write receipt is present".to_owned(),
            "No patch execution permission is granted".to_owned(),
        ],
    }
}

pub fn write_report_pair(
    json_path: &Path,
    markdown_path: &Path,
    value: &Value,
    markdown: &str,
) -> Result<()> {
    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut json_file = std::fs::File::create(json_path)?;
    serde_json::to_writer_pretty(&mut json_file, value)?;
    writeln!(json_file)?;
    std::fs::write(markdown_path, markdown)?;
    Ok(())
}

fn action_understanding_proof(
    project_id: eliot_types::ProjectId,
    task_id: TaskId,
    goal: &str,
    report_ref: &str,
    change_plan: &ChangePlan,
    verifier_plan: &VerifierPlan,
) -> UnderstandingProof {
    let (files_to_change, files_to_inspect): (Vec<_>, Vec<_>) = change_plan
        .files
        .iter()
        .map(|file| file.path.clone())
        .partition(|path| {
            change_plan.files.iter().any(|file| {
                file.path == *path && file.expected_change_kind != FileChangeKind::ReadOnly
            })
        });
    UnderstandingProof {
        task_id: task_id.to_string(),
        project_id,
        goal: goal.to_owned(),
        code_task: true,
        current_truth_refs: Vec::new(),
        evidence_refs: Vec::new(),
        codecortex_report_refs: vec![report_ref.to_owned()],
        files_to_change,
        files_to_inspect,
        causal_bridge: "ActionLease planning is grounded by CodeCortex evidence".to_owned(),
        causal_bridge_from_goal_to_code: change_plan.summary.clone(),
        invariants: change_plan.invariants_to_preserve.clone(),
        negative_memory_checked: true,
        unknowns: change_plan.risks.clone(),
        planned_action: "prepare bounded action plan only".to_owned(),
        expected_verifiers: verifier_plan
            .required
            .iter()
            .map(|verifier| verifier.command_display.clone())
            .collect(),
        blast_radius_acknowledged: true,
        skill_refs: Vec::new(),
        skill_application_rationales: Vec::new(),
        skill_anti_scope_acknowledgements: Vec::new(),
        skill_required_inputs: Vec::new(),
        skill_verifier_plan_refs: Vec::new(),
        risk_level: "low".to_owned(),
    }
}

fn action_lease_markdown(report: &Value) -> String {
    let mut output = String::from("# ActionLease Report\n\n");
    for key in ["project", "task", "goal", "operation_status"] {
        let value = report.get(key).and_then(Value::as_str).unwrap_or("unknown");
        let _ = writeln!(output, "- {key}: `{value}`");
    }
    if let Some(lease) = report.get("record").and_then(|record| record.get("lease")) {
        let decision = lease
            .get("decision")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let status = lease
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let _ = writeln!(output, "- decision: `{decision}`");
        let _ = writeln!(output, "- status: `{status}`");
        if let Some(reasons) = lease.get("denial_reasons").and_then(Value::as_array) {
            let _ = writeln!(output, "- denial_reasons: `{}`", reasons.len());
        }
    }
    if let Some(receipt) = report
        .get("record")
        .and_then(|record| record.get("write_receipt"))
        .and_then(|receipt| receipt.get("write_id"))
        .and_then(Value::as_str)
    {
        let _ = writeln!(output, "- write_receipt: `{receipt}`");
    }
    output
}

fn parse_project_or_new(value: &str) -> eliot_types::ProjectId {
    eliot_types::ProjectId::from_str(value).unwrap_or_else(|_| eliot_types::ProjectId::new_v7())
}

fn parse_task_or_new(value: &str) -> TaskId {
    TaskId::from_str(value).unwrap_or_else(|_| TaskId::new_v7())
}

fn change_kind_for_action(kind: ActionKind) -> FileChangeKind {
    match kind {
        ActionKind::ReadOnlyInspect | ActionKind::ProbePlan => FileChangeKind::ReadOnly,
        ActionKind::ChangePlanOnly
        | ActionKind::PatchExecution
        | ActionKind::ShellExecution
        | ActionKind::ExternalAgentDelegation => FileChangeKind::Modify,
    }
}

fn requested_action_text(kind: ActionKind) -> String {
    match kind {
        ActionKind::ReadOnlyInspect => "read only inspect grounded code".to_owned(),
        ActionKind::ProbePlan => "probe grounded code plan".to_owned(),
        ActionKind::ChangePlanOnly => "prepare bounded code change plan".to_owned(),
        ActionKind::PatchExecution => "execute code patch".to_owned(),
        ActionKind::ShellExecution => "run raw shell command".to_owned(),
        ActionKind::ExternalAgentDelegation => "delegate to external agent".to_owned(),
    }
}

fn current_git_head(report: &CodeCortexReport) -> Option<String> {
    let output = ProcessCommand::new("git")
        .arg("-C")
        .arg(&report.repo_root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;
    if !output.status.success() {
        return report.git_head.clone();
    }
    let head = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if head.is_empty() {
        report.git_head.clone()
    } else {
        Some(head)
    }
}

fn action_work_lease(request: &ActionRequest, report: &CodeCortexReport) -> WorkLease {
    let now = OffsetDateTime::now_utc();
    let work_lease_id = WorkLeaseId::new_v7();
    let read_set = request
        .proposed_change_plan
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let write_set = request
        .proposed_change_plan
        .files
        .iter()
        .filter(|file| file.expected_change_kind != FileChangeKind::ReadOnly)
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let verifier_set = request
        .proposed_verifier_plan
        .required
        .iter()
        .map(|verifier| verifier.command_display.clone())
        .collect::<Vec<_>>();
    WorkLease {
        work_lease_id,
        work_item_id: WorkItemId::new_v7(),
        agent_session_id: AgentSessionId::new_v7(),
        agent_id: request.agent_id,
        project_id: request.project_id,
        task_id: request.task_id,
        role: AgentRole::Implementer,
        state: WorkLeaseState::Granted,
        epoch: 0,
        scope: default_work_scope(report.repo_root.clone(), read_set, write_set, verifier_set),
        decision: WorkLeaseDecision {
            kind: WorkLeaseDecisionKind::Granted,
            reason: WorkLeaseDecisionReason::NoConflict,
            message: "bounded ActionLease planning work scope".to_owned(),
            work_lease_id: Some(work_lease_id),
            conflicting_lease_ids: Vec::new(),
            expires_at: Some(now + time::Duration::hours(1)),
        },
        conflict_refs: Vec::new(),
        granted_at: now,
        expires_at: now + time::Duration::hours(1),
        renewed_at: None,
        released_at: None,
        revoked_at: None,
        write_receipt: None,
    }
}
