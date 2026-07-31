#![allow(
    clippy::expect_used,
    clippy::format_collect,
    clippy::print_stdout,
    clippy::too_many_lines,
    clippy::struct_excessive_bools
)]

use crate::{
    host_runtime::supervised_process::{
        ChildCriticality, ProcessRestartPolicy, RestartStrategy, SupervisedChildKind,
        SupervisedProcessSpec, run_supervised_process_blocking,
    },
    runtime_instance::{atomic_write_bytes, atomic_write_json},
};
use anyhow::{Context, Result, bail};
use eliot_store::CanonicalStore;
use eliot_types::{
    AgentHostId, AgentSessionId, EpistemicStatus, FetchAtomsL2Request, HostLaunchScope,
    MemoryInfluenceClass, MemoryInfluenceTrace, ObservabilityKind, ObservabilityWriteStatus,
    ProjectId, ReadConsistencyMode, SemanticCommandKind, SessionId, TaskId,
    UL_CROSS_AGENT_CONFIRMATION_TOKEN, UlCrossAgentContaminationReceipt, UlCrossAgentDirection,
    UlCrossAgentDirectionEvidence, UlCrossAgentMemoryMode, UlCrossAgentPlan,
    UlCrossAgentReaderOutput, UlCrossAgentReport, UlCrossAgentRole, UlCrossAgentSuite,
    UlCrossAgentWriterOutput, UlReasoningRequest, UlReasoningRoute, WriteId, WriteStatus,
    scan_ul_cross_agent_reader_inputs,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::windows::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

const READER_PROMPT_ALPHA: &str = "Open or inspect src/relay_alpha.rs. Determine whether ELIOT contains a previous lesson specifically bound to this file. Return the required JSON. Do not guess an opaque marker.";
const READER_PROMPT_BETA: &str = "Open or inspect src/relay_beta.rs. Determine whether ELIOT contains a previous lesson specifically bound to this file. Return the required JSON. Do not guess an opaque marker.";
const CLAUDE_UL_MODEL: &str = "opus";
const ANTIGRAVITY_UL_MODEL: &str = "claude-opus-4-6-thinking";
const CLAUDE_SMOKE_MODEL: &str = "sonnet";
const ANTIGRAVITY_SMOKE_MODEL: &str = "gemini-3.6-flash-high";
const CLAUDE_WRITER_REFUSAL_NOTE: &str = "Claude Code previously safety-refused the legacy imperative UL-11 writer prompt before tool_use. Under explicit operator authorization, the writer prompt now states that this is a synthetic candidate-only certification write. Preserve this note as a provider-compatibility regression marker.";
const ANTIGRAVITY_WRITER_NON_JSON_NOTE: &str = "Antigravity Opus 4.6 previously exited successfully before tool_use with bounded non-JSON stdout. Raw provider prose was intentionally not retained, so this is an unclassified contract failure and must not be relabeled as a safety refusal.";

#[derive(Clone, Debug, Serialize)]
struct CrossAgentDoctor {
    schema_version: &'static str,
    ready: bool,
    source_root: PathBuf,
    suite_valid: bool,
    output_contract_valid: bool,
    governor_executable: PathBuf,
    governor_outside_onedrive: bool,
    claude: Value,
    antigravity: Value,
    daemon: Value,
}

#[derive(Clone, Debug, Serialize)]
struct CallArchive {
    case_id: String,
    host: AgentHostId,
    role: UlCrossAgentRole,
    task_id: String,
    planned_session_id: String,
    mcp_profile: String,
    requested_model: String,
    prompt_sha256: String,
    provider_executable_hash: String,
    integration_bundle_hash: String,
    mcp_preflight: Option<ScopedMcpPreflightEvidence>,
    contamination: Option<UlCrossAgentContaminationReceipt>,
    provider_dispatched: bool,
    outcome_unknown: bool,
    revision_before: Option<u64>,
    revision_after: Option<u64>,
    structured_output_sha256: Option<String>,
    #[serde(skip_serializing)]
    structured_output: Option<Value>,
    canonical_verification: CanonicalCallVerification,
    terminal_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ScopedMcpPreflightEvidence {
    host: AgentHostId,
    profile: String,
    agent_session_id: String,
    memory_scope: &'static str,
    project_id: String,
    task_id: String,
    role_lease_id: String,
    tool_names: Vec<String>,
    current_state_revision: u64,
}

#[derive(Clone, Debug, Serialize)]
struct ProviderMcpSmokeEvidence {
    schema_version: &'static str,
    smoke_id: String,
    host: AgentHostId,
    model: String,
    model_selection_reason: &'static str,
    project_id: ProjectId,
    task_id: TaskId,
    agent_session_id: AgentSessionId,
    role_lease_id: String,
    repo: PathBuf,
    mcp_preflight: ScopedMcpPreflightEvidence,
    provider_session_client_name: String,
    provider_session_transport: String,
    provider_executable_hash: String,
    integration_bundle_hash: String,
    structured_output: Value,
    structured_output_sha256: String,
    provider_dispatched: bool,
    controller_substitute_call: bool,
    passed: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
struct CanonicalCallVerification {
    candidate_handle: Option<String>,
    candidate_write_id: Option<String>,
    candidate_exact: bool,
    candidate_session_exact: bool,
    candidate_stayed_candidate_only: bool,
    injection_receipt_ids: Vec<String>,
    treatment_received_exact_handle: bool,
    influence_record_ids: Vec<String>,
    influence_receipt_exact: bool,
    memory_free_zero_injections: bool,
}

#[derive(Clone, Debug, Serialize)]
struct KnownProviderIssue {
    provider: &'static str,
    category: &'static str,
    status: &'static str,
    note: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct RunEvidence {
    schema_version: &'static str,
    run_id: String,
    project_id: ProjectId,
    repo: PathBuf,
    plan: UlCrossAgentPlan,
    provider_call_count: u8,
    calls: Vec<CallArchive>,
    terminal_errors: Vec<String>,
    known_provider_issues: Vec<KnownProviderIssue>,
}

#[derive(Clone, Debug)]
struct ProviderEvidence {
    executable_hash: String,
    bundle_hash: String,
}

pub(crate) fn doctor(config_path: &Path) -> Result<()> {
    let projection = doctor_projection(config_path)?;
    println!("{}", serde_json::to_string(&projection)?);
    if !projection.ready {
        bail!("UL cross-agent doctor is not ready");
    }
    Ok(())
}

pub(crate) async fn inspect(config_path: &Path, run_id: &str) -> Result<()> {
    validate_run_id(run_id)?;
    let evidence_path = certification_root()?.join(run_id).join("evidence.json");
    let evidence: Value = serde_json::from_slice(
        &fs::read(&evidence_path)
            .with_context(|| format!("read cross-agent evidence {}", evidence_path.display()))?,
    )
    .context("decode cross-agent evidence")?;
    if evidence.get("run_id").and_then(Value::as_str) != Some(run_id) {
        bail!("cross-agent evidence run_id does not match the requested run");
    }
    let project_id = evidence
        .get("project_id")
        .and_then(Value::as_str)
        .context("cross-agent evidence has no project_id")
        .and_then(|value| ProjectId::from_str(value).context("parse evidence project_id"))?;
    let calls = evidence
        .get("calls")
        .and_then(Value::as_array)
        .context("cross-agent evidence has no calls")?;
    let config = crate::config::load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    let mut treatments = Vec::new();
    for call in calls {
        if call.get("role").and_then(Value::as_str) != Some("treatment") {
            continue;
        }
        let case_id = call
            .get("case_id")
            .and_then(Value::as_str)
            .context("treatment evidence has no case_id")?;
        let session_id = call
            .get("planned_session_id")
            .and_then(Value::as_str)
            .context("treatment evidence has no planned_session_id")
            .and_then(|value| SessionId::from_str(value).context("parse treatment session_id"))?;
        let task_id = call
            .get("task_id")
            .and_then(Value::as_str)
            .context("treatment evidence has no task_id")
            .and_then(|value| TaskId::from_str(value).context("parse treatment task_id"))?;
        let receipts = store
            .load_injection_receipts(project_id, session_id)
            .await
            .with_context(|| format!("load {case_id} injection receipts"))?;
        let influence = store
            .observability_records_by_kind::<MemoryInfluenceTrace>(
                project_id,
                Some(task_id),
                ObservabilityKind::MemoryInfluenceTrace,
            )
            .await
            .with_context(|| format!("load {case_id} influence records"))?;
        treatments.push(json!({
            "case_id": case_id,
            "provider_session_id": session_id,
            "task_id": task_id,
            "injection_receipts": receipts,
            "influence_records": influence,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": "eliot-ul-cross-agent-receipt-inspection-v1",
            "run_id": run_id,
            "project_id": project_id,
            "read_only": true,
            "treatments": treatments,
        }))?
    );
    Ok(())
}

pub(crate) async fn run(config_path: &Path, confirmation: &str) -> Result<()> {
    if confirmation != UL_CROSS_AGENT_CONFIRMATION_TOKEN {
        bail!("UL cross-agent live run requires --confirm {UL_CROSS_AGENT_CONFIRMATION_TOKEN}");
    }
    require_provider_smokes()?;
    let doctor = doctor_projection(config_path)?;
    if !doctor.ready {
        bail!(
            "UL cross-agent certification is blocked by provider/runtime doctor status: {}",
            serde_json::to_string(&doctor)?
        );
    }

    let source_root = source_root()?;
    let suite = load_suite(&source_root)?;
    let output_contract_bytes =
        fs::read(source_root.join("tests/cognitive/ul-cross-agent/output-contract.json"))?;
    let output_contract: Value = serde_json::from_slice(&output_contract_bytes)?;
    let run_id = format!("ul-cross-agent-{}", uuid::Uuid::now_v7());
    let run_root = certification_root()?.join(&run_id);
    let repo = run_root.join("repo");
    fs::create_dir_all(&run_root)?;
    create_fixture_repo(&source_root, config_path, &repo)?;

    let project_identity = invoke_reference_tool(
        config_path,
        "codex_controller",
        "eliot_project_identity",
        &json!({"project_key": repo.to_string_lossy()}),
    )?;
    let project_id = project_identity
        .pointer("/tool_call/project_id")
        .and_then(Value::as_str)
        .context("project identity response has no project_id")
        .and_then(|value| ProjectId::from_str(value).context("parse certification project_id"))?;
    let plan = suite
        .plan(run_id.clone(), project_id)
        .map_err(anyhow::Error::msg)?;
    atomic_write_json(&run_root.join("plan.json"), &plan)?;
    atomic_write_json(&run_root.join("doctor.json"), &doctor)?;

    for call in &plan.calls {
        create_task_contract(config_path, project_id, call)?;
    }

    let marker_a = random_marker();
    let marker_b = random_marker();
    let writer_write_a = uuid::Uuid::now_v7().to_string();
    let writer_write_b = uuid::Uuid::now_v7().to_string();
    let mut calls = Vec::with_capacity(plan.calls.len());
    let mut provider_call_count = 0_u8;
    let mut terminal_errors = Vec::new();

    for call in &plan.calls {
        if provider_call_count >= plan.hard_provider_call_cap {
            bail!(
                "UL cross-agent hard provider call cap was reached before {}",
                call.case_id
            );
        }
        let provider_evidence = provider_evidence(config_path, call.host)?;
        let requested_model = provider_model(call.host)?.to_owned();
        let marker = match call.direction {
            UlCrossAgentDirection::A => &marker_a,
            UlCrossAgentDirection::B => &marker_b,
        };
        let writer_write_id = match call.direction {
            UlCrossAgentDirection::A => &writer_write_a,
            UlCrossAgentDirection::B => &writer_write_b,
        };
        let prompt = if call.role == UlCrossAgentRole::Writer {
            writer_prompt(call, project_id, marker, writer_write_id)?
        } else {
            reader_prompt(call, project_id)
        };
        let prompt_sha256 = sha256_bytes(prompt.as_bytes());
        let contamination = if call.role == UlCrossAgentRole::Writer {
            None
        } else {
            Some(scan_reader_authority(
                &source_root,
                &repo,
                marker,
                &prompt,
                &output_contract_bytes,
                call,
                project_id,
            )?)
        };
        if contamination
            .as_ref()
            .is_some_and(|receipt| !receipt.passed)
        {
            let reason = format!("{} aborted as CONTAMINATED_INPUT", call.case_id);
            terminal_errors.push(reason.clone());
            calls.push(CallArchive {
                case_id: call.case_id.clone(),
                host: call.host,
                role: call.role,
                task_id: call.task_id.to_string(),
                planned_session_id: call.session_id.to_string(),
                mcp_profile: auditor_mcp_profile(call.host).to_owned(),
                requested_model: requested_model.clone(),
                prompt_sha256,
                provider_executable_hash: provider_evidence.executable_hash,
                integration_bundle_hash: provider_evidence.bundle_hash,
                mcp_preflight: None,
                contamination,
                provider_dispatched: false,
                outcome_unknown: false,
                revision_before: project_revision(config_path, project_id).ok(),
                revision_after: None,
                structured_output_sha256: None,
                structured_output: None,
                canonical_verification: CanonicalCallVerification::default(),
                terminal_error: Some(reason),
            });
            break;
        }

        let preflight_session_id = fresh_preflight_session(call.session_id);
        let preflight_scope = crate::host_runtime::prepare_ul_auditor_scope(
            config_path,
            call.host,
            project_id,
            call.task_id,
            preflight_session_id,
            &format!("{run_id}-{}-preflight", call.case_id),
        )
        .await
        .with_context(|| format!("prepare isolated MCP preflight for {}", call.case_id))?;
        let mcp_preflight = scoped_mcp_preflight(
            config_path,
            call.host,
            project_id,
            call.task_id,
            preflight_session_id,
            &preflight_scope,
        )
        .with_context(|| format!("run scoped MCP preflight for {}", call.case_id))?;
        let launch_scope = crate::host_runtime::prepare_ul_auditor_scope(
            config_path,
            call.host,
            project_id,
            call.task_id,
            call.session_id,
            &format!("{run_id}-{}", call.case_id),
        )
        .await
        .with_context(|| format!("prepare canonical auditor scope for {}", call.case_id))?;
        let revision_before = project_revision(config_path, project_id).ok();
        let request = UlReasoningRequest {
            idempotency_key: format!("{run_id}-{}", call.case_id),
            project_id,
            task_id: call.task_id,
            route: route(call.host)?,
            model: Some(requested_model.clone()),
            prompt,
            output_schema: if call.role == UlCrossAgentRole::Writer {
                writer_output_schema()
            } else {
                output_contract.clone()
            },
            max_input_bytes: 64 * 1024,
            max_output_units: 8_192,
            timeout_seconds: 180,
        };
        let result = crate::host_runtime::invoke_ul_scoped_reasoning(
            config_path,
            &repo,
            &request,
            launch_scope,
        )
        .await;
        let revision_after = project_revision(config_path, project_id).ok();
        match result {
            Ok(output) => {
                provider_call_count = provider_call_count.saturating_add(1);
                let structured_output_sha256 = Some(sha256_bytes(&serde_json::to_vec(&output)?));
                let (canonical_verification, terminal_error) = match verify_canonical_call(
                    config_path,
                    project_id,
                    call,
                    marker,
                    writer_write_id,
                    &output,
                )
                .await
                {
                    Ok(verification) => (verification, None),
                    Err(error) => {
                        let reason =
                            format!("{} canonical verification failed: {error:#}", call.case_id);
                        terminal_errors.push(reason.clone());
                        (CanonicalCallVerification::default(), Some(reason))
                    }
                };
                let verification_failed = terminal_error.is_some();
                calls.push(CallArchive {
                    case_id: call.case_id.clone(),
                    host: call.host,
                    role: call.role,
                    task_id: call.task_id.to_string(),
                    planned_session_id: call.session_id.to_string(),
                    mcp_profile: auditor_mcp_profile(call.host).to_owned(),
                    requested_model: requested_model.clone(),
                    prompt_sha256,
                    provider_executable_hash: provider_evidence.executable_hash,
                    integration_bundle_hash: provider_evidence.bundle_hash,
                    mcp_preflight: Some(mcp_preflight.clone()),
                    contamination,
                    provider_dispatched: true,
                    outcome_unknown: false,
                    revision_before,
                    revision_after,
                    structured_output_sha256,
                    structured_output: Some(output),
                    canonical_verification,
                    terminal_error,
                });
                if verification_failed {
                    break;
                }
            }
            Err(error) => {
                let error_detail = format!("{error:#}");
                let provider_dispatched = error_reports_provider_dispatched(&error_detail);
                let outcome_unknown =
                    provider_dispatched && error_reports_unknown_outcome(&error_detail);
                if provider_dispatched {
                    provider_call_count = provider_call_count.saturating_add(1);
                }
                let reason = format!("{} provider outcome: {error_detail}", call.case_id);
                terminal_errors.push(reason.clone());
                calls.push(CallArchive {
                    case_id: call.case_id.clone(),
                    host: call.host,
                    role: call.role,
                    task_id: call.task_id.to_string(),
                    planned_session_id: call.session_id.to_string(),
                    mcp_profile: auditor_mcp_profile(call.host).to_owned(),
                    requested_model,
                    prompt_sha256,
                    provider_executable_hash: provider_evidence.executable_hash,
                    integration_bundle_hash: provider_evidence.bundle_hash,
                    mcp_preflight: Some(mcp_preflight),
                    contamination,
                    provider_dispatched,
                    outcome_unknown,
                    revision_before,
                    revision_after,
                    structured_output_sha256: None,
                    structured_output: None,
                    canonical_verification: CanonicalCallVerification::default(),
                    terminal_error: Some(reason),
                });
                break;
            }
        }
    }

    let direction_a = direction_evidence(&calls, UlCrossAgentDirection::A, &marker_a);
    let direction_b = direction_evidence(&calls, UlCrossAgentDirection::B, &marker_b);
    let unknown_outcome_calls = calls
        .iter()
        .filter(|call| call.outcome_unknown)
        .map(|call| call.case_id.clone())
        .collect();
    let report = UlCrossAgentReport::from_evidence(
        run_id.clone(),
        project_id,
        provider_call_count,
        &direction_a,
        &direction_b,
        unknown_outcome_calls,
    );
    atomic_write_json(
        &run_root.join("controller-private-outputs.json"),
        &json!({
            "schema_version": "eliot-ul-cross-agent-controller-outputs-v1",
            "run_id": run_id,
            "calls": calls.iter().filter_map(|call| {
                call.structured_output.as_ref().map(|output| json!({
                    "case_id": call.case_id,
                    "task_id": call.task_id,
                    "session_id": call.planned_session_id,
                    "output": output,
                }))
            }).collect::<Vec<_>>()
        }),
    )?;
    let evidence = RunEvidence {
        schema_version: "eliot-ul-cross-agent-evidence-v1",
        run_id: run_id.clone(),
        project_id,
        repo: repo.clone(),
        plan,
        provider_call_count,
        calls,
        terminal_errors,
        known_provider_issues: vec![
            KnownProviderIssue {
                provider: "claude-code",
                category: "safety_refusal_before_tool_use",
                status: "prompt_reworded_under_operator_authorization",
                note: CLAUDE_WRITER_REFUSAL_NOTE,
            },
            KnownProviderIssue {
                provider: "antigravity",
                category: "unclassified_non_json_before_tool_use",
                status: "provider_contract_hardened_pending_retest",
                note: ANTIGRAVITY_WRITER_NON_JSON_NOTE,
            },
        ],
    };
    atomic_write_json(&run_root.join("evidence.json"), &evidence)?;
    atomic_write_json(
        &run_root.join("controller-private-expected.json"),
        &json!({
            "schema_version": "eliot-ul-cross-agent-controller-expected-v1",
            "direction_a": {"marker": marker_a, "write_id": writer_write_a},
            "direction_b": {"marker": marker_b, "write_id": writer_write_b}
        }),
    )?;
    atomic_write_json(&run_root.join("report.json"), &report)?;
    atomic_write_bytes(
        &run_root.join("report.md"),
        report_markdown(&report).as_bytes(),
    )?;
    atomic_write_bytes(
        &certification_root()?.join("latest-run.txt"),
        run_id.as_bytes(),
    )?;
    println!("{}", serde_json::to_string(&report)?);
    if !report.passed {
        bail!(
            "UL cross-agent certification did not pass; sanitized report: {}",
            run_root.join("report.json").display()
        );
    }
    Ok(())
}

pub(crate) async fn smoke(
    config_path: &Path,
    route: UlReasoningRoute,
    confirmation: &str,
) -> Result<()> {
    if confirmation != UL_CROSS_AGENT_CONFIRMATION_TOKEN {
        bail!(
            "UL cross-agent provider smoke requires --confirm {UL_CROSS_AGENT_CONFIRMATION_TOKEN}"
        );
    }
    let host = route.host();
    let source_root = source_root()?;
    let smoke_id = format!("ul11r3-smoke-{}-{}", host.as_str(), uuid::Uuid::now_v7());
    let smoke_root = certification_root()?
        .join("provider-smokes")
        .join(&smoke_id);
    let repo = smoke_root.join("repo");
    fs::create_dir_all(&smoke_root)?;
    create_fixture_repo(&source_root, config_path, &repo)?;

    let project_identity = invoke_reference_tool(
        config_path,
        "codex_controller",
        "eliot_project_identity",
        &json!({"project_key": repo.to_string_lossy()}),
    )?;
    let project_id = project_identity
        .pointer("/tool_call/project_id")
        .and_then(Value::as_str)
        .context("provider smoke project identity returned no project_id")
        .and_then(|value| ProjectId::from_str(value).context("parse smoke project_id"))?;
    let task_id = TaskId::new_v7();
    create_smoke_task_contract(config_path, project_id, task_id, host)?;
    let session_id = SessionId::new_v7();
    let launch_scope = crate::host_runtime::prepare_ul_auditor_scope(
        config_path,
        host,
        project_id,
        task_id,
        session_id,
        &smoke_id,
    )
    .await
    .context("prepare provider smoke scope")?;
    let mcp_preflight = scoped_mcp_preflight(
        config_path,
        host,
        project_id,
        task_id,
        session_id,
        &launch_scope,
    )
    .context("run provider smoke MCP preflight")?;
    let role_lease_id = launch_scope
        .role_lease_id
        .clone()
        .context("provider smoke scope has no TaskRoleLease")?;
    let agent_session_id = launch_scope
        .agent_session_id
        .context("provider smoke scope has no AgentSession")?;
    let provider_evidence = provider_evidence(config_path, host)?;
    let (model, model_selection_reason) = match host {
        AgentHostId::Claude => (
            CLAUDE_SMOKE_MODEL,
            "simple MCP-adoption smoke uses the economical Claude route; Opus is reserved for complex certification or escalation",
        ),
        AgentHostId::Antigravity => (
            ANTIGRAVITY_SMOKE_MODEL,
            "Gemini Flash high has ample quota and is sufficient for a single current_state tool call; Antigravity Opus is reserved for UL-11 reasoning",
        ),
        _ => bail!("unsupported provider smoke host"),
    };
    let request = UlReasoningRequest {
        idempotency_key: smoke_id.clone(),
        project_id,
        task_id,
        route,
        model: Some(model.to_owned()),
        prompt: "Use the installed ELIOT workflow and ELIOT MCP. Read the current project/task state and return project_id, task_id, memory_revision as JSON. Do not copy identifiers from files or infer them from the path; use ELIOT current_state under the bound session.".to_owned(),
        output_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "project_id": {"type": "string"},
                "task_id": {"type": "string"},
                "memory_revision": {"type": "integer", "minimum": 0}
            },
            "required": ["project_id", "task_id", "memory_revision"]
        }),
        max_input_bytes: 16 * 1024,
        max_output_units: 1_024,
        timeout_seconds: 180,
    };
    let output =
        crate::host_runtime::invoke_ul_scoped_reasoning(config_path, &repo, &request, launch_scope)
            .await
            .with_context(|| format!("{} live provider smoke failed", host.as_str()))?;
    if output.get("project_id").and_then(Value::as_str) != Some(project_id.to_string().as_str())
        || output.get("task_id").and_then(Value::as_str) != Some(task_id.to_string().as_str())
        || output.get("memory_revision").and_then(Value::as_u64)
            != Some(mcp_preflight.current_state_revision)
    {
        bail!(
            "{} provider smoke returned schema-valid but canonically incorrect current_state",
            host.as_str()
        );
    }

    let provider_session = load_provider_session_report(config_path, agent_session_id)?;
    let provider_session_client_name = provider_session
        .get("client_name")
        .and_then(Value::as_str)
        .context("provider AgentSession report has no client_name")?
        .to_owned();
    let provider_session_transport = provider_session
        .get("transport")
        .and_then(Value::as_str)
        .context("provider AgentSession report has no transport")?
        .to_owned();
    if provider_session_client_name.starts_with("eliot-ul11r3-")
        || provider_session_transport != "mcp_stdio_windows_named_pipe"
        || provider_session
            .get("agent_session_id")
            .and_then(Value::as_str)
            != Some(agent_session_id.to_string().as_str())
        || provider_session
            .get("bound_project_id")
            .and_then(Value::as_str)
            != Some(project_id.to_string().as_str())
        || provider_session
            .get("bound_task_id")
            .and_then(Value::as_str)
            != Some(task_id.to_string().as_str())
        || provider_session
            .get("access_profile")
            .and_then(Value::as_str)
            != Some(auditor_mcp_profile(host))
        || provider_session
            .pointer("/host_identity/host_id")
            .and_then(Value::as_str)
            != Some(host.as_str())
        || !provider_session
            .get("task_role_lease_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.iter()
                    .any(|reference| reference.as_str() == Some(role_lease_id.as_str()))
            })
    {
        bail!(
            "{} provider smoke did not leave an exact provider-owned scoped MCP AgentSession receipt",
            host.as_str()
        );
    }

    let structured_output_sha256 = sha256_bytes(&serde_json::to_vec(&output)?);
    let evidence = ProviderMcpSmokeEvidence {
        schema_version: "eliot-ul11r3-provider-mcp-smoke-v1",
        smoke_id,
        host,
        model: model.to_owned(),
        model_selection_reason,
        project_id,
        task_id,
        agent_session_id,
        role_lease_id,
        repo,
        mcp_preflight,
        provider_session_client_name,
        provider_session_transport,
        provider_executable_hash: provider_evidence.executable_hash,
        integration_bundle_hash: provider_evidence.bundle_hash,
        structured_output: output,
        structured_output_sha256,
        provider_dispatched: true,
        controller_substitute_call: false,
        passed: true,
    };
    let evidence_path = smoke_root.join("evidence.json");
    atomic_write_json(&evidence_path, &evidence)?;
    atomic_write_json(&provider_smoke_latest_path(host)?, &evidence)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "status": "passed",
            "host": host,
            "model": model,
            "evidence": evidence_path
        }))?
    );
    Ok(())
}

fn create_smoke_task_contract(
    config_path: &Path,
    project_id: ProjectId,
    task_id: TaskId,
    host: AgentHostId,
) -> Result<()> {
    let response = invoke_reference_tool(
        config_path,
        "codex_controller",
        "eliot_task_contract_create",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": uuid::Uuid::now_v7(),
            "title": format!("UL-11R3 {} authenticated MCP adoption smoke", host.as_str()),
            "acceptance_items": [
                {
                    "item_id": "scoped_transport",
                    "description": "provider starts the exact scoped ELIOT stdio child",
                    "required_evidence": "observation"
                },
                {
                    "item_id": "current_state",
                    "description": "provider returns the canonical bound project/task revision",
                    "required_evidence": "verification"
                }
            ]
        }),
    )?;
    if response.pointer("/tool_call/task_contract").is_none() {
        bail!("provider smoke task contract creation returned no canonical task");
    }
    Ok(())
}

fn load_provider_session_report(
    config_path: &Path,
    agent_session_id: AgentSessionId,
) -> Result<Value> {
    let path = crate::delegation_runtime::root_from_config(config_path)
        .join("reports")
        .join("agent-sessions")
        .join(format!("{agent_session_id}.json"));
    serde_json::from_slice(&fs::read(&path)?)
        .with_context(|| format!("read provider AgentSession receipt {}", path.display()))
}

fn provider_smoke_latest_path(host: AgentHostId) -> Result<PathBuf> {
    Ok(certification_root()?
        .join("provider-smokes")
        .join(format!("{}-latest.json", host.as_str())))
}

fn require_provider_smokes() -> Result<()> {
    for host in [AgentHostId::Claude, AgentHostId::Antigravity] {
        let path = provider_smoke_latest_path(host)?;
        let evidence: Value = serde_json::from_slice(&fs::read(&path).with_context(|| {
            format!(
                "{} provider smoke has not passed; run the bounded smoke before the eight-call suite",
                host.as_str()
            )
        })?)?;
        if evidence.get("passed").and_then(Value::as_bool) != Some(true)
            || evidence.get("host").and_then(Value::as_str) != Some(host.as_str())
            || evidence.get("provider_dispatched").and_then(Value::as_bool) != Some(true)
            || evidence
                .get("controller_substitute_call")
                .and_then(Value::as_bool)
                != Some(false)
        {
            bail!(
                "{} provider smoke evidence is not a passing live MCP receipt",
                host.as_str()
            );
        }
    }
    Ok(())
}

pub(crate) fn report(run_id: &str) -> Result<()> {
    if run_id.trim().is_empty() || run_id.contains(['/', '\\']) || run_id == "." || run_id == ".." {
        bail!("invalid UL cross-agent run id");
    }
    let path = certification_root()?.join(run_id).join("report.json");
    let report: UlCrossAgentReport = serde_json::from_slice(
        &fs::read(&path)
            .with_context(|| format!("read UL cross-agent report {}", path.display()))?,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn doctor_projection(config_path: &Path) -> Result<CrossAgentDoctor> {
    let source_root = source_root()?;
    let suite_valid = load_suite(&source_root).is_ok();
    let output_contract_valid = validate_reader_output_contract(
        &source_root.join("tests/cognitive/ul-cross-agent/output-contract.json"),
    )
    .is_ok();
    let governor_executable = std::env::current_exe()?.canonicalize()?;
    let governor_comparison_path = PathBuf::from(subprocess_path(&governor_executable));
    let governor_outside_onedrive = std::env::var_os("OneDrive").is_none_or(|root| {
        let root = PathBuf::from(subprocess_path(Path::new(&root)));
        !path_starts_with(&governor_comparison_path, &root)
    });
    let claude = invoke_governor_json(config_path, ["host", "doctor", "--host", "claude"])
        .unwrap_or_else(|error| json!({"ready": false, "error": format!("{error:#}")}));
    let antigravity = invoke_governor_json(config_path, ["antigravity", "doctor"])
        .unwrap_or_else(|error| json!({"ready": false, "error": format!("{error:#}")}));
    let daemon = invoke_governor_json(config_path, ["daemon", "doctor", "--instance", "default"])
        .unwrap_or_else(|error| json!({"ready": false, "error": format!("{error:#}")}));
    let claude_ready = claude.get("ready").and_then(Value::as_bool) == Some(true)
        || claude.get("status").and_then(Value::as_str) == Some("ready");
    let antigravity_ready = antigravity
        .pointer("/doctor/status")
        .and_then(Value::as_str)
        == Some("ready")
        || antigravity
            .pointer("/doctor/ready")
            .and_then(Value::as_bool)
            == Some(true)
        || antigravity.get("ready").and_then(Value::as_bool) == Some(true);
    let daemon_ready = daemon.get("ready").and_then(Value::as_bool) == Some(true)
        || daemon.get("status").and_then(Value::as_str) == Some("ready")
        || daemon.pointer("/overall/status").and_then(Value::as_str) == Some("ready");
    Ok(CrossAgentDoctor {
        schema_version: "eliot-ul-cross-agent-doctor-v1",
        ready: suite_valid
            && output_contract_valid
            && governor_outside_onedrive
            && claude_ready
            && antigravity_ready
            && daemon_ready,
        source_root,
        suite_valid,
        output_contract_valid,
        governor_executable,
        governor_outside_onedrive,
        claude,
        antigravity,
        daemon,
    })
}

fn invoke_governor_json<I, S>(config_path: &Path, args: I) -> Result<Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(std::env::current_exe()?);
    if config_path.is_file() {
        command.args(["--config", &config_path.to_string_lossy()]);
    }
    command.args(args);
    let output = run_cross_agent_supervised(
        config_path,
        &command,
        "governor-doctor",
        Duration::from_secs(60),
        SupervisedChildKind::Verifier,
    )?;
    if !output.status.success() {
        bail!(
            "governor doctor subprocess failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("decode governor doctor JSON")
}

fn provider_evidence(config_path: &Path, host: AgentHostId) -> Result<ProviderEvidence> {
    let doctor = invoke_governor_json(
        config_path,
        ["host", "doctor", "--host", provider_doctor_selector(host)],
    )?;
    Ok(ProviderEvidence {
        executable_hash: doctor
            .pointer("/profile/executable_hash")
            .and_then(Value::as_str)
            .context("host doctor returned no provider executable hash")?
            .to_owned(),
        bundle_hash: doctor
            .pointer("/bundle/hash")
            .and_then(Value::as_str)
            .context("host doctor returned no integration bundle hash")?
            .to_owned(),
    })
}

fn provider_doctor_selector(host: AgentHostId) -> &'static str {
    match host {
        AgentHostId::Claude => "claude_code_plugin",
        AgentHostId::Antigravity => "antigravity",
        _ => host.as_str(),
    }
}

fn auditor_mcp_profile(host: AgentHostId) -> &'static str {
    match host {
        AgentHostId::Claude => "claude_governed",
        AgentHostId::Antigravity => "external_auditor",
        _ => "unsupported",
    }
}

fn run_cross_agent_supervised(
    config_path: &Path,
    command: &Command,
    operation_class: &str,
    timeout: Duration,
    child_kind: SupervisedChildKind,
) -> Result<std::process::Output> {
    let mut environment = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            environment.insert(OsString::from(name), OsString::from(value));
        } else {
            environment.remove(name);
        }
    }
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let operation_id = format!(
        "ul-cross-agent-{}-{}",
        operation_class
            .chars()
            .map(|character| if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            })
            .collect::<String>(),
        uuid::Uuid::now_v7()
    );
    let output = run_supervised_process_blocking(
        SupervisedProcessSpec {
            operation_id: operation_id.clone(),
            invocation_id: None,
            generation: 1,
            child_kind,
            criticality: ChildCriticality::InvocationDependency,
            restart_policy: ProcessRestartPolicy {
                strategy: RestartStrategy::Never,
                max_restarts: 0,
                restart_window_seconds: 60,
                base_backoff_ms: 0,
                pre_dispatch_only: false,
            },
            executable: command.get_program().into(),
            args: command.get_args().map(OsString::from).collect(),
            cwd: command
                .get_current_dir()
                .map(ToOwned::to_owned)
                .map_or_else(std::env::current_dir, Ok)?,
            environment,
            stdin_payload: None,
            stdout_limit_bytes: 8 * 1024 * 1024,
            stderr_limit_bytes: 8 * 1024 * 1024,
            timeout_profile: eliot_types::ProviderTimeoutProfile {
                profile_id: "ul-cross-agent-process-v1".to_owned(),
                provider: "eliot-governor".to_owned(),
                route_or_operation_class: operation_class.to_owned(),
                spawn_deadline_ms: Some(5_000),
                dispatch_ack_deadline_ms: None,
                first_output_deadline_ms: Some(timeout_ms),
                idle_output_deadline_ms: Some(timeout_ms),
                absolute_runtime_deadline_ms: timeout_ms,
                cancellation_grace_ms: 25,
                cleanup_grace_ms: 5_000,
                reconciliation_window_ms: 0,
                output_heartbeat_supported: true,
                status_lookup_supported: false,
                evidence_basis: vec!["bounded UL cross-agent helper".to_owned()],
                assumptions: Vec::new(),
                hard_upper_bounds: vec!["caller-supplied timeout".to_owned()],
                policy_version: "runtime-supervision-v1".to_owned(),
            },
            runtime_contract_sha256: None,
            role_lease_id: None,
            role_lease_epoch: None,
        },
        eliot_engine::runtime_supervision::AdapterExecutionContext {
            operation_id,
            generation: 1,
            cancellation: eliot_engine::runtime_supervision::CancellationToken::new(),
            deadline: tokio::time::Instant::now() + timeout,
            runtime_store:
                crate::host_runtime::supervised_process::daemon_operation_runtime_handle(
                    config_path,
                )?,
            role_lease_id: None,
            role_lease_epoch: None,
            runtime_contract_sha256: None,
        },
    )?;
    if output.timed_out
        || output.worker_error.is_some()
        || !output.reap_receipt.proves_complete_reap()
    {
        bail!(
            "UL cross-agent supervised subprocess failed or timed out: {:?}",
            output.worker_error
        );
    }
    Ok(std::process::Output {
        status: std::process::ExitStatus::from_raw(
            output.exit_code.unwrap_or(i32::MAX).cast_unsigned(),
        ),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn invoke_reference_tool(
    config_path: &Path,
    profile: &str,
    tool_name: &str,
    arguments: &Value,
) -> Result<Value> {
    let script = source_root()?.join("scripts/eliot-mcp-reference-client.ps1");
    let governor_executable = subprocess_path(&std::env::current_exe()?);
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        &script.to_string_lossy(),
        "-EliotExe",
        &governor_executable,
        "-Profile",
        profile,
        "-ToolName",
        tool_name,
        "-ToolArgumentsJson",
        &serde_json::to_string(arguments)?,
        "-TimeoutSeconds",
        "60",
    ]);
    if config_path.is_file() {
        command.args(["-Config", &config_path.to_string_lossy()]);
    }
    let output = run_cross_agent_supervised(
        config_path,
        &command,
        &format!("reference-tool-{tool_name}"),
        Duration::from_secs(65),
        SupervisedChildKind::McpPreflight,
    )?;
    if !output.status.success() {
        bail!(
            "reference MCP tool {tool_name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: Value =
        serde_json::from_slice(&output.stdout).context("decode reference MCP client JSON")?;
    if !value.get("tool_call_error").is_none_or(Value::is_null) {
        bail!(
            "reference MCP tool {tool_name} returned an error: {}",
            value["tool_call_error"]
        );
    }
    Ok(value)
}

fn scoped_mcp_preflight(
    config_path: &Path,
    host: AgentHostId,
    project_id: ProjectId,
    task_id: eliot_types::TaskId,
    session_id: eliot_types::SessionId,
    scope: &HostLaunchScope,
) -> Result<ScopedMcpPreflightEvidence> {
    let agent_session_id = scope
        .agent_session_id
        .context("scoped MCP preflight requires agent_session_id")?;
    let role_lease_id = scope
        .role_lease_id
        .as_deref()
        .context("scoped MCP preflight requires role_lease_id")?;
    if agent_session_id != AgentSessionId::from_uuid(session_id.as_uuid())
        || scope.project_id != Some(project_id)
        || scope.task_id != Some(task_id)
    {
        bail!("scoped MCP preflight scope differs from the planned provider call");
    }

    let script = source_root()?.join("scripts/eliot-mcp-reference-client.ps1");
    let governor_executable = subprocess_path(&std::env::current_exe()?);
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        &script.to_string_lossy(),
        "-EliotExe",
        &governor_executable,
        "-HostSurface",
        host.as_str(),
        "-ProjectId",
        &project_id.to_string(),
        "-AgentSessionId",
        &agent_session_id.to_string(),
        "-TaskId",
        &task_id.to_string(),
        "-RoleLeaseId",
        role_lease_id,
        "-ToolName",
        "eliot_current_state",
        "-ToolArgumentsJson",
        &serde_json::to_string(&preflight_current_state_arguments())?,
        "-ClientName",
        &format!("eliot-ul11r3-{}-preflight", host.as_str()),
        "-TimeoutSeconds",
        "60",
    ]);
    if host == AgentHostId::Antigravity {
        command.args(["-Profile", "external_auditor"]);
    }
    if config_path.is_file() {
        command.args(["-Config", &config_path.to_string_lossy()]);
    }
    let output = run_cross_agent_supervised(
        config_path,
        &command,
        &format!("scoped-preflight-{}", host.as_str()),
        Duration::from_secs(65),
        SupervisedChildKind::McpPreflight,
    )?;
    if !output.status.success() {
        bail!(
            "{} scoped MCP preflight failed: {}",
            host.as_str(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: Value =
        serde_json::from_slice(&output.stdout).context("decode scoped MCP preflight JSON")?;
    if !value.get("tool_call_error").is_none_or(Value::is_null) {
        bail!(
            "{} scoped current_state returned an error: {}",
            host.as_str(),
            value["tool_call_error"]
        );
    }

    let expected_profile = auditor_mcp_profile(host);
    let actual_profile = value
        .get("profile")
        .and_then(Value::as_str)
        .context("scoped MCP preflight returned no access profile")?;
    if actual_profile != expected_profile {
        bail!(
            "{} scoped MCP profile mismatch: expected {expected_profile}, received {actual_profile}",
            host.as_str()
        );
    }
    let tool_names = value
        .get("tool_names")
        .and_then(Value::as_array)
        .context("scoped MCP preflight returned no tool list")?
        .iter()
        .map(|name| {
            name.as_str()
                .map(str::to_owned)
                .context("scoped MCP tool name is not a string")
        })
        .collect::<Result<Vec<_>>>()?;
    let actual_tools = tool_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_tools = crate::mcp_stdio::PART_E_WORKER_TOOLS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if actual_tools != expected_tools || tool_names.len() != expected_tools.len() {
        bail!(
            "{} scoped MCP tool list is not the exact duplicate-free Part-E surface",
            host.as_str()
        );
    }

    let agent_session = value
        .get("agent_session")
        .context("scoped MCP preflight returned no AgentSession")?;
    for (field, expected) in [
        ("agent_session_id", agent_session_id.to_string()),
        ("bound_project_id", project_id.to_string()),
        ("bound_task_id", task_id.to_string()),
    ] {
        if agent_session.get(field).and_then(Value::as_str) != Some(expected.as_str()) {
            bail!(
                "{} scoped MCP AgentSession field {field} did not match the bound scope",
                host.as_str()
            );
        }
    }
    if !agent_session
        .get("task_role_lease_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter()
                .any(|reference| reference.as_str() == Some(role_lease_id))
        })
    {
        bail!(
            "{} scoped MCP AgentSession did not carry the bound TaskRoleLease",
            host.as_str()
        );
    }
    let current_state_revision = value
        .pointer("/tool_call/memory_revision")
        .and_then(Value::as_u64)
        .context("scoped MCP current_state returned no revision fence")?;

    Ok(ScopedMcpPreflightEvidence {
        host,
        profile: actual_profile.to_owned(),
        agent_session_id: agent_session_id.to_string(),
        memory_scope: "memory_free_control",
        project_id: project_id.to_string(),
        task_id: task_id.to_string(),
        role_lease_id: role_lease_id.to_owned(),
        tool_names,
        current_state_revision,
    })
}

fn create_task_contract(
    config_path: &Path,
    project_id: ProjectId,
    call: &eliot_types::UlCrossAgentPlannedCall,
) -> Result<()> {
    let response = invoke_reference_tool(
        config_path,
        "codex_controller",
        "eliot_task_contract_create",
        &json!({
            "project_id": project_id,
            "task_id": call.task_id,
            "write_id": uuid::Uuid::now_v7(),
            "title": format!("UL-11 {} blind relay certification", call.case_id),
            "acceptance_items": [
                {
                    "item_id": "blindness",
                    "description": "provider input remains marker-blind outside the writer call",
                    "required_evidence": "observation"
                },
                {
                    "item_id": "canonical",
                    "description": "result is reconciled against canonical ELIOT receipts",
                    "required_evidence": "verification"
                }
            ]
        }),
    )?;
    if response.pointer("/tool_call/task_contract").is_none() {
        bail!(
            "task contract creation returned no canonical task for {}",
            call.case_id
        );
    }
    Ok(())
}

fn project_revision(config_path: &Path, project_id: ProjectId) -> Result<u64> {
    let response = invoke_reference_tool(
        config_path,
        "codex_controller",
        "eliot_fetch_l2",
        &json!({
            "project_id": project_id,
            "handles": [],
            "consistency": "latest"
        }),
    )?;
    response
        .pointer("/tool_call/at_revision")
        .and_then(Value::as_u64)
        .context("fetch_l2 returned no at_revision")
}

fn treatment_surface_matches_canonical_evidence(
    reader_surface: Option<&str>,
    receipt_surface: &str,
    influence_context_id: Option<&str>,
) -> bool {
    let known_receipt_surface = matches!(
        receipt_surface,
        "mcp_auto_boot"
            | "mcp_response_piggyback"
            | "ul_boot"
            | "ul_fired"
            | "recall_l0"
            | "fetch_l2"
            | "packet"
    );
    if !known_receipt_surface {
        return false;
    }

    match reader_surface {
        Some("ul_boot") => matches!(receipt_surface, "mcp_auto_boot" | "ul_boot"),
        Some("ul_fired") => {
            matches!(receipt_surface, "mcp_response_piggyback" | "ul_fired")
        }
        Some("recall_l0" | "fetch_l2") => {
            influence_context_id.is_some_and(|context_id| context_id.starts_with("retrieval:"))
        }
        Some("packet") => {
            influence_context_id.is_some_and(|context_id| !context_id.starts_with("retrieval:"))
        }
        _ => false,
    }
}

#[allow(clippy::too_many_lines)]
async fn verify_canonical_call(
    config_path: &Path,
    project_id: ProjectId,
    call: &eliot_types::UlCrossAgentPlannedCall,
    marker: &str,
    writer_write_id: &str,
    output: &Value,
) -> Result<CanonicalCallVerification> {
    let config = crate::config::load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    let mut verification = CanonicalCallVerification::default();
    match call.role {
        UlCrossAgentRole::Writer => {
            let writer: UlCrossAgentWriterOutput = serde_json::from_value(output.clone())
                .with_context(|| format!("decode {} writer output contract", call.case_id))?;
            let write_id =
                WriteId::from_str(writer_write_id).context("parse expected writer write_id")?;
            let expected_handle = format!("claim:{write_id}");
            let response = store
                .fetch_atoms_l2(&FetchAtomsL2Request {
                    project_id,
                    handles: vec![expected_handle.clone()],
                    continuation: None,
                    consistency: ReadConsistencyMode::Latest,
                    at_least_revision: None,
                })
                .await?;
            let claim = response
                .claims
                .iter()
                .find(|claim| format!("claim:{}", claim.claim_id) == expected_handle)
                .context("canonical writer candidate handle did not resolve")?;
            let receipt = store
                .write_receipt_by_id(&write_id)
                .await?
                .context("canonical writer WriteReceipt did not resolve")?;
            let expected_profile = match call.host {
                AgentHostId::Claude => "claude_governed",
                AgentHostId::Antigravity => "external_auditor",
                _ => bail!("unsupported UL writer host"),
            };
            let cue_exact = claim
                .payload
                .get("cue_bindings")
                .and_then(Value::as_array)
                .is_some_and(|bindings| {
                    bindings.iter().any(|binding| {
                        binding.get("cue_kind").and_then(Value::as_str) == Some("file_path")
                            && binding.get("cue_value").and_then(Value::as_str)
                                == Some(call.file_cue.as_str())
                            && binding.get("strength").and_then(Value::as_str) == Some("primary")
                    })
                });
            let session_exact = claim
                .payload
                .get("agent_session_id")
                .and_then(Value::as_str)
                == Some(call.session_id.to_string().as_str());
            let canonical_candidate_only = claim.status == EpistemicStatus::Candidate
                && claim.payload.get("candidate_only").and_then(Value::as_bool) == Some(true)
                && claim
                    .payload
                    .get("controller_reconciliation_required")
                    .and_then(Value::as_bool)
                    == Some(true);
            let receipt_exact = receipt.project_id == project_id
                && receipt.task_id == Some(call.task_id)
                && receipt.command_kind == SemanticCommandKind::ClaimPropose
                && matches!(
                    receipt.status,
                    WriteStatus::Committed | WriteStatus::IdempotentReplay
                )
                && receipt.rejected_reason.is_none()
                && receipt.created_records.iter().any(|record| {
                    record == &expected_handle || record == &claim.claim_id.to_string()
                });
            verification.candidate_handle = Some(expected_handle.clone());
            verification.candidate_write_id = Some(write_id.to_string());
            verification.candidate_session_exact = session_exact;
            verification.candidate_stayed_candidate_only = canonical_candidate_only;
            verification.candidate_exact = writer.candidate_only
                && writer.candidate_handle == expected_handle
                && writer.write_receipt == write_id.to_string()
                && response.returned_handles.contains(&expected_handle)
                && claim.statement == expected_writer_statement(call, marker)
                && claim.payload.get("task_id").and_then(Value::as_str)
                    == Some(call.task_id.to_string().as_str())
                && claim.payload.get("profile").and_then(Value::as_str) == Some(expected_profile)
                && cue_exact
                && session_exact
                && canonical_candidate_only
                && receipt_exact;
        }
        UlCrossAgentRole::Treatment => {
            let reader: UlCrossAgentReaderOutput = serde_json::from_value(output.clone())
                .with_context(|| format!("decode {} reader output contract", call.case_id))?;
            let write_id =
                WriteId::from_str(writer_write_id).context("parse treatment writer write_id")?;
            let expected_handle = format!("claim:{write_id}");
            let receipts = store
                .load_injection_receipts(project_id, call.session_id)
                .await?;
            verification.injection_receipt_ids = receipts
                .iter()
                .map(|receipt| receipt.injection_id.clone())
                .collect();
            let traces = store
                .observability_records_by_kind::<MemoryInfluenceTrace>(
                    project_id,
                    Some(call.task_id),
                    ObservabilityKind::MemoryInfluenceTrace,
                )
                .await?;
            let expected_session = AgentSessionId::from_uuid(call.session_id.as_uuid());
            let matching_trace = traces.iter().find(|trace| {
                trace.task_id == call.task_id
                    && trace.session_id == expected_session
                    && trace.memory_handle == expected_handle
                    && matches!(
                        trace.influence_class,
                        MemoryInfluenceClass::SeenButNotUsed
                            | MemoryInfluenceClass::UsedAndChangedAction
                    )
                    && (trace.influence_class != MemoryInfluenceClass::UsedAndChangedAction
                        || trace
                            .downstream_outcome_ref
                            .as_deref()
                            .is_some_and(|reference| !reference.trim().is_empty()))
            });
            verification.treatment_received_exact_handle = receipts.iter().any(|receipt| {
                receipt.session_id == call.session_id
                    && receipt.task_id == Some(call.task_id)
                    && receipt.item_ref == expected_handle
                    && !receipt.outcome.to_ascii_lowercase().contains("suppress")
                    && treatment_surface_matches_canonical_evidence(
                        reader.delivery_surface.as_deref(),
                        receipt.surface.as_str(),
                        matching_trace.map(|trace| trace.packet_id.as_str()),
                    )
            });
            let influence_receipt = if let Some(value) = reader.influence_receipt.as_deref() {
                let write_id = WriteId::from_str(value)
                    .context("parse treatment influence receipt write_id")?;
                Some((write_id, store.observability_receipt(write_id).await?))
            } else {
                None
            };
            if let Some((_, Some(receipt))) = influence_receipt.as_ref() {
                verification
                    .influence_record_ids
                    .push(receipt.record_id.clone());
            }
            verification.influence_receipt_exact = matching_trace.is_some()
                && influence_receipt.as_ref().is_some_and(|(_, receipt)| {
                    receipt.as_ref().is_some_and(|receipt| {
                        receipt.project_id == project_id
                            && receipt.task_id == Some(call.task_id)
                            && receipt.kind == ObservabilityKind::MemoryInfluenceTrace
                            && matches!(
                                receipt.status,
                                ObservabilityWriteStatus::Committed
                                    | ObservabilityWriteStatus::IdempotentReplay
                            )
                            && receipt.rejected_reason.is_none()
                    })
                });
        }
        UlCrossAgentRole::MemoryFreeControl => {
            let _: UlCrossAgentReaderOutput = serde_json::from_value(output.clone())
                .with_context(|| format!("decode {} reader output contract", call.case_id))?;
            let receipts = store
                .load_injection_receipts(project_id, call.session_id)
                .await?;
            verification.injection_receipt_ids = receipts
                .iter()
                .map(|receipt| receipt.injection_id.clone())
                .collect();
            let traces = store
                .observability_records_by_kind::<MemoryInfluenceTrace>(
                    project_id,
                    Some(call.task_id),
                    ObservabilityKind::MemoryInfluenceTrace,
                )
                .await?;
            verification.memory_free_zero_injections = receipts.is_empty() && traces.is_empty();
        }
        UlCrossAgentRole::PrewriteControl => {
            let _: UlCrossAgentReaderOutput = serde_json::from_value(output.clone())
                .with_context(|| format!("decode {} reader output contract", call.case_id))?;
        }
    }
    Ok(verification)
}

fn reader_prompt(call: &eliot_types::UlCrossAgentPlannedCall, project_id: ProjectId) -> String {
    let semantic = match call.direction {
        UlCrossAgentDirection::A => READER_PROMPT_ALPHA,
        UlCrossAgentDirection::B => READER_PROMPT_BETA,
    };
    let memory_boundary = match call.memory_mode {
        UlCrossAgentMemoryMode::MemoryFreeControl => {
            "This is the pre-registered memory_free_control arm. Do not call recall_l0, fetch_l2, compile_packet_l3, or memory_influence_trace. If you inspect current state, its scope must be memory_free_control. No reusable memory handle may be exposed."
        }
        UlCrossAgentMemoryMode::Treatment => {
            "Use the normal governed ELIOT retrieval path for this certification project. Start with recall_l0 using the inspected file path as the query; if it returns a relevant handle, fetch that exact handle before acknowledging influence. That exact fetch establishes the same-session retrieval context required by the minimal influence acknowledgement."
        }
        _ => "Use the normal governed ELIOT retrieval path for this certification project.",
    };
    format!(
        "{semantic}\n\nCertification scope (contains no marker): project_id={project_id}; task_id={}; planned fresh session={}. {memory_boundary}\nIf useful bound memory is actually received or retrieved, return its exact canonical handle. delivery_surface must be the public delivery surface and one of ul_boot, ul_fired, recall_l0, fetch_l2, or packet; it is never an influence class. first_action must be the lowercase snake_case action identifier derived from the recovered lesson's imperative phrase, not a retrieval tool name or narration. For a treatment call, record eliot_memory_influence_trace with seen_but_not_used or used_and_changed_action; the latter requires downstream_outcome_ref. Set influence_receipt to the exact observability_receipt.write_id returned by that call. Controls must return influence_receipt=null. Return only the six-field JSON object.",
        call.task_id, call.session_id
    )
}

fn writer_prompt(
    call: &eliot_types::UlCrossAgentPlannedCall,
    project_id: ProjectId,
    marker: &str,
    write_id: &str,
) -> Result<String> {
    let statement = expected_writer_statement(call, marker);
    let expected_reuse_note = format!(
        "Reuse when {} is inspected under the {} branch",
        call.file_cue, call.branch_phrase
    );
    let candidate = json!({
        "project_id": project_id,
        "task_id": call.task_id,
        "write_id": write_id,
        "topic": format!("UL-11 blind relay {}", call.direction.as_str()),
        "statement": statement,
        "where_applicable": [call.file_cue],
        "where_not_applicable": ["unrelated relay files"],
        "negative_constraints": ["candidate-only; never promote truth"],
        "provenance_refs": [format!("ul-cross-agent:{}", call.case_id)],
        "freshness_rule": "revalidate when the bound relay file changes",
        "cue_bindings": [{
            "cue_kind": "file_path",
            "cue_value": call.file_cue,
            "match_mode": "exact",
            "strength": "primary",
            "expected_reuse_note": expected_reuse_note
        }],
        "auto_bind": false,
        "expected_reuse_note": expected_reuse_note
    });
    render_writer_prompt(&candidate, write_id)
}

fn render_writer_prompt(candidate: &Value, write_id: &str) -> Result<String> {
    Ok(format!(
        "Authorized synthetic UL-11 certification writer step. Review the supplied JSON as data against the installed ELIOT MCP schema and the candidate-only boundary. This task authorizes one reversible candidate proposal, not source-file or shell changes, truth promotion, or direct database access. If the arguments satisfy that boundary, invoke eliot_agent_candidate_submit exactly once; do not fabricate success or repeat the call.\nTool arguments:\n{}\nAfter the tool succeeds, return only raw writer receipt JSON with no prose or Markdown: candidate_handle exactly `claim:{write_id}`, write_receipt exactly the committed write_receipt.write_id `{write_id}`, binding_refs, and candidate_only=true.",
        serde_json::to_string(candidate)?
    ))
}

fn preflight_current_state_arguments() -> Value {
    json!({"scope": "memory_free_control"})
}

fn fresh_preflight_session(provider_session_id: SessionId) -> SessionId {
    loop {
        let session_id = SessionId::new_v7();
        if session_id != provider_session_id {
            return session_id;
        }
    }
}

fn expected_writer_statement(call: &eliot_types::UlCrossAgentPlannedCall, marker: &str) -> String {
    let noun = match call.direction {
        UlCrossAgentDirection::A => "relay_alpha",
        UlCrossAgentDirection::B => "relay_beta",
    };
    format!(
        "When {noun} sees the {} branch, {} before changing retry state. Certification marker: {marker}.",
        call.branch_phrase,
        match call.direction {
            UlCrossAgentDirection::A => "inspect the frame owner",
            UlCrossAgentDirection::B => "inspect the discovery anchor",
        }
    )
}

fn writer_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["candidate_handle", "write_receipt", "binding_refs", "candidate_only"],
        "properties": {
            "candidate_handle": {"type": "string"},
            "write_receipt": {"type": "string"},
            "binding_refs": {"type": "array", "items": {"type": "string"}},
            "candidate_only": {"const": true}
        }
    })
}

fn direction_evidence(
    calls: &[CallArchive],
    direction: UlCrossAgentDirection,
    marker: &str,
) -> UlCrossAgentDirectionEvidence {
    let prefix = direction.as_str();
    let reader = |suffix: &str| {
        calls
            .iter()
            .find(|call| call.case_id == format!("{prefix}{suffix}"))
            .and_then(|call| call.structured_output.clone())
            .and_then(|value| serde_json::from_value::<UlCrossAgentReaderOutput>(value).ok())
    };
    let writer_call = calls
        .iter()
        .find(|call| call.case_id == format!("{prefix}1"));
    let canonical_handle =
        writer_call.and_then(|call| call.canonical_verification.candidate_handle.as_deref());
    let treatment_call = calls
        .iter()
        .find(|call| call.case_id == format!("{prefix}2"));
    let memory_free_call = calls
        .iter()
        .find(|call| call.case_id == format!("{prefix}3"));
    let prewrite = reader("0");
    let treatment = reader("2");
    let memory_free = reader("3");
    let expected_action = match direction {
        UlCrossAgentDirection::A => "inspect_frame_owner",
        UlCrossAgentDirection::B => "inspect_discovery_anchor",
    };
    let revisions_are_exact = calls
        .iter()
        .filter(|call| call.case_id.starts_with(prefix))
        .all(
            |call| match (call.revision_before, call.revision_after, call.role) {
                (Some(before), Some(after), UlCrossAgentRole::Writer) => after == before + 1,
                (Some(before), Some(after), _) => after == before,
                _ => false,
            },
        );
    let contamination_clear = calls
        .iter()
        .filter(|call| call.case_id.starts_with(prefix))
        .filter_map(|call| call.contamination.as_ref())
        .all(|receipt| receipt.passed);
    let treatment_exact = treatment
        .as_ref()
        .is_some_and(|output| output.marker.as_deref() == Some(marker));
    let treatment_handle_exact = treatment.as_ref().is_some_and(|output| {
        writer_call
            .and_then(|call| call.canonical_verification.candidate_handle.as_deref())
            .is_some_and(|handle| output.memory_handle.as_deref() == Some(handle))
    });
    let no_cross_scope_leakage = prewrite
        .as_ref()
        .is_some_and(|output| output.marker.is_none() && output.memory_handle.is_none())
        && memory_free.as_ref().is_some_and(|output| {
            output.marker.is_none()
                && canonical_handle
                    .is_none_or(|handle| output.memory_handle.as_deref() != Some(handle))
        })
        && writer_call.is_some_and(|call| call.canonical_verification.candidate_session_exact)
        && memory_free_call
            .is_some_and(|call| call.canonical_verification.memory_free_zero_injections);
    UlCrossAgentDirectionEvidence {
        direction,
        prewrite_control_marker_absent: prewrite
            .as_ref()
            .is_some_and(|output| output.marker.is_none()),
        writer_canonical_write_succeeded: writer_call
            .is_some_and(|call| call.canonical_verification.candidate_exact),
        writer_memory_has_exact_cue: writer_call
            .is_some_and(|call| call.canonical_verification.candidate_exact),
        treatment_recovered_exact_marker: treatment_exact,
        treatment_named_exact_handle: treatment_handle_exact
            && treatment_call
                .is_some_and(|call| call.canonical_verification.treatment_received_exact_handle),
        treatment_used_allowed_delivery_surface: treatment
            .as_ref()
            .is_some_and(UlCrossAgentReaderOutput::uses_allowed_delivery_surface)
            && treatment_call
                .is_some_and(|call| call.canonical_verification.treatment_received_exact_handle),
        treatment_applicability_exact: treatment
            .as_ref()
            .is_some_and(|output| output.applicability == "applicable"),
        treatment_first_action_exact: treatment
            .as_ref()
            .is_some_and(|output| output.first_action.as_deref() == Some(expected_action)),
        treatment_has_valid_influence_receipt: treatment_call
            .is_some_and(|call| call.canonical_verification.influence_receipt_exact),
        memory_free_control_marker_absent: memory_free
            .as_ref()
            .is_some_and(|output| output.marker.is_none())
            && memory_free_call
                .is_some_and(|call| call.canonical_verification.memory_free_zero_injections),
        no_input_contamination: contamination_clear,
        no_cross_scope_leakage,
        truth_revision_changed_only_for_candidate: revisions_are_exact,
        candidate_stayed_candidate_only: writer_call
            .is_some_and(|call| call.canonical_verification.candidate_stayed_candidate_only),
    }
}

fn scan_reader_authority(
    source_root: &Path,
    repo: &Path,
    marker: &str,
    prompt: &str,
    output_contract: &[u8],
    call: &eliot_types::UlCrossAgentPlannedCall,
    project_id: ProjectId,
) -> Result<UlCrossAgentContaminationReceipt> {
    let mut owned = vec![
        ("reader_prompt".to_owned(), prompt.as_bytes().to_vec()),
        ("output_contract".to_owned(), output_contract.to_vec()),
        (
            "reader_governor_scope".to_owned(),
            format!(
                "project_id={project_id}\ntask_id={}\nsession_id={}\nhost={}\nprofile={}",
                call.task_id,
                call.session_id,
                call.host.as_str(),
                if call.host == AgentHostId::Antigravity {
                    "external_auditor"
                } else {
                    "claude_governed"
                }
            )
            .into_bytes(),
        ),
    ];
    collect_regular_files(repo, "fixture_repo", &mut owned)?;
    let integration = source_root
        .join("integrations")
        .join(if call.host == AgentHostId::Claude {
            "claude"
        } else {
            "antigravity"
        });
    if integration.is_dir() {
        collect_regular_files(&integration, "provider_bundle", &mut owned)?;
    }
    if call.host == AgentHostId::Antigravity
        && let Some(user_profile) = std::env::var_os("USERPROFILE")
    {
        let installed_plugin = PathBuf::from(user_profile)
            .join(".gemini")
            .join("config")
            .join("plugins")
            .join("eliot-antigravity");
        if installed_plugin.is_dir() {
            collect_regular_files(&installed_plugin, "installed_provider_bundle", &mut owned)?;
        }
    }
    let environment = std::env::vars()
        .map(|(name, value)| format!("{name}={value}\0"))
        .collect::<String>();
    owned.push(("reader_environment".to_owned(), environment.into_bytes()));
    let git_history = Command::new("git")
        .current_dir(repo)
        .args(["log", "-p", "--all"])
        .output()?;
    if !git_history.status.success() {
        bail!("read fixture Git history for contamination scan");
    }
    owned.push(("fixture_git_history".to_owned(), git_history.stdout));
    Ok(scan_ul_cross_agent_reader_inputs(
        marker,
        owned
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice())),
    ))
}

fn collect_regular_files(
    root: &Path,
    label: &str,
    output: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!("UL cross-agent scan rejects symlink {}", path.display());
        }
        if file_type.is_dir() {
            if entry.file_name() != ".git" {
                collect_regular_files(&path, label, output)?;
            }
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            output.push((
                format!("{label}:{}", relative.to_string_lossy()),
                fs::read(&path)?,
            ));
        }
    }
    Ok(())
}

fn create_fixture_repo(source_root: &Path, config_path: &Path, repo: &Path) -> Result<()> {
    let template = source_root.join("tests/cognitive/ul-cross-agent/fixture-template");
    if repo.exists() {
        bail!("UL cross-agent fixture repository already exists");
    }
    copy_tree(&template, repo)?;
    write_antigravity_workspace_mcp(config_path, repo)?;
    run_git(repo, ["init"])?;
    run_git(repo, ["config", "user.name", "ELIOT UL Certification"])?;
    run_git(
        repo,
        ["config", "user.email", "eliot-certification@localhost"],
    )?;
    run_git(repo, ["add", "."])?;
    run_git(repo, ["commit", "-m", "UL-11 isolated fixture baseline"])?;
    let status = run_git(repo, ["status", "--porcelain"])?;
    if !status.trim().is_empty() {
        bail!("UL cross-agent fixture worktree is not clean");
    }
    Ok(())
}

fn write_antigravity_workspace_mcp(config_path: &Path, repo: &Path) -> Result<()> {
    let agents_root = repo.join(".agents");
    fs::create_dir_all(&agents_root)?;
    let governor_executable = subprocess_path(&std::env::current_exe()?);
    atomic_write_json(
        &agents_root.join("mcp_config.json"),
        &json!({
            "mcpServers": {
                "eliot-governor": {
                    "command": governor_executable,
                    "args": [
                        "--config",
                        config_path,
                        "mcp",
                        "stdio",
                        "--host",
                        "antigravity",
                        "--profile",
                        "external_auditor",
                        "--instance",
                        "default"
                    ]
                }
            }
        }),
    )
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!("fixture template must not contain symlinks");
        }
        if file_type.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(source_path, destination_path)?;
        }
    }
    Ok(())
}

fn run_git<I, S>(cwd: &Path, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git").current_dir(cwd).args(args).output()?;
    if !output.status.success() {
        bail!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn load_suite(source_root: &Path) -> Result<UlCrossAgentSuite> {
    let path = source_root.join("tests/cognitive/ul-cross-agent/suite.json");
    let suite: UlCrossAgentSuite = serde_json::from_slice(&fs::read(path)?)?;
    suite.validate().map_err(anyhow::Error::msg)?;
    Ok(suite)
}

fn validate_reader_output_contract(path: &Path) -> Result<()> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    if value.get("type").and_then(Value::as_str) != Some("object")
        || value.get("additionalProperties").and_then(Value::as_bool) != Some(false)
        || value
            .get("properties")
            .and_then(Value::as_object)
            .map(serde_json::Map::len)
            != Some(6)
    {
        bail!("UL cross-agent reader output contract is invalid");
    }
    Ok(())
}

fn route(host: AgentHostId) -> Result<UlReasoningRoute> {
    match host {
        AgentHostId::Claude => Ok(UlReasoningRoute::Claude),
        AgentHostId::Antigravity => Ok(UlReasoningRoute::Antigravity),
        _ => bail!("UL cross-agent suite supports only Claude and Antigravity"),
    }
}

fn provider_model(host: AgentHostId) -> Result<&'static str> {
    match host {
        AgentHostId::Claude => Ok(CLAUDE_UL_MODEL),
        AgentHostId::Antigravity => Ok(ANTIGRAVITY_UL_MODEL),
        _ => bail!("UL cross-agent suite supports only Claude and Antigravity"),
    }
}

fn random_marker() -> String {
    format!("ULX-{}", uuid::Uuid::new_v4().simple())
}

fn report_markdown(report: &UlCrossAgentReport) -> String {
    format!(
        "# UL-11 blind reciprocal memory certification\n\n- Run: `{}`\n- Project: `{}`\n- Provider calls: `{}/{}`\n- Claude to Antigravity: `{}`\n- Antigravity to Claude: `{}`\n- Global result: `{}`\n- Unknown outcomes: `{}`\n- Known provider issue: Claude Code previously safety-refused the legacy writer wording before tool use; the operator-authorized synthetic wording is tracked as a regression fix.\n- Known provider issue: Antigravity previously returned bounded non-JSON output before tool use; because raw prose was not retained, the cause remains unclassified rather than being labeled a refusal.\n\nThis report is sanitized: hidden markers, private writer prompts, and provider credentials are not included.\n",
        report.run_id,
        report.project_id,
        report.provider_call_count,
        report.hard_provider_call_cap,
        if report.direction_a.passed {
            "PASS"
        } else {
            "FAIL"
        },
        if report.direction_b.passed {
            "PASS"
        } else {
            "FAIL"
        },
        if report.passed { "PASS" } else { "FAIL" },
        report.unknown_outcome_calls.len(),
    )
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn path_starts_with(path: &Path, root: &Path) -> bool {
    let path = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let root = root
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    path == root || path.starts_with(&format!("{}/", root.trim_end_matches('/')))
}

fn subprocess_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    value.strip_prefix(r"\\?\").unwrap_or(&value).to_owned()
}

fn error_reports_provider_dispatched(error: &str) -> bool {
    error.to_ascii_lowercase().contains("provider dispatched:")
}

fn error_reports_unknown_outcome(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("unknown outcome")
        || error.contains("outcome is unknown")
        || error.contains("unknown_outcome")
        || error.contains("timed out")
}

fn source_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .context("resolve ELIOT source root")
}

fn certification_root() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not set")?;
    Ok(PathBuf::from(local)
        .join("Eliot")
        .join("certification")
        .join("ul-cross-agent"))
}

fn validate_run_id(run_id: &str) -> Result<()> {
    if !run_id.starts_with("ul-cross-agent-")
        || run_id.len() > 96
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("cross-agent run_id is not a safe certification directory name");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        auditor_mcp_profile, error_reports_provider_dispatched, error_reports_unknown_outcome,
        fresh_preflight_session, preflight_current_state_arguments, provider_doctor_selector,
        provider_model, reader_prompt, render_writer_prompt, subprocess_path,
        treatment_surface_matches_canonical_evidence, validate_run_id,
        write_antigravity_workspace_mcp,
    };
    use eliot_types::{
        AgentHostId, SessionId, TaskId, UlCrossAgentDirection, UlCrossAgentMemoryMode,
        UlCrossAgentPlannedCall, UlCrossAgentRole,
    };
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn powershell_subprocess_path_strips_windows_extended_prefix() {
        assert_eq!(
            subprocess_path(Path::new(
                r"\\?\C:\Users\fixture\AppData\Local\Eliot\eliot-governor.exe"
            )),
            r"C:\Users\fixture\AppData\Local\Eliot\eliot-governor.exe"
        );
        assert_eq!(
            subprocess_path(Path::new(r"C:\Eliot\eliot-governor.exe")),
            r"C:\Eliot\eliot-governor.exe"
        );
    }

    #[test]
    fn receipt_inspection_accepts_only_safe_run_ids() {
        assert!(validate_run_id("ul-cross-agent-019fa36e-3c6b-74c1-9365-3f62bad6c3fe").is_ok());
        for invalid in [
            "../ul-cross-agent-run",
            r"ul-cross-agent-..\run",
            "ul-cross-agent-run.json",
            "other-run",
        ] {
            assert!(validate_run_id(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn provider_dispatch_classification_ignores_timeout_option_names() {
        let predispatch =
            "--idempotency-key and --timeout-seconds are currently managed for Antigravity only";
        assert!(!error_reports_provider_dispatched(predispatch));
        assert!(!error_reports_unknown_outcome(predispatch));

        let unknown =
            "provider dispatched: antigravity exceeded the wall-clock budget; outcome is unknown";
        assert!(error_reports_provider_dispatched(unknown));
        assert!(error_reports_unknown_outcome(unknown));
    }

    #[test]
    fn public_delivery_surfaces_are_bound_to_canonical_evidence() {
        assert!(treatment_surface_matches_canonical_evidence(
            Some("ul_boot"),
            "mcp_auto_boot",
            None
        ));
        assert!(treatment_surface_matches_canonical_evidence(
            Some("ul_fired"),
            "mcp_response_piggyback",
            None
        ));
        assert!(treatment_surface_matches_canonical_evidence(
            Some("fetch_l2"),
            "mcp_response_piggyback",
            Some("retrieval:0123456789abcdef")
        ));
        assert!(!treatment_surface_matches_canonical_evidence(
            Some("fetch_l2"),
            "mcp_response_piggyback",
            Some("packet:0123456789abcdef")
        ));
        assert!(treatment_surface_matches_canonical_evidence(
            Some("packet"),
            "mcp_response_piggyback",
            Some("packet:0123456789abcdef")
        ));
        assert!(!treatment_surface_matches_canonical_evidence(
            Some("ul_fired"),
            "unknown_surface",
            None
        ));
    }

    #[test]
    fn certification_provider_evidence_uses_the_claude_code_surface() {
        assert_eq!(
            provider_doctor_selector(AgentHostId::Claude),
            "claude_code_plugin"
        );
        assert_eq!(auditor_mcp_profile(AgentHostId::Claude), "claude_governed");
        assert_eq!(
            auditor_mcp_profile(AgentHostId::Antigravity),
            "external_auditor"
        );
    }

    #[test]
    fn certification_pins_opus_models_for_both_providers() {
        assert_eq!(
            provider_model(AgentHostId::Claude).expect("Claude model route"),
            "opus"
        );
        assert_eq!(
            provider_model(AgentHostId::Antigravity).expect("Antigravity model route"),
            "claude-opus-4-6-thinking"
        );
    }

    #[test]
    fn writer_prompt_records_authorization_without_legacy_refusal_wording() {
        let prompt = render_writer_prompt(
            &json!({
                "write_id": "019f0000-0000-7000-8000-000000000000",
                "candidate_only": true
            }),
            "019f0000-0000-7000-8000-000000000000",
        )
        .expect("writer prompt");
        assert!(prompt.contains("Authorized synthetic UL-11 certification writer step"));
        assert!(prompt.contains("eliot_agent_candidate_submit exactly once"));
        assert!(prompt.contains("one reversible candidate proposal"));
        assert!(prompt.contains("not source-file or shell changes, truth promotion"));
        assert!(prompt.contains("only raw writer receipt JSON with no prose or Markdown"));
        assert!(!prompt.contains("Private UL-11 writer call"));
    }

    #[test]
    fn full_call_preflight_is_isolated_and_reader_contract_stays_blind() {
        let provider_session = SessionId::new_v7();
        let preflight_session = fresh_preflight_session(provider_session);
        assert_ne!(preflight_session, provider_session);
        assert_eq!(
            preflight_current_state_arguments(),
            json!({"scope": "memory_free_control"})
        );

        let treatment = UlCrossAgentPlannedCall {
            call_number: 3,
            case_id: "A2".to_owned(),
            direction: UlCrossAgentDirection::A,
            host: AgentHostId::Antigravity,
            role: UlCrossAgentRole::Treatment,
            memory_mode: UlCrossAgentMemoryMode::Treatment,
            task_id: TaskId::new_v7(),
            session_id: provider_session,
            file_cue: "src/relay_alpha.rs".to_owned(),
            branch_phrase: "FROST-17".to_owned(),
            expected_first_action: "inspect_frame_owner".to_owned(),
            marker_visible_to_provider: false,
        };
        let prompt = reader_prompt(
            &treatment,
            "00000000-0000-0000-0000-000000000001"
                .parse()
                .expect("project id"),
        );
        for surface in ["ul_boot", "ul_fired", "recall_l0", "fetch_l2", "packet"] {
            assert!(prompt.contains(surface));
        }
        assert!(prompt.contains("it is never an influence class"));
        assert!(prompt.contains("lowercase snake_case action identifier"));
        assert!(!prompt.contains("inspect_frame_owner"));
        assert!(!prompt.contains("ULX-"));
        assert!(!prompt.contains("claim:"));

        let mut memory_free = treatment;
        memory_free.role = UlCrossAgentRole::MemoryFreeControl;
        memory_free.memory_mode = UlCrossAgentMemoryMode::MemoryFreeControl;
        let memory_free_prompt = reader_prompt(
            &memory_free,
            "00000000-0000-0000-0000-000000000001"
                .parse()
                .expect("project id"),
        );
        assert!(memory_free_prompt.contains("Do not call recall_l0, fetch_l2"));
        assert!(memory_free_prompt.contains("scope must be memory_free_control"));
    }

    #[test]
    fn certification_repo_has_one_workspace_scoped_antigravity_mcp() {
        let root = std::env::temp_dir().join(format!(
            "eliot-ul11r3-workspace-mcp-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create fixture root");
        let config = root.join("governor.toml");
        write_antigravity_workspace_mcp(&config, &root).expect("write workspace MCP config");
        let value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join(".agents/mcp_config.json")).expect("read MCP config"),
        )
        .expect("parse MCP config");
        let servers = value["mcpServers"].as_object().expect("mcpServers object");
        assert_eq!(servers.len(), 1);
        let eliot = &servers["eliot-governor"];
        assert_eq!(
            eliot["args"],
            json!([
                "--config",
                config,
                "mcp",
                "stdio",
                "--host",
                "antigravity",
                "--profile",
                "external_auditor",
                "--instance",
                "default"
            ])
        );
        assert!(
            !root
                .join(".gemini/antigravity-cli/mcp_config.json")
                .exists()
        );
        assert!(!root.join(".agents/agents").exists());
        std::fs::remove_dir_all(root).expect("remove fixture root");
    }
}
