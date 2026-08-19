//! The tools and prompts the Governor exposes over MCP.
//!
//! This is the single catalog: the live server answers `tools/list` and
//! `prompts/list` from it, and package manifests are generated from it rather
//! than transcribed, so a hand-maintained second copy cannot drift away from
//! what is actually served.

use super::{
    BOUND_PROJECT_DEFAULT_TOOLS, BOUND_TASK_DEFAULT_TOOLS, McpAccessProfile, READ_ONLY_TOOLS,
    action_lease_status_schema, action_plan_schema, agent_candidate_schema, blackboard_ack_schema,
    blackboard_add_schema, codecortex_scan_schema, cognitive_record_schema, compile_packet_schema,
    json_schema, mailbox_ack_schema, mailbox_send_schema, memory_influence_trace_schema,
    observe_schema, patch_apply_schema, tool, understanding_proof_schema, work_claim_schema,
    work_create_schema, work_lease_schema, work_status_schema, worktree_create_schema,
    worktree_lease_schema, worktree_review_schema, worktree_status_schema,
};
use anyhow::{Context as _, Result};
use eliot_types::{ClaudeSurface, ProviderMcpToolProfileBinding};
use serde_json::{Value, json};

pub(super) fn prompt_definitions() -> Vec<Value> {
    vec![
        prompt_definition(
            "eliot-start",
            "Start or resume a material task through the live Eliot task cycle.",
        ),
        prompt_definition(
            "eliot-understand",
            "Build decision-sufficient understanding from current truth and exact evidence.",
        ),
        prompt_definition(
            "eliot-delegate",
            "Delegate or accept one bounded, role-leased Eliot work item.",
        ),
        prompt_definition(
            "eliot-finish",
            "Verify current artifacts and submit an honest completion proof.",
        ),
    ]
}

fn prompt_definition(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "description": description,
        "arguments": [
            {
                "name": "task",
                "description": "Optional concise task goal or task identifier.",
                "required": false
            }
        ]
    })
}

pub(super) fn prompt_get(params: &Value) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .context("prompts/get params.name is required")?;
    let task = params
        .get("arguments")
        .and_then(|arguments| arguments.get("task"))
        .and_then(Value::as_str)
        .unwrap_or("the active task")
        .trim();
    let text = prompt_text(name, task)?;
    Ok(json!({
        "description": prompt_definitions()
            .into_iter()
            .find(|prompt| prompt.get("name").and_then(Value::as_str) == Some(name))
            .and_then(|prompt| prompt.get("description").cloned())
            .unwrap_or(Value::Null),
        "messages": [
            {
                "role": "user",
                "content": { "type": "text", "text": text }
            }
        ]
    }))
}

fn prompt_text(name: &str, task: &str) -> Result<String> {
    let text = match name {
        "eliot-start" => format!(
            "Start or resume {task}. Call eliot_host_session_status, resolve the stable project identity, read current task/current state, and compile only the smallest packet needed. Confirm the task-scoped role and revision before any material action."
        ),
        "eliot-understand" => format!(
            "For {task}, separate current verified truth from supported, assumed, conflicted, stale, and unknown state. Expand exact handles, check negative memory, trace goal -> owner -> symbol or artifact -> observable -> verifier, then submit an UnderstandingProof or run the cheapest discriminative probe."
        ),
        "eliot-delegate" => format!(
            "For {task}, confirm that delegation has positive value and that the current session has the required task-scoped role. Delegate one bounded work item with exact acceptance, packet refs, expected result, verifier, leases, and an idempotency key; reconcile unknown outcomes before retrying."
        ),
        "eliot-finish" => format!(
            "For {task}, read exact finish gaps, run mapped verifiers against the accepted artifact scope, account for every acceptance item, and submit CompletionProof with the honest status. A model response is candidate evidence, not a verifier."
        ),
        other => anyhow::bail!("unknown Eliot prompt: {other}"),
    };
    Ok(text)
}

pub(super) fn tool_definitions() -> Vec<Value> {
    let mut tools = task_tool_definitions();
    tools.extend(core_tool_definitions());
    tools.extend(external_review_tool_definitions());
    tools.extend(agent_broker_tool_definitions());
    tools.extend(delegation_tool_definitions());
    tools.extend(delegation_calibration_tool_definitions());
    tools.extend(antigravity_tool_definitions());
    tools.extend(eval_tool_definitions());
    tools.extend(verification_tool_definitions());
    tools.extend(metrics_tool_definitions());
    tools.extend(replay_tool_definitions());
    tools.extend(action_tool_definitions());
    tools.extend(patch_tool_definitions());
    tools.extend(work_tool_definitions());
    tools.extend(worktree_tool_definitions());
    tools.extend(collective_tool_definitions());
    tools.extend(runtime_tool_definitions());
    tools.extend(service_tool_definitions());
    tools.extend(adapter_tool_definitions());
    tools.extend(recovery_report_tool_definitions());
    tools.extend(memory_lifecycle_tool_definitions());
    tools.extend(skill_tool_definitions());
    tools.extend(skill_curator_tool_definitions());
    tools.extend(operator_tool_definitions());
    tools
}

#[allow(clippy::too_many_lines)]
fn operator_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_operator_contract",
            "Eliot Operator Contract",
            "Return the canonical versioned operator protocol manifest and hash.",
            &json!({"type": "object", "additionalProperties": false}),
        ),
        tool(
            "eliot_operator_snapshot",
            "Eliot Operator Snapshot",
            "Return bounded Governor-produced operator projections, optionally focused on one canonical task.",
            &json_schema(&[("project_id", "string"), ("task_id", "string")], &[]),
        ),
        tool(
            "eliot_operator_query",
            "Eliot Operator Semantic Query",
            "Return one server-bounded page from a typed Governor projection; never raw SQL or arbitrary JSON editing.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "projection": {"type": "string", "enum": [
                        "overview", "tasks_work", "task_cognition", "memory_explorer",
                        "causal_provenance", "schema_contracts", "query_lab",
                        "experience_skills", "sleep_meta", "agents_routing",
                        "autonomy", "approvals", "timeline_operations"
                    ]},
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "query_operation": {
                        "type": "string",
                        "enum": [
                            "current_state", "recall_preview", "exact_evidence",
                            "relationship_slice", "trace_replay", "health_report"
                        ]
                    },
                    "query_parameters": {"type": "object"},
                    "result_mode": {
                        "type": "string",
                        "enum": ["human", "json", "graph"]
                    },
                    "selected_ref": {"type": "string"},
                    "expand_depth": {"type": "integer", "minimum": 1, "maximum": 3},
                    "filter": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "search": {"type": "string"},
                            "record_kind": {"type": "string"},
                            "status": {"type": "string"},
                            "lifecycle": {"type": "string"},
                            "authority": {"type": "string"},
                            "observed_after": {"type": "string"},
                            "observed_before": {"type": "string"}
                        }
                    },
                    "cursor": {"type": "string"},
                    "page_size": {"type": "integer", "minimum": 1, "maximum": 100}
                },
                "required": ["projection", "page_size"]
            }),
        ),
        tool(
            "eliot_operator_command",
            "Eliot Operator Command",
            "Submit one typed operator command with an expected canonical task revision.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 256},
                    "command": {"type": "object"},
                    "route_decision": {"type": "object"},
                    "route_context": {"type": "object"}
                },
                "required": ["project_id", "task_id", "expected_revision", "idempotency_key", "command"]
            }),
        ),
        tool(
            "eliot_procedure_candidate_create",
            "Eliot Procedure Candidate Create",
            "Persist one exact task-scoped candidate SkillCard bound to a canonical ExperiencePattern; this never activates the skill.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 256},
                    "pattern_ref": {"type": "string", "pattern": "^experience-pattern:.+$"},
                    "candidate_skill": {"type": "object"}
                },
                "required": [
                    "project_id", "task_id", "expected_revision", "idempotency_key",
                    "pattern_ref", "candidate_skill"
                ]
            }),
        ),
        tool(
            "eliot_procedure_candidate_disposition",
            "Eliot Procedure Candidate Disposition",
            "Evaluate one exact canonical procedure SkillCard against its canonical ExperiencePattern and current task evidence; persist the disposition without activating the skill.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 256},
                    "pattern_ref": {"type": "string", "pattern": "^experience-pattern:.+$"},
                    "candidate_ref": {"type": "string", "pattern": "^skill:.+$"},
                    "holdout_evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "resource_ref": {"type": "string", "minLength": 1},
                                "content_hash": {"type": "string", "minLength": 64}
                            },
                            "required": ["resource_ref", "content_hash"]
                        }
                    },
                    "negative_transfer_refs": {
                        "type": "array", "items": {"type": "string"}
                    }
                },
                "required": [
                    "project_id", "task_id", "expected_revision", "idempotency_key",
                    "pattern_ref", "candidate_ref", "holdout_evidence",
                    "negative_transfer_refs"
                ]
            }),
        ),
        tool(
            "eliot_contour_route_preview",
            "Eliot Contour Route Preview",
            "Resolve effective contour routing through system, project, and task policy without widening stronger policy.",
            &json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "work_item_id": {"type": "string"},
                    "contour": {"type": "string"},
                    "policies": {"type": "array", "items": {"type": "object"}},
                    "live_routes": {"type": "array", "items": {"type": "object"}}
                },
                "required": ["project_id", "task_id", "work_item_id", "contour", "policies", "live_routes"]
            }),
        ),
        tool(
            "eliot_autonomy_contract_write",
            "Eliot Autonomy Contract Write",
            "Validate and durably write one bounded autonomy contract through WriterActor.",
            &json!({
                "type": "object",
                "properties": {"contract": {"type": "object"}},
                "required": ["contract"]
            }),
        ),
        tool(
            "eliot_autonomy_approval_request",
            "Eliot R3 Approval Request",
            "Bind one exact R3 completion action and current run revisions to the authenticated controller principal.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "autonomy_run_id": {"type": "string"},
                    "expected_state_revision": {"type": "integer", "minimum": 0},
                    "expected_runtime_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "minLength": 1},
                    "completion_proof": {"type": "object"},
                    "reason": {"type": "string", "minLength": 1},
                    "verifier_refs": {"type": "array", "items": {"type": "string"}},
                    "ttl_minutes": {"type": "integer", "minimum": 1, "maximum": 60}
                },
                "required": ["project_id", "task_id", "autonomy_run_id", "expected_state_revision", "expected_runtime_revision", "idempotency_key", "completion_proof", "reason", "verifier_refs", "ttl_minutes"]
            }),
        ),
        tool(
            "eliot_autonomy_approval_decide",
            "Eliot R3 Approval Decision",
            "As HumanOperator, grant or deny one exact unexpired R3 approval request with revision CAS.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "autonomy_run_id": {"type": "string"},
                    "approval_id": {"type": "string"},
                    "expected_approval_revision": {"type": "integer", "minimum": 0},
                    "decision": {"type": "string", "enum": ["granted", "denied"]},
                    "reason": {"type": "string", "minLength": 1},
                    "idempotency_key": {"type": "string", "minLength": 1}
                },
                "required": ["project_id", "task_id", "autonomy_run_id", "approval_id", "expected_approval_revision", "decision", "reason", "idempotency_key"]
            }),
        ),
        tool(
            "eliot_autonomy_transition",
            "Eliot Autonomy Transition",
            "Load the canonical autonomy run and apply one governed state transition.",
            &json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "autonomy_run_id": {"type": "string"},
                    "expected_state_revision": {"type": "integer", "minimum": 0},
                    "target": {"type": "string"},
                    "reason": {"type": "string"},
                    "risk_tier": {"type": "string"},
                    "verifier_refs": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["project_id", "task_id", "autonomy_run_id", "expected_state_revision", "target", "reason", "risk_tier", "verifier_refs"]
            }),
        ),
        tool(
            "eliot_autonomy_runtime_action",
            "Eliot Bounded Autonomy Runtime Action",
            "Rehydrate one canonical bounded run, execute one typed lease/budget/work/recovery/completion action, and persist the resulting canonical runtime records.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "autonomy_run_id": {"type": "string"},
                    "expected_state_revision": {"type": "integer", "minimum": 0},
                    "expected_runtime_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 256},
                    "action": {
                        "type": "object",
                        "properties": {
                            "action": {"type": "string", "enum": [
                                "create_work_plan", "advance", "assign_work", "charge_usage",
                                "complete_work_item", "reassign_work", "record_tripwire",
                                "pause_for_recovery", "resume_after_recovery", "complete_run"
                            ]}
                        },
                        "required": ["action"]
                    }
                },
                "required": [
                    "project_id", "task_id", "autonomy_run_id", "expected_state_revision",
                    "expected_runtime_revision", "idempotency_key", "action"
                ]
            }),
        ),
    ]
}

fn agent_broker_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_agent_delegate",
            "Eliot Agent Delegate",
            "As the active task controller, enqueue bounded work for another role-leased host through the shared Governor broker.",
            &json!({
                "type": "object",
                "properties": {
                    "project_id": { "type": "string" },
                    "task_id": { "type": "string" },
                    "work_item_id": { "type": "string" },
                    "target_host": { "type": "string", "enum": ["codex", "antigravity", "opencode", "claude"] },
                    "target_role_lease_id": { "type": "string" },
                    "work_lease_id": { "type": "string" },
                    "requested_capabilities": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
                    "packet_refs": { "type": "array", "items": { "type": "string" } },
                    "expected_result_kind": { "type": "string" },
                    "verifier_ref": { "type": "string" },
                    "idempotency_key": { "type": "string" }
                },
                "required": ["project_id", "task_id", "work_item_id", "target_host", "target_role_lease_id", "work_lease_id", "requested_capabilities", "expected_result_kind", "verifier_ref", "idempotency_key"]
            }),
        ),
        tool(
            "eliot_agent_job_claim",
            "Eliot Agent Job Claim",
            "Claim a queued broker job as the authenticated target task-role session.",
            &json_schema(&[("invocation_id", "string")], &["invocation_id"]),
        ),
        tool(
            "eliot_agent_job_status",
            "Eliot Agent Job Status",
            "Read one broker invocation, job, candidate result, and its controller dispositions as a task participant.",
            &json_schema(&[("invocation_id", "string")], &["invocation_id"]),
        ),
        tool(
            "eliot_agent_result_submit",
            "Eliot Agent Result Submit",
            "Submit a candidate-only AgentResultEnvelope from the authenticated target task-role session.",
            &json!({
                "type": "object",
                "properties": {
                    "result_id": { "type": "string" },
                    "invocation_id": { "type": "string" },
                    "status": { "type": "string", "enum": ["succeeded", "partial", "blocked", "failed", "timed_out", "unknown_outcome"] },
                    "summary": { "type": "string" },
                    "artifact_refs": { "type": "array", "items": { "type": "string" } },
                    "evidence_refs": { "type": "array", "items": { "type": "string" } },
                    "verifier_refs": { "type": "array", "items": { "type": "string" } },
                    "exit_status": { "type": "integer" },
                    "token_or_cost_telemetry": { "type": "string" },
                    "unknown_outcome_evidence_refs": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["result_id", "invocation_id", "status", "summary"]
            }),
        ),
        tool(
            "eliot_agent_result_finalize",
            "Eliot Agent Result Finalize",
            "Controller-only finalization of an exact managed provider output into a captured CandidateDiff, accepted review, commit-bound AgentResult, and accepted disposition.",
            &json!({
                "type": "object",
                "properties": {
                    "invocation_id": { "type": "string" },
                    "expected_provider_output_hash": { "type": "string" },
                    "idempotency_key": { "type": "string" },
                    "verifier_refs": { "type": "array", "items": { "type": "string" } }
                },
                "required": [
                    "invocation_id",
                    "expected_provider_output_hash",
                    "idempotency_key",
                    "verifier_refs"
                ],
                "additionalProperties": false
            }),
        ),
        tool(
            "eliot_agent_result",
            "Eliot Agent Result",
            "Read one candidate AgentResultEnvelope and controller dispositions as an active task participant.",
            &json_schema(&[("result_id", "string")], &["result_id"]),
        ),
        tool(
            "eliot_agent_result_disposition",
            "Eliot Agent Result Disposition",
            "Accept, reject, or request a probe for a candidate result as the active task controller; this does not bypass verifier or FinishGate.",
            &json!({
                "type": "object",
                "properties": {
                    "result_id": { "type": "string" },
                    "kind": { "type": "string", "enum": ["accepted", "rejected", "probe_requested"] },
                    "reason": { "type": "string" },
                    "evidence_refs": { "type": "array", "items": { "type": "string" } },
                    "idempotency_key": { "type": "string" }
                },
                "required": ["result_id", "kind", "reason", "idempotency_key"]
            }),
        ),
    ]
}

/// The tools and prompts a Claude surface sees, resolved offline.
///
/// This is the same catalog the live server answers `tools/list` and
/// `prompts/list` from. Package manifests must be generated from here rather
/// than transcribed: a hand-maintained second copy of the tool set drifts
/// silently, and the drift is only visible to whoever is holding the manifest.
///
/// Both Claude surfaces currently resolve to the same access profile. That
/// profile is still named after Claude Desktop even though Claude Code uses it
/// too, which is a misnomer scheduled for renaming, not a capability
/// difference: one host family, one Governor authority, one tool set.
pub(crate) fn claude_surface_catalog(surface: ClaudeSurface) -> Value {
    let profile = match surface {
        ClaudeSurface::ClaudeCodePlugin | ClaudeSurface::ClaudeDesktopMcpb => {
            McpAccessProfile::ClaudeGoverned
        }
    };
    let mut mcpb_tools = tool_definitions_for_profile(profile)
        .into_iter()
        .filter_map(|definition| {
            Some(json!({
                "name": definition.get("name")?.as_str()?,
                "description": definition.get("description")?.as_str()?,
            }))
        })
        .collect::<Vec<_>>();
    let mut mcpb_prompts = prompt_definitions()
        .into_iter()
        .filter_map(|definition| {
            let name = definition.get("name")?.as_str()?;
            let description = definition.get("description")?.as_str()?;
            let arguments = definition
                .get("arguments")?
                .as_array()?
                .iter()
                .filter_map(|argument| argument.get("name").and_then(Value::as_str))
                .collect::<Vec<_>>();
            let text = prompt_text(name, "${arguments.task}").ok()?;
            Some(json!({
                "name": name,
                "description": description,
                "arguments": arguments,
                "text": text,
            }))
        })
        .collect::<Vec<_>>();
    // Sorted so the catalog is comparable byte for byte across runs.
    mcpb_tools.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    mcpb_prompts.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    let tools = mcpb_tools
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let prompts = mcpb_prompts
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    json!({
        "schema_version": "eliot-mcp-catalog-v2",
        "host": "claude",
        "surface": surface.as_str(),
        "access_profile": profile.as_str(),
        "supports_lifecycle_hooks": surface.supports_lifecycle_hooks(),
        "tools": tools,
        "prompts": prompts,
        "mcpb_tools": mcpb_tools,
        "mcpb_prompts": mcpb_prompts,
    })
}

pub(crate) fn provider_mcp_tool_profile(
    profile: McpAccessProfile,
) -> ProviderMcpToolProfileBinding {
    let mut tool_names = tool_definitions_for_profile(profile)
        .into_iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    tool_names.sort();
    tool_names.dedup();
    ProviderMcpToolProfileBinding::new(profile.as_str(), tool_names)
}

pub(crate) fn tool_definitions_for_profile(profile: McpAccessProfile) -> Vec<Value> {
    tool_definitions()
        .into_iter()
        .filter_map(|mut definition| {
            let name = definition.get("name").and_then(Value::as_str)?.to_owned();
            if !profile.allows(&name) {
                return None;
            }
            if matches!(
                profile,
                McpAccessProfile::DynamicAgent
                    | McpAccessProfile::ClaudeGoverned
                    | McpAccessProfile::CodexWorker
                    | McpAccessProfile::UnderstandingReader
                    | McpAccessProfile::ExternalAuditor
            ) {
                let defaulted_fields = [
                    BOUND_PROJECT_DEFAULT_TOOLS
                        .contains(&name.as_str())
                        .then_some("project_id"),
                    BOUND_TASK_DEFAULT_TOOLS
                        .contains(&name.as_str())
                        .then_some("task_id"),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
                if let Some(required) = definition
                    .pointer_mut("/inputSchema/required")
                    .and_then(Value::as_array_mut)
                {
                    required.retain(|field| {
                        field
                            .as_str()
                            .is_none_or(|field| !defaulted_fields.contains(&field))
                    });
                }
            }
            if name == "eliot_compile_packet_l3" {
                definition["annotations"] = json!({
                    "readOnlyHint": false,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                });
            } else if READ_ONLY_TOOLS.contains(&name.as_str()) {
                definition["annotations"] = json!({
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                });
            } else if matches!(
                name.as_str(),
                "eliot_agent_candidate_submit" | "eliot.observe"
            ) {
                definition["annotations"] = json!({
                    "readOnlyHint": false,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                });
            }
            Some(definition)
        })
        .collect()
}

pub(super) fn external_review_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_external_review_providers",
            "Eliot External Review Providers",
            "List governed external review provider profiles; real providers are policy-gated.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_external_review_request",
            "Eliot External Review Request",
            "Create a governed mock-only external review request with WorkLease gating.",
            &json_schema(
                &[
                    ("project", "string"),
                    ("task", "string"),
                    ("provider", "string"),
                    ("role", "string"),
                    ("question", "string"),
                ],
                &["project", "task", "provider", "question"],
            ),
        ),
        tool(
            "eliot_external_review_job_status",
            "Eliot External Review Job Status",
            "Inspect a governed external review job status by id.",
            &json_schema(&[("job", "string")], &["job"]),
        ),
        tool(
            "eliot_external_review_result",
            "Eliot External Review Result",
            "Inspect a candidate-only tainted external review result by id.",
            &json_schema(&[("result", "string")], &["result"]),
        ),
        tool(
            "eliot_external_review_report",
            "Eliot External Review Report",
            "Return the bounded external review protocol report.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_external_review_run_mock",
            "Eliot External Review Run Mock",
            "Run an approved mock external review request through AdapterSupervisor.",
            &json_schema(&[("request", "string")], &["request"]),
        ),
    ]
}

pub(super) fn delegation_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_delegate_review",
            "Eliot Delegate Review",
            "Route a bounded candidate-only review through Governor policy to Antigravity.",
            &json!({
                "type": "object",
                "properties": {
                    "project_id": { "type": "string" },
                    "task_id": { "type": "string" },
                    "origin": { "type": "string", "enum": ["user_directed", "codex_requested", "policy_shadow"] },
                    "review_kind": { "type": "string", "enum": ["architecture_audit", "risk_review", "diff_audit", "verifier_advice"] },
                    "question": { "type": "string" },
                    "work_lease_id": { "type": "string" },
                    "evidence_refs": { "type": "array", "items": { "type": "string" } },
                    "preferred_provider": { "type": "string", "enum": ["auto", "antigravity"], "default": "auto" },
                    "wait": { "type": "boolean", "default": false },
                    "campaign_id": { "type": "string" },
                    "idempotency_key": { "type": "string" },
                    "require_budget_slot": { "type": "boolean" },
                    "explicit_operator_intent": { "type": "boolean" }
                },
                "required": ["project_id", "task_id", "origin", "review_kind", "question", "work_lease_id", "campaign_id", "idempotency_key", "require_budget_slot", "explicit_operator_intent"]
            }),
        ),
        tool(
            "eliot_delegate_status",
            "Eliot Delegate Status",
            "Read the safe policy, job, worktree, and budget status for a delegation.",
            &json_schema(&[("delegation_id", "string")], &["delegation_id"]),
        ),
        tool(
            "eliot_delegate_result",
            "Eliot Delegate Result",
            "Read the normalized candidate-only result and outcome attribution.",
            &json_schema(&[("delegation_id", "string")], &["delegation_id"]),
        ),
        tool(
            "eliot_delegate_report",
            "Eliot Delegate Report",
            "Read the bounded delegation diagnostic report.",
            &json!({ "type": "object" }),
        ),
    ]
}

pub(super) fn delegation_calibration_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_delegation_calibration_status",
            "Eliot Delegation Calibration Status",
            "Read bounded delegation calibration counts and doctor status.",
            &json!({"type":"object"}),
        ),
        tool(
            "eliot_delegation_calibration_report",
            "Eliot Delegation Calibration Report",
            "Read the bounded calibration report without raw prompts or provider output.",
            &json!({"type":"object"}),
        ),
        tool(
            "eliot_delegation_policy_candidate",
            "Eliot Delegation Policy Candidate",
            "Read the inactive delegation routing policy candidate.",
            &json!({"type":"object"}),
        ),
        tool(
            "eliot_delegation_promotion_status",
            "Eliot Delegation Promotion Status",
            "Read the promotion gate decision; this tool cannot activate policy.",
            &json!({"type":"object"}),
        ),
    ]
}

pub(super) fn antigravity_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_antigravity_status",
            "Eliot Antigravity Status",
            "Report governed Antigravity detection and disabled-by-default provider state.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_doctor",
            "Eliot Antigravity Doctor",
            "Return Antigravity connector doctor status without raw agy access.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_request",
            "Eliot Antigravity Request",
            "Create a governed Antigravity review request; no provider execution is started.",
            &json_schema(
                &[
                    ("project", "string"),
                    ("task", "string"),
                    ("mode", "string"),
                    ("question", "string"),
                ],
                &["project", "task", "question"],
            ),
        ),
        tool(
            "eliot_antigravity_job_status",
            "Eliot Antigravity Job Status",
            "Inspect latest governed Antigravity run status.",
            &json_schema(&[("run", "string")], &[]),
        ),
        tool(
            "eliot_antigravity_result",
            "Eliot Antigravity Result",
            "Return candidate-only tainted Antigravity normalized result.",
            &json_schema(&[("run", "string")], &[]),
        ),
        tool(
            "eliot_antigravity_report",
            "Eliot Antigravity Report",
            "Return the bounded Antigravity connector report.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_skills",
            "Eliot Antigravity Skills",
            "Return official installed Antigravity plugin skill visibility status (compatibility alias).",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_plugin",
            "Eliot Antigravity Plugin",
            "Return official installed Antigravity plugin status (compatibility alias).",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_auth_status",
            "Eliot Antigravity Auth Status",
            "Return bounded auth status without token, keyring, browser, or private API reads.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_enablement_status",
            "Eliot Antigravity Enablement Status",
            "Return current real-provider enablement receipt/status; MCP cannot enable Antigravity.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_visibility",
            "Eliot Antigravity Visibility",
            "Return historical GUI, CLI, plugin, skill, MCP discovery, invocation, and worktree smoke evidence. This is not current session-role evidence; use eliot_host_session_status for the authenticated caller's role.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_mcp_status",
            "Eliot Antigravity MCP Status",
            "Return HOME-level Antigravity MCP registration status without config mutation or secret values.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_plugin_status",
            "Eliot Antigravity Plugin Status",
            "Return official ELIOT Antigravity plugin, skill, rule, and auditor-agent visibility status.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_live_smoke_status",
            "Eliot Antigravity Live Smoke Status",
            "Return latest governed real Antigravity smoke status; MCP cannot run Antigravity.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_antigravity_real_report",
            "Eliot Antigravity Real Report",
            "Return a bounded real-provider report without raw agy access or execution authority.",
            &json!({ "type": "object" }),
        ),
    ]
}

pub(super) fn eval_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_eval_case_list",
            "Eliot Eval Case List",
            "List deterministic eval cases without creating or mutating benchmark truth.",
            &json_schema(&[("family", "string")], &[]),
        ),
        tool(
            "eliot_eval_suite_list",
            "Eliot Eval Suite List",
            "Return fixed eval suite and manifest handles without raw fixture access.",
            &json_schema(&[("suite", "string")], &[]),
        ),
        tool(
            "eliot_eval_run",
            "Eliot Eval Run",
            "Run deterministic no-mutation evaluation and write report-only artifacts.",
            &json_schema(&[("suite", "string"), ("profile", "string")], &[]),
        ),
        tool(
            "eliot_eval_verdict",
            "Eliot Eval Verdict",
            "Return a report-only eval verdict that grants no authority.",
            &json_schema(&[("run", "string")], &[]),
        ),
        tool(
            "eliot_eval_report",
            "Eliot Eval Report",
            "Return bounded eval status and report handles.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_eval_smoke",
            "Eliot Eval Smoke",
            "Run the core smoke suite in deterministic no-mutation mode.",
            &json_schema(&[("suite", "string")], &[]),
        ),
        tool(
            "eliot_eval_coverage",
            "Eliot Eval Coverage",
            "Return the integration eval coverage matrix without exposing raw fixtures.",
            &json_schema(&[("suite", "string")], &[]),
        ),
        tool(
            "eliot_eval_baseline_list",
            "Eliot Eval Baseline List",
            "List report-only eval baseline snapshots; baseline creation is not exposed through MCP.",
            &json_schema(&[("suite", "string")], &[]),
        ),
        tool(
            "eliot_eval_compare",
            "Eliot Eval Compare",
            "Compare a bounded candidate eval run against a report-only baseline snapshot.",
            &json_schema(
                &[
                    ("suite", "string"),
                    ("baseline", "string"),
                    ("candidate_run", "string"),
                ],
                &[],
            ),
        ),
        tool(
            "eliot_eval_gate",
            "Eliot Eval Gate",
            "Evaluate a governed integration regression gate without granting action or patch authority.",
            &json_schema(&[("profile", "string"), ("suite", "string")], &[]),
        ),
        tool(
            "eliot_eval_profiles",
            "Eliot Eval Profiles",
            "List built-in integration regression gate profiles.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_eval_trend",
            "Eliot Eval Trend",
            "Return bounded eval trend report for the deterministic suite.",
            &json_schema(&[("suite", "string")], &[]),
        ),
    ]
}

pub(super) fn verification_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_verify_profiles",
            "Eliot Verify Profiles",
            "List built-in verification profiles without raw command execution.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_verify_inventory",
            "Eliot Verify Inventory",
            "Return classified verification test inventory and profile routing metadata.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_verify_plan",
            "Eliot Verify Plan",
            "Create a bounded verification plan for a known profile.",
            &json_schema(&[("profile", "string")], &[]),
        ),
        tool(
            "eliot_verify_report",
            "Eliot Verify Report",
            "Return verification economy status and report handles.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_verify_cost_report",
            "Eliot Verify Cost Report",
            "Return test economy cost summary without weakening safety tests.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_verify_last_verdict",
            "Eliot Verify Last Verdict",
            "Return the latest profile-governed verification verdict.",
            &json!({ "type": "object" }),
        ),
    ]
}

pub(super) fn metrics_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_metrics_registry",
            "Eliot Metrics Registry",
            "Return local metric definitions and redaction policy summaries.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_metrics_dashboard",
            "Eliot Metrics Dashboard",
            "Return the local runtime dashboard without raw payloads or remote export.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_metrics_slo",
            "Eliot Metrics SLO",
            "Return local SLO definitions and latest evaluation summary.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_metrics_latency",
            "Eliot Metrics Latency",
            "Return bounded latency histograms from local metric samples.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_metrics_cost",
            "Eliot Metrics Cost",
            "Return local cost ledger summary with mock provider zero-cost accounting.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_metrics_quality",
            "Eliot Metrics Quality",
            "Return local quality signals for eval, verification, completion, and review.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_metrics_report",
            "Eliot Metrics Report",
            "Return the aggregate local observability report.",
            &json!({ "type": "object" }),
        ),
    ]
}

pub(super) fn task_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_cognitive_job_fetch",
            "Eliot Cognitive Job Fetch",
            "Fetch the exact role-specific sealed job packet for this authenticated one-shot cognitive call. The fetch itself exposes no cross-session memory.",
            &json_schema(&[("call_id", "string")], &["call_id"]),
        ),
        tool(
            "eliot_task_contract_create",
            "Eliot TaskContract Create",
            "Create one canonical revision-fenced TaskContract with exactly two acceptance items.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "write_id": {"type": "string"},
                    "title": {"type": "string"},
                    "acceptance_items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "item_id": {"type": "string"},
                                "description": {"type": "string"},
                                "required_evidence": {
                                    "type": "string",
                                    "enum": ["observation", "verification"]
                                }
                            },
                            "required": ["item_id", "description", "required_evidence"]
                        }
                    }
                },
                "required": [
                    "project_id",
                    "task_id",
                    "write_id",
                    "title",
                    "acceptance_items"
                ]
            }),
        ),
        tool(
            "eliot_task_state",
            "Eliot Task State",
            "Read current canonical TaskContract state and its revision fence.",
            &json_schema(
                &[("project_id", "string"), ("task_id", "string")],
                &["project_id", "task_id"],
            ),
        ),
        tool(
            "eliot_task_action_request",
            "Eliot Task Action Request",
            "Deny incomplete understanding or issue one bounded task ActionLease with a receipt.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_task_observation_record",
            "Eliot Task Observation Record",
            "Record one task-scoped candidate ToolObservation through the daemon writer.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_agent_candidate_submit",
            "Eliot Agent Candidate Submit",
            "Save a lesson/decision/failure to memory. Use after solving anything non-obvious or failing. Needs: statement, kind, expected_reuse_note (bindings auto from your session). Returns: handle.",
            &agent_candidate_schema(),
        ),
        tool(
            "eliot.observe",
            "Eliot Observe",
            "Capture an observation, decision, failure, or outcome as candidate-only memory; automatic cue binding is best effort and task-unbound captures remain cold.",
            &observe_schema(),
        ),
        tool(
            "eliot_write_cognitive_observation",
            "Eliot Write Cognitive Observation",
            "Record a tool/test observation (errors, diagnostics). Use on notable failures. Needs: payload. Returns: receipt; may trigger ul_fired on next call.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("write_id", "string"),
                    ("payload", "object"),
                ],
                &["payload"],
            ),
        ),
        tool(
            "eliot_task_verification_run",
            "Eliot Task Verification Run",
            "Run a fixed registered daemon verifier in canonical task or exact Git artifact scope; candidate assertions are denied.",
            &json!({ "type": "object" }),
        ),
    ]
}

#[allow(clippy::too_many_lines)]
pub(super) fn core_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_host_session_status",
            "Eliot Host Session Status",
            "Return the authenticated current host session binding and its active task-role/controller leases. This is the only authoritative current-role surface; host identity, Antigravity visibility, provider status, old invocation receipts, and memory history never grant a role.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_project_identity",
            "Eliot Project Identity",
            "Return the Governor-bound project/task scope for a managed host session, or resolve a stable human-readable repository key to the canonical project UUID for an unbound client.",
            &json_schema(&[("project_key", "string")], &[]),
        ),
        tool(
            "eliot_current_state",
            "Eliot Current State",
            "Project memory snapshot + revision. Use at doubt about current truth. Needs: nothing. Returns: verified/contested claims, revision fence.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("scope", "string"),
                    ("at_least_revision", "integer"),
                ],
                &["project_id"],
            ),
        ),
        tool(
            "eliot_recall_l0",
            "Eliot Recall L0",
            "Search the current multi-kind memory projection by keywords. Scope and lifecycle filtering happen before ranking; lifecycle_audit explicitly exposes audit-only records. Returns at most 12 compact handles plus inspectable integer rank features.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("query", "string"),
                    ("scope", "string"),
                    ("limit", "integer"),
                    ("lifecycle_audit", "boolean"),
                    ("task_class_cues", "array"),
                    ("concept_refs", "array"),
                ],
                &["project_id", "query"],
            ),
        ),
        tool(
            "eliot_fetch_l2",
            "Eliot Fetch L2",
            "Expand memory handles to full cards. Use only for handles you will act on. Needs: handles[]. Returns: cards + relations.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("handles", "array"),
                    ("continuation", "string"),
                    ("at_least_revision", "integer"),
                ],
                &["project_id", "handles"],
            ),
        ),
        tool(
            "eliot_compile_packet_l3",
            "Eliot Compile Packet L3",
            "Task context packet + prefilled frame_stub. Use BEFORE any material edit. Needs: goal (task_id auto). Returns: packet, frame_stub (edit <=5 fields), verifier, ul_gate.",
            &compile_packet_schema(),
        ),
        tool(
            "eliot_understanding_outcome_record",
            "Eliot Understanding Outcome Record",
            "Validate the selected causal path against actual artifacts and verifier outcome, then write the reality-linked record through WriterActor.",
            &cognitive_record_schema("record"),
        ),
        tool(
            "eliot_memory_influence_trace",
            "Eliot Memory Influence Trace",
            "Acknowledge memory you used. Minimal form: memory_handle, influence_class[, downstream_outcome_ref]. Server fills the rest. Returns: receipt.",
            &memory_influence_trace_schema(),
        ),
        tool(
            "eliot_context_cargo_receipt",
            "Eliot Context Cargo Receipt",
            "Write a governed context-cargo observation; repeated no-delta loading may propose demotion but never applies it automatically.",
            &cognitive_record_schema("receipt"),
        ),
        tool(
            "eliot_task_meaning",
            "Eliot Task Meaning",
            "Build a host-neutral TaskMeaningFrame quality report and MemoryNeedDecision. NO_USEFUL_MEMORY is a valid result.",
            &json_schema(
                &[("frame", "object"), ("requested_need", "string")],
                &["frame"],
            ),
        ),
        tool(
            "eliot_memory_corpus_profile",
            "Eliot Memory Corpus Profile",
            "Measure the real canonical claim, episode, case, pattern, maturity, provenance, boundary, and verifier coverage before adding memory.",
            &json_schema(&[("project_id", "string")], &["project_id"]),
        ),
        tool(
            "eliot_experience_recall",
            "Eliot Experience Recall",
            "Return zero to three compact experience_priors after memory-need, kind, maturity, fused-cue, exposure, and applicability gates. Priors never enter verified_now.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("frame", "object"),
                    ("requested_need", "string"),
                    ("exposure_policy", "object"),
                ],
                &["project_id", "frame"],
            ),
        ),
        tool(
            "eliot_experience_reinstate",
            "Eliot Experience Context Reinstatement",
            "Expand one exact causal case into its source-cited episode, action/outcome chain, and verifier neighborhood.",
            &json_schema(
                &[("project_id", "string"), ("case_id", "string")],
                &["project_id", "case_id"],
            ),
        ),
        tool(
            "eliot_experience_form",
            "Eliot Experience Formation",
            "Curator/ReasoningBroker write path: reconstruct one verified episode as a candidate-only ExperienceCase, or return NOTHING_TO_LEARN. It cannot promote truth or a procedure.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("episode", "object"),
                ],
                &["project_id", "task_id", "episode"],
            ),
        ),
        tool(
            "eliot_experience_abstract",
            "Eliot Contrastive Experience Abstraction",
            "Curator/ReasoningBroker write path: derive one candidate pattern only from multiple canonical cases with a preserved contrast boundary; NO_LEARNABLE_PATTERN is valid.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("case_refs", "array"),
                ],
                &["project_id", "task_id", "case_refs"],
            ),
        ),
        tool(
            "eliot_experience_maturity_transition",
            "Eliot Experience Maturity Transition",
            "Apply the deterministic maturity gate to one canonical pattern. Transfer validation requires paraphrase survival, near-miss rejection, an independent host, and a verified decision delta; the result remains candidate-only and grants no current truth or procedure authority.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("pattern_id", "string"),
                    ("target_state", "string"),
                    ("evidence", "object"),
                ],
                &[
                    "project_id",
                    "task_id",
                    "pattern_id",
                    "target_state",
                    "evidence",
                ],
            ),
        ),
        tool(
            "eliot_negative_transfer_record",
            "Eliot Negative Transfer Record",
            "Persist outcome feedback and a governed demote, suppress, reconstruct, or require-probe lifecycle action while preserving history.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("experiment_ref", "string"),
                    ("memory_handles", "array"),
                    ("harm", "object"),
                    ("root_cause_stage", "string"),
                    ("source_has_reconstructable_episode", "boolean"),
                ],
                &[
                    "project_id",
                    "task_id",
                    "experiment_ref",
                    "memory_handles",
                    "harm",
                    "root_cause_stage",
                ],
            ),
        ),
        tool(
            "eliot_cognitive_lab_evaluate",
            "Eliot Cognitive Transfer Lab",
            "Evaluate sealed-case encoding, retrieval, applicability, near-miss, verifier, contamination, and behavioral-transfer checks and persist the result.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("run_id", "string"),
                    ("cases", "array"),
                    ("answers", "array"),
                ],
                &["project_id", "task_id", "run_id", "cases", "answers"],
            ),
        ),
        tool(
            "eliot_cognitive_failure_localization_record",
            "Eliot Cognitive Failure Localization Record",
            "Persist the evidence-backed primary failure stage before broad cognitive architecture changes.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("report", "object"),
                ],
                &["project_id", "task_id", "report"],
            ),
        ),
        tool(
            "eliot_submit_understanding_proof",
            "Eliot Submit Understanding Proof",
            "Validate operational understanding before nontrivial actions.",
            &understanding_proof_schema(),
        ),
        tool(
            "eliot_cognitive_gate",
            "Eliot Cognitive Gate",
            "Decide whether Codex may act.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_submit_completion_proof",
            "Eliot Submit Completion Proof",
            "Validate completion proof before DONE claims; canonical task completion may include only a small save_decision statement or explicit nothing_to_save memory outcome.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_codecortex_scan",
            "Eliot CodeCortex Scan",
            "Run a governed internal CodeCortex grounding scan and write its report through WriterActor.",
            &codecortex_scan_schema(),
        ),
        tool(
            "eliot_codecortex_latest",
            "Eliot CodeCortex Latest",
            "Return the latest governed CodeCortex report handle and evidence.",
            &json!({ "type": "object" }),
        ),
    ]
}

#[allow(clippy::too_many_lines)]
pub(super) fn replay_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_trace_completeness",
            "Eliot Canonical Trace Register",
            "Resolve all 13 trace evidence parts from canonical task, observation, verifier receipts and engine derivations; caller-shaped evidence strings are not accepted.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("expected_task_revision", "integer"),
                    ("idempotency_key", "string"),
                    ("trace_ref", "string"),
                    ("actual_observation_ref", "string"),
                    ("verifier_run_ref", "string"),
                    ("artifact_ref", "string"),
                    ("source_route", "string"),
                    ("source_tool", "string"),
                    ("source_verifier", "string"),
                    ("outcome", "string"),
                    ("taint", "string"),
                ],
                &[
                    "project_id",
                    "task_id",
                    "expected_task_revision",
                    "idempotency_key",
                    "trace_ref",
                    "actual_observation_ref",
                    "verifier_run_ref",
                    "artifact_ref",
                    "source_route",
                    "source_tool",
                    "source_verifier",
                    "outcome",
                    "taint",
                ],
            ),
        ),
        tool(
            "eliot_replay_case_create",
            "Eliot Replay Case Create (Disabled)",
            "Legacy report-only fixture path is disabled; use eliot_replay_run with a canonical trace.",
            &json_schema(
                &[
                    ("project", "string"),
                    ("task", "string"),
                    ("kind", "string"),
                ],
                &["project", "task"],
            ),
        ),
        tool(
            "eliot_replay_set_create",
            "Eliot Replay Set Create (Disabled)",
            "Legacy report-only fixture path is disabled; use eliot_replay_run with fixed/holdout refs.",
            &json_schema(
                &[
                    ("project", "string"),
                    ("name", "string"),
                    ("fixed", "boolean"),
                    ("holdout", "boolean"),
                ],
                &["project"],
            ),
        ),
        tool(
            "eliot_replay_run",
            "Eliot Sealed Replay Run",
            "Seal a named 2-20 case fixed or holdout set, persist its cases and snapshots, then derive baseline and candidate executions only from canonical trace evidence.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("expected_task_revision", "integer"),
                    ("idempotency_key", "string"),
                    ("trace_refs", "array"),
                    ("set_name", "string"),
                    ("set_role", "string"),
                    ("set_version", "integer"),
                    ("case_kind", "string"),
                    ("baseline_policy", "object"),
                    ("candidate_policy", "object"),
                    ("baseline_version", "string"),
                    ("candidate_version", "string"),
                    ("sealed_context_version", "string"),
                    ("evaluator_version", "string"),
                    ("mutation_attempt", "string"),
                ],
                &[
                    "project_id",
                    "task_id",
                    "expected_task_revision",
                    "idempotency_key",
                    "trace_refs",
                    "set_name",
                    "set_role",
                    "set_version",
                    "case_kind",
                    "baseline_policy",
                    "candidate_policy",
                    "baseline_version",
                    "candidate_version",
                    "sealed_context_version",
                    "evaluator_version",
                ],
            ),
        ),
        tool(
            "eliot_replay_report",
            "Eliot Replay Report",
            "Return latest replay run and verdict reports.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_sleep_run",
            "Eliot Governed Sleep Run",
            "Run candidate-only sleep over registered complete trace refs; missing/incomplete refs are retained as exclusions.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("expected_task_revision", "integer"),
                    ("idempotency_key", "string"),
                    ("trigger", "string"),
                    ("dry_run", "boolean"),
                    ("trace_refs", "array"),
                ],
                &[
                    "project_id",
                    "task_id",
                    "expected_task_revision",
                    "idempotency_key",
                    "trigger",
                    "dry_run",
                    "trace_refs",
                ],
            ),
        ),
        tool(
            "eliot_sleep_report",
            "Eliot Sleep Report",
            "Return latest candidate-only sleep report.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_dream_candidate_create",
            "Eliot Dream Candidate Create (Disabled)",
            "Direct fixture creation is disabled; eliot_sleep_run creates candidates from canonical traces.",
            &json_schema(
                &[
                    ("project", "string"),
                    ("kind", "string"),
                    ("source_trace", "string"),
                ],
                &[],
            ),
        ),
        tool(
            "eliot_dream_report",
            "Eliot Dream Report",
            "Return latest dream candidate report.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_meta_experiment_run",
            "Eliot Meta Experiment Run",
            "Derive metrics from canonical fixed/holdout baseline and candidate executions, persist isolation rejection receipts, and stage only replay_threshold_v1 policy candidates.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("expected_task_revision", "integer"),
                    ("idempotency_key", "string"),
                    ("eval_run_id", "string"),
                    ("change_class", "string"),
                    ("changed_variables", "array"),
                    ("coupled_change_rationale", "string"),
                    ("baseline_policy", "object"),
                    ("candidate_policy", "object"),
                    ("fixed_baseline_execution_id", "string"),
                    ("fixed_candidate_execution_id", "string"),
                    ("holdout_baseline_execution_id", "string"),
                    ("holdout_candidate_execution_id", "string"),
                    ("attempted_fence", "object"),
                ],
                &[
                    "project_id",
                    "task_id",
                    "expected_task_revision",
                    "idempotency_key",
                    "eval_run_id",
                    "change_class",
                    "changed_variables",
                    "baseline_policy",
                    "candidate_policy",
                    "fixed_baseline_execution_id",
                    "fixed_candidate_execution_id",
                    "holdout_baseline_execution_id",
                    "holdout_candidate_execution_id",
                ],
            ),
        ),
        tool(
            "eliot_meta_experiment_disposition",
            "Eliot Meta Experiment Disposition",
            "Promote or exactly roll back replay_threshold_v1 using the engine-derived exact action hash; unsupported policies remain blocked.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("expected_task_revision", "integer"),
                    ("idempotency_key", "string"),
                    ("experiment_id", "string"),
                    ("expected_experiment_revision", "integer"),
                    ("decision", "string"),
                    ("rollback_requested", "boolean"),
                    ("operator_command_ref", "string"),
                    ("expected_action_hash", "string"),
                ],
                &[
                    "project_id",
                    "task_id",
                    "expected_task_revision",
                    "idempotency_key",
                    "experiment_id",
                    "expected_experiment_revision",
                    "decision",
                ],
            ),
        ),
        tool(
            "eliot_canonical_status",
            "Eliot Canonical Status",
            "Rehydrate canonical traces, exclusions, replay hashes, metrics, and terminal dispositions for one task.",
            &json_schema(
                &[("project_id", "string"), ("task_id", "string")],
                &["project_id", "task_id"],
            ),
        ),
    ]
}

#[allow(clippy::too_many_lines)]
pub(super) fn memory_lifecycle_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_memory_curation_preview",
            "Eliot Memory Curation Preview",
            "Return a read-only, corpus-wide, revision-fenced page of explicit reversible curation findings; never mutates or deletes memory.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "at_revision": {"type": "integer", "minimum": 0},
                    "ruleset_version": {"type": "string", "enum": ["eliot-l13-curation-v1"]},
                    "cursor": {"type": "string"},
                    "page_size": {"type": "integer", "minimum": 1, "maximum": 100}
                },
                "required": ["project_id", "task_id", "at_revision", "ruleset_version", "page_size"]
            }),
        ),
        tool(
            "eliot_memory_distillation_preview",
            "Eliot Memory Distillation Preview",
            "Build a pure revision-fenced distillation plan from the complete canonical corpus and canonical utility ledger. Semantic merges and incomplete scans remain candidate-only.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "at_revision": {"type": "integer", "minimum": 0},
                    "ruleset_version": {"type": "string", "enum": ["eliot-c4-distillation-v1"]},
                    "cursor": {"type": "string"},
                    "page_size": {"type": "integer", "minimum": 1, "maximum": 100}
                },
                "required": ["project_id", "ruleset_version", "page_size"]
            }),
        ),
        tool(
            "eliot_memory_distillation_schedule",
            "Eliot Memory Distillation Schedule",
            "Return a resumable bounded scheduler checkpoint. It pauses under interactive load, invalid batch sizes, or insufficient new evidence.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "trigger": {"type": "string", "enum": ["verified_task_closure", "nightly", "idle", "manual"]},
                    "new_evidence_count": {"type": "integer", "minimum": 0},
                    "minimum_evidence_count": {"type": "integer", "minimum": 0},
                    "interactive_load_active": {"type": "boolean"},
                    "cursor": {"type": "string"},
                    "batch_size": {"type": "integer", "minimum": 1, "maximum": 500}
                },
                "required": [
                    "project_id",
                    "trigger",
                    "new_evidence_count",
                    "minimum_evidence_count",
                    "interactive_load_active",
                    "batch_size"
                ]
            }),
        ),
        tool(
            "eliot_memory_distillation_apply",
            "Eliot Memory Distillation Apply",
            "Recompute an exact revision-fenced plan and apply only explicitly selected high-confidence reversible actions through canonical lifecycle transitions. Requires controller or human-operator authority.",
            &json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "project_id": {"type": "string"},
                    "task_id": {"type": "string"},
                    "at_revision": {"type": "integer", "minimum": 0},
                    "ruleset_version": {"type": "string", "enum": ["eliot-c4-distillation-v1"]},
                    "selected_candidate_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "maxItems": 100
                    },
                    "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 256}
                },
                "required": [
                    "project_id",
                    "task_id",
                    "at_revision",
                    "ruleset_version",
                    "selected_candidate_ids",
                    "idempotency_key"
                ]
            }),
        ),
        tool(
            "eliot_memory_lifecycle_status",
            "Eliot Memory Lifecycle Status",
            "Return governed lifecycle state for a memory ref.",
            &json_schema(
                &[("project", "string"), ("memory_ref", "string")],
                &["project", "memory_ref"],
            ),
        ),
        tool(
            "eliot_memory_lifecycle_propose",
            "Eliot Memory Lifecycle Propose",
            "Create a governed non-executing forgetting policy candidate.",
            &json_schema(
                &[
                    ("project", "string"),
                    ("memory_ref", "string"),
                    ("operator", "string"),
                    ("reason", "string"),
                ],
                &["project", "memory_ref", "operator", "reason"],
            ),
        ),
        tool(
            "eliot_memory_lifecycle_vitality",
            "Eliot Memory Lifecycle Vitality",
            "Compute conservative I0 memory vitality score.",
            &json_schema(
                &[("project", "string"), ("memory_ref", "string")],
                &["project"],
            ),
        ),
        tool(
            "eliot_memory_lifecycle_gravity",
            "Eliot Memory Lifecycle Gravity",
            "Compute conservative I0 activation pressure view.",
            &json_schema(
                &[("project", "string"), ("memory_ref", "string")],
                &["project"],
            ),
        ),
        tool(
            "eliot_memory_lifecycle_influence",
            "Eliot Memory Lifecycle Influence",
            "Write a governed MemoryInfluenceReport through WriterActor.",
            &json_schema(
                &[
                    ("project", "string"),
                    ("task", "string"),
                    ("included_refs", "array"),
                    ("outcome", "object"),
                ],
                &["project"],
            ),
        ),
    ]
}

pub(super) fn skill_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_skill_list",
            "Eliot Skill List",
            "List governed skill cards visible for audit or normal recall; Governor-bound host sessions may omit project.",
            &json_schema(&[("project", "string")], &[]),
        ),
        tool(
            "eliot_skill_inspect",
            "Eliot Skill Inspect",
            "Inspect one governed SkillCardV2 by id without activating it.",
            &json_schema(&[("skill", "string")], &["skill"]),
        ),
        tool(
            "eliot_skill_estimate",
            "Eliot Skill Estimate",
            "Estimate skill necessity and distractor risk for a task.",
            &json_schema(
                &[("project", "string"), ("task", "string")],
                &["project", "task"],
            ),
        ),
        tool(
            "eliot_skill_filter",
            "Eliot Skill Filter",
            "Filter irrelevant skills before L3 inclusion.",
            &json_schema(
                &[("project", "string"), ("task", "string")],
                &["project", "task"],
            ),
        ),
        tool(
            "eliot_skill_influence",
            "Eliot Skill Influence",
            "Generate a governed skill influence report.",
            &json_schema(
                &[("project", "string"), ("task", "string")],
                &["project", "task"],
            ),
        ),
        tool(
            "eliot_skill_execution_proof",
            "Eliot Skill Execution Proof",
            "Write SkillExecutionProof through WriterActor with verifier refs.",
            &json_schema(
                &[("skill", "string"), ("task", "string")],
                &["skill", "task"],
            ),
        ),
        tool(
            "eliot_skill_create_candidate",
            "Eliot Skill Create Candidate",
            "Create a candidate SkillCardV2; it is audit-only until activated elsewhere.",
            &json_schema(
                &[("project", "string"), ("name", "string")],
                &["project", "name"],
            ),
        ),
    ]
}

pub(super) fn skill_curator_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_skill_curator_run",
            "Eliot Skill Curator Run",
            "Run governed SkillCurator evidence scan and write run/proposals through WriterActor.",
            &json_schema(
                &[("project", "string"), ("dry_run", "boolean")],
                &["project"],
            ),
        ),
        tool(
            "eliot_skill_curator_proposals",
            "Eliot Skill Curator Proposals",
            "Return governed open SkillCurator proposals without applying them.",
            &json_schema(&[("project", "string")], &["project"]),
        ),
        tool(
            "eliot_skill_curator_inspect",
            "Eliot Skill Curator Inspect",
            "Inspect latest governed SkillCurator run by id.",
            &json_schema(&[("run", "string")], &["run"]),
        ),
        tool(
            "eliot_skill_curator_report",
            "Eliot Skill Curator Report",
            "Return latest governed SkillCurator report.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_skill_curator_gate",
            "Eliot Skill Curator Gate",
            "Evaluate a SkillCurationProposal with SkillCurationGate without applying it.",
            &json_schema(&[("proposal", "string")], &["proposal"]),
        ),
    ]
}

pub(super) fn runtime_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_runtime_status",
            "Eliot Runtime Status",
            "Return the daemon runtime generation and IPC auth generation without secrets; these identifiers are never AgentSession or role state.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_autonomy_run_status",
            "Eliot Autonomy Run Status",
            "Return canonical bounded AutonomyRunContract state for one task; never substitute a verification run or AgentSession.",
            &json_schema(
                &[
                    ("project_id", "string"),
                    ("task_id", "string"),
                    ("autonomy_run_id", "string"),
                ],
                &["project_id", "task_id"],
            ),
        ),
        tool(
            "eliot_runtime_health",
            "Eliot Runtime Health",
            "Return bounded governed runtime health and degraded-mode summary.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_module_list",
            "Eliot Module List",
            "Return governed module manifest and health summary.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_module_health",
            "Eliot Module Health",
            "Return governed module health summary.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_logs_query",
            "Eliot Logs Query",
            "Return bounded structured log events by optional trace id.",
            &json_schema(&[("trace_id", "string"), ("limit", "integer")], &[]),
        ),
    ]
}

pub(super) fn service_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_service_status",
            "Eliot Service Status",
            "Return bounded local Windows service status without install, start, stop, credentials, or SCM mutation.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_ipc_status",
            "Eliot IPC Status",
            "Return bounded local IPC readiness without raw pipe access, raw frames, or handshake secrets.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_readiness_report",
            "Eliot Readiness Report",
            "Return bounded production readiness status and report handle without raw DB or credential details.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_startup_recovery_report",
            "Eliot Startup Recovery Report",
            "Return latest startup recovery report status; recovery scan execution is CLI-only.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_credentials_report",
            "Eliot Credentials Report",
            "Return redacted credential-boundary diagnostics without resolving or returning secret values.",
            &json!({ "type": "object" }),
        ),
    ]
}

pub(super) fn adapter_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_adapter_list",
            "Eliot Adapter List",
            "Return governed internal adapter manifests and health without raw execution tools.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_adapter_health",
            "Eliot Adapter Health",
            "Return bounded adapter supervisor health.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_adapter_inspect",
            "Eliot Adapter Inspect",
            "Inspect one governed adapter manifest by adapter id.",
            &json_schema(&[("adapter", "string")], &["adapter"]),
        ),
        tool(
            "eliot_adapter_execute_test",
            "Eliot Adapter Execute Test",
            "Execute a built-in test adapter and write tainted observation through WriterActor.",
            &json_schema(&[("adapter", "string")], &["adapter"]),
        ),
    ]
}

pub(super) fn recovery_report_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_doctor_report",
            "Eliot Doctor Report",
            "Return governed H0 doctor diagnostics without repair or raw file access.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_data_root_status",
            "Eliot Data Root Status",
            "Return governed data-root validation status without exposing credentials.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_backup_report",
            "Eliot Backup Report",
            "Return latest governed backup manifest/receipt summary without delete or raw copy tools.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_restore_report",
            "Eliot Restore Report",
            "Return latest governed restore verification summary without restore execution.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_blob_report",
            "Eliot Blob Report",
            "Return BlobManifest and GC dry-run summary without blob deletion.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_maintenance_status",
            "Eliot Maintenance Status",
            "Return latest bounded maintenance job status.",
            &json!({ "type": "object" }),
        ),
        tool(
            "eliot_incident_list",
            "Eliot Incident List",
            "Return incident summary and lockdown state without mutation.",
            &json!({ "type": "object" }),
        ),
    ]
}

pub(super) fn action_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_action_plan",
            "Eliot Action Plan",
            "Create a governed E1 ActionLease planning report without granting patch execution.",
            &action_plan_schema(),
        ),
        tool(
            "eliot_action_lease_status",
            "Eliot Action Lease Status",
            "Return the latest governed ActionLease planning status.",
            &action_lease_status_schema(),
        ),
    ]
}

pub(super) fn patch_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_patch_preflight",
            "Eliot Patch Preflight",
            "Preflight a governed unified diff against an approved ActionLease.",
            &patch_apply_schema(),
        ),
        tool(
            "eliot_patch_apply",
            "Eliot Patch Apply",
            "Apply a governed unified diff after ActionLease and verifier checks.",
            &patch_apply_schema(),
        ),
        tool(
            "eliot_patch_status",
            "Eliot Patch Status",
            "Return latest governed PatchRun status.",
            &json_schema(&[("patch_run_id", "string")], &["patch_run_id"]),
        ),
        tool(
            "eliot_verifier_status",
            "Eliot Verifier Status",
            "Return latest governed VerifierRun status.",
            &json_schema(&[("task", "string"), ("task_id", "string")], &[]),
        ),
    ]
}

pub(super) fn work_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_work_create",
            "Eliot Work Create",
            "Create a governed F1 WorkItem coordination record.",
            &work_create_schema(),
        ),
        tool(
            "eliot_work_claim",
            "Eliot Work Claim",
            "Claim a governed WorkLease for an existing WorkItem.",
            &work_claim_schema(),
        ),
        tool(
            "eliot_work_status",
            "Eliot Work Status",
            "Return current governed WorkItem and WorkLease status.",
            &work_status_schema(),
        ),
        tool(
            "eliot_work_renew",
            "Eliot Work Renew",
            "Renew an active governed WorkLease.",
            &work_lease_schema(),
        ),
        tool(
            "eliot_work_release",
            "Eliot Work Release",
            "Release an active governed WorkLease.",
            &work_lease_schema(),
        ),
        tool(
            "eliot_work_conflicts",
            "Eliot Work Conflicts",
            "Return governed WorkConflict records for a task.",
            &work_status_schema(),
        ),
    ]
}

pub(super) fn worktree_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_worktree_create",
            "Eliot Worktree Create",
            "Create a governed disposable WorktreeLease for an active WorkLease.",
            &worktree_create_schema(),
        ),
        tool(
            "eliot_worktree_status",
            "Eliot Worktree Status",
            "Return governed WorktreeLease status.",
            &worktree_status_schema(),
        ),
        tool(
            "eliot_worktree_capture_diff",
            "Eliot Worktree Capture Diff",
            "Capture a bounded CandidateDiff from a governed disposable worktree.",
            &worktree_lease_schema(),
        ),
        tool(
            "eliot_worktree_review",
            "Eliot Worktree Review",
            "Review a CandidateDiff for PatchRunner handoff without applying it.",
            &worktree_review_schema(),
        ),
        tool(
            "eliot_worktree_cleanup",
            "Eliot Worktree Cleanup",
            "Remove a governed disposable worktree after capture or review.",
            &worktree_lease_schema(),
        ),
    ]
}

pub(super) fn collective_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "eliot_blackboard_add",
            "Eliot Blackboard Add",
            "Create a governed F3 blackboard candidate item by reference.",
            &blackboard_add_schema(),
        ),
        tool(
            "eliot_blackboard_list",
            "Eliot Blackboard List",
            "List governed F3 blackboard items for a task.",
            &work_status_schema(),
        ),
        tool(
            "eliot_blackboard_ack",
            "Eliot Blackboard Ack",
            "Acknowledge a governed F3 blackboard item.",
            &blackboard_ack_schema(),
        ),
        tool(
            "eliot_mailbox_send",
            "Eliot Mailbox Send",
            "Send a governed F3 mailbox message by payload reference.",
            &mailbox_send_schema(),
        ),
        tool(
            "eliot_mailbox_inbox",
            "Eliot Mailbox Inbox",
            "List governed F3 mailbox messages for a task.",
            &work_status_schema(),
        ),
        tool(
            "eliot_mailbox_ack",
            "Eliot Mailbox Ack",
            "Acknowledge a governed F3 mailbox message.",
            &mailbox_ack_schema(),
        ),
        tool(
            "eliot_recovery_scan",
            "Eliot Recovery Scan",
            "Run governed F3 lost-agent recovery over existing WorkState.",
            &work_status_schema(),
        ),
        tool(
            "eliot_collective_trace",
            "Eliot Collective Trace",
            "Create a governed F3 collective contribution trace for a task.",
            &work_status_schema(),
        ),
    ]
}
