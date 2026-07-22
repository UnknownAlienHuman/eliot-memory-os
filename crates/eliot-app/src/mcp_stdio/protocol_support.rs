fn initialize_result(profile: McpAccessProfile, session: &Value) -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false },
            "prompts": { "listChanged": false }
        },
        "serverInfo": {
            "name": "eliot-governor",
            "title": "Eliot Governor",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": profile_instructions(profile),
        "experimental": {
            "eliotAgentSession": session
        }
    })
}

fn profile_instructions(profile: McpAccessProfile) -> String {
    let proactive_memory = match profile {
        McpAccessProfile::HumanOperator | McpAccessProfile::HumanReadonly => {
            "Use the bounded operator projections and typed commands only. The Governor remains the sole business-rule and memory authority; do not request raw records, database access, credentials, shell, or hidden reasoning."
        }
        McpAccessProfile::ClaudeGoverned => {
            "For a material project task, resolve one stable project identity, read task/current state, and expand only the exact memory or packet handles needed for the decision. Record cross-memory influence explicitly and submit only novel candidate evidence with a retry-stable write ID. Use delegation and disposition tools only when the current task-scoped role lease authorizes them; this compact profile intentionally omits direct patch, provider, database, and completion authority."
        }
        _ => {
            "For every nontrivial project task, use Eliot before searching local memory files. First call eliot_host_session_status. If it reports governor_bound_scope_active, call eliot_project_identity with no key and let the Governor default all supported project/task fields; never derive or restate those identifiers from a case label, current directory, playground, or host UI. Otherwise call eliot_project_identity with one stable repository key. Then use eliot_task_state, eliot_recall_l0, and eliot_fetch_l2 as needed. Explicit scope must match the Governor binding or it is rejected as PROJECT_SCOPE_MISMATCH or TASK_SCOPE_MISMATCH. Recover daemon runtime_id and auth_generation only from eliot_runtime_status, and bounded autonomy only from eliot_autonomy_run_status; never substitute an AgentSession, role status, or verification run for those canonical identities. Call MCP tools from their live definitions; never read generated MCP JSON schema or report/output files. A recall-only or status-only task needs no handoff write, and an existing recalled claim must never be copied into a new candidate. Submit only a novel reusable finding created by the current material work. Use one eliot_agent_candidate_submit call with one retry-stable UUID write_id, topic, statement, all three array fields where_applicable/where_not_applicable/negative_constraints (empty arrays are valid), non-empty provenance_refs, and freshness_rule; a bound session may omit project_id/task_id. For memory recall, do not call CodeCortex or Antigravity connector reports/smokes unless the task explicitly requires them."
        }
    };
    let authority = match profile {
        McpAccessProfile::CognitiveGovernor => {
            "This private profile admits and advances one canonical cognitive run through sealed Governor RPCs only."
        }
        McpAccessProfile::HostGovernor => {
            "This attested private profile admits host authority mutations through sealed Governor RPCs only."
        }
        McpAccessProfile::CognitiveChild => {
            "This private profile is confined to one capability-bound candidate submission and has no global IPC authority."
        }
        McpAccessProfile::CognitiveControl => {
            "This sealed memory-free control profile exposes an empty MCP tool catalog."
        }
        McpAccessProfile::DynamicAgent | McpAccessProfile::ClaudeGoverned => {
            "Your host identity grants no controller, worker, auditor, verifier, patch, or completion role. Any such role is task-scoped and must be evidenced by eliot_host_session_status plus a current Eliot role/work lease. When that status reports governor_bound_scope_active, call project identity and task/current-memory tools without inventing or restating project/task identifiers; the Governor supplies the bound scope and rejects PROJECT_SCOPE_MISMATCH or TASK_SCOPE_MISMATCH. Never derive scope from a case label, current directory, playground, or host UI. Never infer your role from host-specific Antigravity visibility, provider status, old invocation receipts, or memory history. Use the governed tools directly for proactive recall, candidate writeback, and task work; do not wait for repeated user prompting."
        }
        McpAccessProfile::ExternalAuditor => {
            "You are an external_auditor: recalled state and your writes are candidate evidence only; never claim truth promotion, patch, lease, provider, or completion authority."
        }
        McpAccessProfile::HumanReadonly | McpAccessProfile::Verifier => {
            "This profile is read-only; never claim write, patch, lease, provider, or completion authority."
        }
        McpAccessProfile::HumanOperator => {
            "This is a human operator session. Only typed operator commands are allowed; every mutation remains subject to Governor policy and must return a canonical receipt."
        }
        McpAccessProfile::CodexWorker => {
            "This worker profile cannot apply patches, delegate reviews, or claim completion."
        }
        McpAccessProfile::CodexController => {
            "Controller authority remains governed by task contracts, action leases, and verifier evidence."
        }
    };
    format!(
        "MCP profile {} exposes only governed Eliot tools. {proactive_memory} {authority} No raw SQL, raw shell, raw file, or credential surface is available.",
        profile.as_str()
    )
}

fn tool(name: &str, title: &str, description: &str, input_schema: &Value) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": input_schema.clone()
    })
}

fn json_schema(properties: &[(&str, &str)], required: &[&str]) -> Value {
    let props = properties
        .iter()
        .map(|(name, ty)| ((*name).to_owned(), json!({ "type": ty })))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "type": "object",
        "properties": props,
        "required": required
    })
}

fn compile_packet_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
            "task_id": {"type": "string"},
            "goal": {"type": "string"},
            "candidate_handles": {"type": "array", "items": {"type": "string"}},
            "max_tokens": {"type": "integer", "minimum": 1},
            "memory_mode": {
                "type": "string",
                "enum": [
                    "current_truth_only", "memory_free_control", "mature_experience_only",
                    "include_case_candidates", "full_audit"
                ]
            },
            "material_frame": {
                "type": "object",
                "description": "Required for material work; omitted packets are honestly rated insufficient.",
                "properties": {
                    "acceptance_items": {"type": "array", "items": {"type": "string"}},
                    "environment": {"type": "array", "items": {"type": "string"}},
                    "active_plan": {"type": "array", "items": {"type": "string"}},
                    "completed_work": {"type": "array", "items": {"type": "string"}},
                    "killed_paths": {"type": "array", "items": {"type": "string"}},
                    "causal_bridge": {"type": "array", "items": {"type": "object"}},
                    "negative_memory_checked": {"type": "boolean"},
                    "exact_load_bearing_atoms": {"type": "array", "items": {"type": "string"}},
                    "cheapest_discriminative_probes": {"type": "array", "items": {"type": "string"}},
                    "responsibility_contour_route_refs": {"type": "array", "items": {"type": "string"}},
                    "next_allowed_action": {"type": "string"},
                    "expected_observable": {"type": "string"},
                    "verifier": {"type": "string"},
                    "stop_condition": {"type": "string"},
                    "tool_schema_bytes_visible": {"type": "integer", "minimum": 0},
                    "instruction_hotset_size": {"type": "integer", "minimum": 0}
                },
                "required": [
                    "acceptance_items", "environment", "causal_bridge",
                    "negative_memory_checked", "exact_load_bearing_atoms",
                    "cheapest_discriminative_probes", "responsibility_contour_route_refs",
                    "next_allowed_action", "expected_observable", "verifier", "stop_condition",
                    "tool_schema_bytes_visible", "instruction_hotset_size"
                ]
            }
        },
        "required": ["project_id", "task_id", "goal", "candidate_handles", "max_tokens"]
    })
}

fn understanding_proof_schema() -> Value {
    json_schema(
        &[
            ("task_id", "string"),
            ("project_id", "string"),
            ("goal", "string"),
            ("code_task", "boolean"),
            ("current_truth_refs", "array"),
            ("evidence_refs", "array"),
            ("codecortex_report_refs", "array"),
            ("files_to_change", "array"),
            ("files_to_inspect", "array"),
            ("causal_bridge", "string"),
            ("causal_bridge_from_goal_to_code", "string"),
            ("invariants", "array"),
            ("negative_memory_checked", "boolean"),
            ("unknowns", "array"),
            ("planned_action", "string"),
            ("expected_verifiers", "array"),
            ("blast_radius_acknowledged", "boolean"),
            ("risk_level", "string"),
        ],
        &[
            "task_id",
            "project_id",
            "goal",
            "current_truth_refs",
            "evidence_refs",
            "causal_bridge",
            "invariants",
            "negative_memory_checked",
            "unknowns",
            "planned_action",
            "expected_verifiers",
            "risk_level",
        ],
    )
}

fn codecortex_scan_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("goal", "string"),
            ("exact_patterns", "array"),
            ("max_files", "integer"),
            ("max_matches_per_pattern", "integer"),
            ("include_diagnostics", "boolean"),
        ],
        &["project", "task", "goal"],
    )
}

fn action_plan_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("project_id", "string"),
            ("task", "string"),
            ("task_id", "string"),
            ("goal", "string"),
            ("requested_action_kind", "string"),
            ("change_plan", "object"),
            ("verifier_plan", "object"),
        ],
        &["goal"],
    )
}

fn action_lease_status_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("project_id", "string"),
            ("task", "string"),
            ("task_id", "string"),
        ],
        &[],
    )
}

fn patch_apply_schema() -> Value {
    json_schema(
        &[("lease_id", "string"), ("diff_text", "string")],
        &["lease_id", "diff_text"],
    )
}

fn work_create_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("goal", "string"),
            ("read", "array"),
            ("write", "array"),
        ],
        &["project", "task", "goal"],
    )
}

fn work_claim_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("role", "string"),
        ],
        &["project", "task"],
    )
}

fn work_status_schema() -> Value {
    json_schema(
        &[("project", "string"), ("task", "string")],
        &["project", "task"],
    )
}

fn work_lease_schema() -> Value {
    json_schema(&[("lease_id", "string")], &["lease_id"])
}

fn worktree_create_schema() -> Value {
    json_schema(&[("lease_id", "string")], &["lease_id"])
}

fn worktree_status_schema() -> Value {
    json_schema(
        &[
            ("worktree_lease", "string"),
            ("worktree_lease_id", "string"),
        ],
        &[],
    )
}

fn worktree_lease_schema() -> Value {
    json_schema(&[("worktree_lease", "string")], &["worktree_lease"])
}

fn worktree_review_schema() -> Value {
    json_schema(
        &[("candidate_diff", "string"), ("decision", "string")],
        &["candidate_diff", "decision"],
    )
}

fn blackboard_add_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("kind", "string"),
            ("payload_ref", "string"),
            ("evidence", "array"),
            ("confidence", "string"),
        ],
        &["project", "task", "payload_ref"],
    )
}

fn blackboard_ack_schema() -> Value {
    json_schema(
        &[
            ("item", "string"),
            ("item_id", "string"),
            ("session", "string"),
        ],
        &[],
    )
}

fn mailbox_send_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("kind", "string"),
            ("payload_ref", "string"),
            ("recipient", "string"),
            ("message_id", "string"),
        ],
        &["project", "task", "payload_ref"],
    )
}

fn mailbox_ack_schema() -> Value {
    json_schema(&[("message", "string"), ("message_id", "string")], &[])
}

fn tool_success(structured: &Value) -> Result<Value> {
    Ok(json!({
        "content": [{ "type": "text", "text": serde_json::to_string(&structured)? }],
        "structuredContent": structured.clone(),
        "isError": false
    }))
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true
    })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn canonical_project_key(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("project id or stable project key must not be empty");
    }
    let without_extended_prefix = trimmed.strip_prefix("\\\\?\\").unwrap_or(trimmed);
    let normalized = without_extended_prefix
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 512 {
        anyhow::bail!("canonical project key must contain 1..=512 bytes");
    }
    Ok(normalized)
}

fn project_id_from_canonical_key(value: &str) -> ProjectId {
    let identity = format!("eliot://project/{value}");
    let digest = blake3::hash(identity.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ProjectId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

fn parse_project_id(value: &str) -> Result<ProjectId> {
    ProjectId::from_str(value)
        .or_else(|_| canonical_project_key(value).map(|key| project_id_from_canonical_key(&key)))
}

fn parse_forgetting_operator(value: &str) -> Result<ForgettingOperator> {
    match value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "")
        .as_str()
    {
        "suppress" => Ok(ForgettingOperator::Suppress),
        "demote" => Ok(ForgettingOperator::Demote),
        "supersede" => Ok(ForgettingOperator::Supersede),
        "archive" => Ok(ForgettingOperator::Archive),
        "compress" => Ok(ForgettingOperator::Compress),
        "markpoisoned" => Ok(ForgettingOperator::MarkPoisoned),
        "retainauditonly" => Ok(ForgettingOperator::RetainAuditOnly),
        "purge" => anyhow::bail!("purge is not supported by the governed memory lifecycle"),
        other => anyhow::bail!("unknown memory lifecycle operator: {other}"),
    }
}

fn parse_forgetting_reason(value: &str) -> Result<ForgettingReason> {
    match value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "")
        .as_str()
    {
        "stale" => Ok(ForgettingReason::Stale),
        "superseded" => Ok(ForgettingReason::Superseded),
        "lowutility" => Ok(ForgettingReason::LowUtility),
        "poisoned" => Ok(ForgettingReason::Poisoned),
        "privacy" => Ok(ForgettingReason::Privacy),
        "duplicate" => Ok(ForgettingReason::Duplicate),
        "wrongscope" => Ok(ForgettingReason::WrongScope),
        "negativetransfer" => Ok(ForgettingReason::NegativeTransfer),
        "falseactivation" => Ok(ForgettingReason::FalseActivation),
        "contextbloat" => Ok(ForgettingReason::ContextBloat),
        "verifiercontradicted" => Ok(ForgettingReason::VerifierContradicted),
        other => anyhow::bail!("unknown memory lifecycle reason: {other}"),
    }
}

fn consistency(at_least_revision: Option<u64>) -> ReadConsistencyMode {
    at_least_revision.map_or(ReadConsistencyMode::Latest, |_| {
        ReadConsistencyMode::AtLeastRevision
    })
}

fn revision(at_least_revision: Option<u64>) -> Option<MemoryRevision> {
    at_least_revision.map(MemoryRevision::new)
}

fn write_json_report<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    writeln!(file)?;
    Ok(())
}

async fn write_codecortex_report_to_memory(
    state: &McpState,
    report: &mut CodeCortexReport,
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    CodeCortexMemoryWriter::write_report(&handle, &admission, report).await?;
    Ok(())
}

async fn write_memory_influence_to_memory(
    state: &McpState,
    report: &mut MemoryInfluenceReport,
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    MemoryLifecycleMemoryWriter::write_influence_report(&handle, &admission, report).await?;
    Ok(())
}

async fn write_skill_card_to_memory(
    state: &McpState,
    skill: &SkillCardV2,
) -> Result<eliot_types::WriteReceiptRef> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    let receipt = SkillRegistryService::write_skill_card(&handle, &admission, skill).await?;
    Ok(receipt)
}

async fn write_skill_execution_proof_to_memory(
    state: &McpState,
    proof: &mut eliot_types::SkillExecutionProof,
) -> Result<eliot_types::WriteReceiptRef> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    let receipt = SkillExecutionProofService::write_proof(&handle, &admission, proof).await?;
    Ok(receipt)
}

async fn write_skill_curator_run_to_memory(
    state: &McpState,
    run: &mut SkillCuratorRun,
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    SkillCuratorMemoryWriter::write_run(&handle, &admission, run).await?;
    for proposal in &mut run.proposals {
        SkillCuratorMemoryWriter::write_proposal(&handle, &admission, proposal).await?;
    }
    Ok(())
}

fn write_skill_curator_reports(state: &McpState, report: &SkillCurationReport) -> Result<()> {
    write_json_report(
        &state
            .root
            .join("reports")
            .join("skill-curator")
            .join("latest.json"),
        report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("skill-curator")
            .join("latest.md"),
        &typed_report_markdown("Skill Curator", report)?,
    )?;
    let proposals_report = json!({
        "component": "skill_curation_proposals",
        "run_id": report.run.run_id,
        "open_proposals": report.open_proposals,
        "generated_at": report.generated_at
    });
    write_json_report(
        &state
            .root
            .join("reports")
            .join("skill-curation-proposals")
            .join("latest.json"),
        &proposals_report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("skill-curation-proposals")
            .join("latest.md"),
        &typed_report_markdown("Skill Curation Proposals", &proposals_report)?,
    )?;
    write_skill_curator_gate_report(state, &report.gate_decisions)
}

fn write_skill_curator_gate_report(
    state: &McpState,
    gate_decisions: &[SkillCurationGateDecision],
) -> Result<()> {
    let gate_report = json!({
        "component": "skill_curation_gate",
        "gate_decisions": gate_decisions,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_json_report(
        &state
            .root
            .join("reports")
            .join("skill-curation-gate")
            .join("latest.json"),
        &gate_report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("skill-curation-gate")
            .join("latest.md"),
        &typed_report_markdown("Skill Curation Gate", &gate_report)?,
    )
}

fn latest_skill_curator_run(root: &Path) -> Result<Option<SkillCuratorRun>> {
    let path = root
        .join("reports")
        .join("skill-curator")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    let report: SkillCurationReport = serde_json::from_reader(std::fs::File::open(path)?)?;
    Ok(Some(report.run))
}

fn find_skill_curation_proposal(root: &Path, proposal_id: &str) -> Result<SkillCurationProposal> {
    let run = latest_skill_curator_run(root)?
        .context("no latest skill-curator run found; call eliot_skill_curator_run first")?;
    if proposal_id == "latest" {
        return run
            .proposals
            .into_iter()
            .next()
            .context("no latest skill curation proposal found");
    }
    if let Some(action) = parse_skill_curation_action(proposal_id) {
        return run
            .proposals
            .into_iter()
            .find(|proposal| proposal.action == action)
            .with_context(|| format!("no skill curation proposal for action {proposal_id}"));
    }
    run.proposals
        .into_iter()
        .find(|proposal| proposal.proposal_id == proposal_id)
        .with_context(|| format!("skill curation proposal not found: {proposal_id}"))
}

fn parse_skill_curation_action(value: &str) -> Option<SkillCurationAction> {
    match value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "")
        .as_str()
    {
        "keep" => Some(SkillCurationAction::Keep),
        "patch" => Some(SkillCurationAction::Patch),
        "archive" => Some(SkillCurationAction::Archive),
        "quarantine" => Some(SkillCurationAction::Quarantine),
        "split" => Some(SkillCurationAction::Split),
        "merge" => Some(SkillCurationAction::Merge),
        "promote" => Some(SkillCurationAction::Promote),
        _ => None,
    }
}

async fn write_patch_memory(
    state: &McpState,
    patch_run: &mut eliot_types::PatchRun,
    verifier_runs: &mut [VerifierRun],
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    for verifier_run in verifier_runs {
        PatchMemoryWriter::write_verifier_run(&handle, &admission, verifier_run).await?;
    }
    PatchMemoryWriter::write_patch_run(&handle, &admission, patch_run).await?;
    Ok(())
}

fn patch_request_from_input(
    root: &Path,
    lease_id: &str,
    diff_text: String,
) -> Result<(PatchRequest, ActionLease, CodeCortexReport, VerifierPlan)> {
    let lease = latest_action_lease(root)?;
    if lease.lease_id.to_string() != lease_id {
        anyhow::bail!("requested lease_id does not match latest ActionLease report");
    }
    let report = latest_codecortex_report(root)?
        .context("no latest CodeCortex report found; call eliot_codecortex_scan first")?;
    let verifier_plan = lease
        .verifier_plan
        .clone()
        .context("latest ActionLease has no VerifierPlan")?;
    let scope = lease
        .allowed_scope
        .as_ref()
        .context("latest ActionLease has no ActionScope")?;
    let request = PatchRequest {
        patch_request_id: PatchRequestId::new_v7(),
        project_id: lease.project_id,
        task_id: lease.task_id,
        agent_id: lease.agent_id,
        action_lease_id: lease.lease_id,
        repo_root: scope.repo_root.clone(),
        git_head_before: scope.git_head.clone(),
        codecortex_report_refs: vec![eliot_engine::codecortex_report_ref(&report)],
        verifier_plan_ref: format!("verifier_plan:{}", lease.lease_id),
        diff: UnifiedDiff {
            byte_len: diff_text.len(),
            text: diff_text,
        },
        created_at: time::OffsetDateTime::now_utc(),
    };
    Ok((request, lease, report, verifier_plan))
}

fn latest_action_lease(root: &Path) -> Result<ActionLease> {
    let latest = action_plan::latest_action_lease_report(root)?
        .context("no latest ActionLease report found; call eliot_action_plan first")?;
    serde_json::from_value(
        latest
            .get("record")
            .and_then(|record| record.get("lease"))
            .cloned()
            .context("latest ActionLease report is missing record.lease")?,
    )
    .map_err(Into::into)
}

fn patch_repo_root(lease: &ActionLease) -> Result<PathBuf> {
    lease
        .allowed_scope
        .as_ref()
        .map(|scope| PathBuf::from(&scope.repo_root))
        .context("ActionLease has no allowed scope repo_root")
}

fn patch_work_lease(
    action_lease: &ActionLease,
    report: &CodeCortexReport,
    verifier_plan: &VerifierPlan,
) -> WorkLease {
    let now = time::OffsetDateTime::now_utc();
    let work_lease_id = WorkLeaseId::new_v7();
    let action_scope = action_lease.allowed_scope.as_ref();
    let write_set = action_scope
        .map(|scope| scope.allowed_files.clone())
        .unwrap_or_default();
    let repo_root =
        action_scope.map_or_else(|| report.repo_root.clone(), |scope| scope.repo_root.clone());
    let verifier_set = verifier_plan
        .required
        .iter()
        .map(|verifier| verifier.command_display.clone())
        .collect::<Vec<_>>();
    WorkLease {
        work_lease_id,
        work_item_id: WorkItemId::new_v7(),
        agent_session_id: AgentSessionId::new_v7(),
        agent_id: action_lease.agent_id,
        project_id: action_lease.project_id,
        task_id: action_lease.task_id,
        role: AgentRole::Implementer,
        state: WorkLeaseState::Granted,
        epoch: 0,
        scope: default_work_scope(repo_root, write_set.clone(), write_set, verifier_set),
        decision: WorkLeaseDecision {
            kind: WorkLeaseDecisionKind::Granted,
            reason: WorkLeaseDecisionReason::NoConflict,
            message: "bounded MCP patch work scope".to_owned(),
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

fn codecortex_latest_path(root: &Path) -> PathBuf {
    root.join("reports").join("codecortex").join("latest.json")
}

fn patch_latest_path(root: &Path) -> PathBuf {
    root.join("reports").join("patch").join("latest.json")
}

fn latest_codecortex_report(root: &Path) -> Result<Option<CodeCortexReport>> {
    let path = codecortex_latest_path(root);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn latest_json_report(path: &Path) -> Result<Option<Value>> {
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn external_review_latest_path(root: &Path, report_dir: &str) -> PathBuf {
    root.join("reports").join(report_dir).join("latest.json")
}

fn antigravity_latest_path(root: &Path, report_dir: &str) -> PathBuf {
    root.join("reports").join(report_dir).join("latest.json")
}

fn write_external_review_mcp_report<T>(
    state: &McpState,
    report_dir: &str,
    title: &str,
    value: &T,
) -> Result<()>
where
    T: serde::Serialize,
{
    let json_path = external_review_latest_path(&state.root, report_dir);
    write_json_report(&json_path, value)?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join(report_dir)
            .join("latest.md"),
        &typed_report_markdown(title, value)?,
    )
}

fn write_antigravity_mcp_report<T>(
    state: &McpState,
    report_dir: &str,
    title: &str,
    value: &T,
) -> Result<()>
where
    T: serde::Serialize,
{
    let json_path = antigravity_latest_path(&state.root, report_dir);
    write_json_report(&json_path, value)?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join(report_dir)
            .join("latest.md"),
        &typed_report_markdown(title, value)?,
    )
}

fn write_antigravity_mcp_invocation_receipt(state: &McpState, tool_name: &str) -> Result<()> {
    let event_id = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    let audit_event_ref = format!("reports/antigravity-mcp-invocations/events/{event_id}.json");
    let receipt = AntigravityMcpBoundaryService.invocation_receipt_with_audit(
        state.profile.as_str(),
        tool_name,
        true,
        Some(&audit_event_ref),
    )?;
    write_antigravity_mcp_report(
        state,
        "antigravity-mcp-invocations",
        "Antigravity MCP Invocation",
        &receipt,
    )?;
    let event_path = state.root.join(&audit_event_ref);
    write_json_report(&event_path, &receipt)?;
    write_markdown_report(
        &event_path.with_extension("md"),
        &typed_report_markdown("Antigravity MCP Invocation Event", &receipt)?,
    )
}

fn mcp_antigravity_resolution_probe_contract() -> (
    AntigravityBinaryResolution,
    AntigravityCapabilityProbe,
    AntigravityCommandContract,
) {
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    let probe = AntigravityCapabilityProbeService.probe_from_resolution(&resolution);
    let contract = AntigravityCommandContractService.build(&resolution, &probe);
    (resolution, probe, contract)
}

fn mcp_antigravity_home() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

fn mcp_antigravity_installation_readiness() -> (bool, bool) {
    let home = mcp_antigravity_home();
    let plugin = AntigravityOfficialPluginService.status(&home);
    let plugin_ready = (plugin.gui_installed || plugin.cli_installed)
        && plugin.official_schema_valid
        && plugin.skill_visible
        && plugin.agent_visible
        && plugin.rule_visible;
    let mcp_registered = AntigravityMcpConfigService
        .status(&home)
        .iter()
        .any(|status| {
            status.surface == eliot_types::AntigravityMcpConfigSurface::Gui && status.registered
        });
    (plugin_ready, mcp_registered)
}

fn latest_antigravity_mcp_run(state: &McpState) -> Result<Option<AntigravityRun>> {
    latest_json_report(&antigravity_latest_path(&state.root, "antigravity-runs"))?
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

fn latest_antigravity_mcp_typed<T>(state: &McpState, report_dir: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    Ok(
        latest_json_report(&antigravity_latest_path(&state.root, report_dir))?
            .and_then(|value| serde_json::from_value(value).ok()),
    )
}

fn parse_antigravity_mode(value: &str) -> Result<AntigravityReviewMode> {
    match value {
        "audit-plan" | "audit_plan" => Ok(AntigravityReviewMode::AuditPlan),
        "candidate-implementation" | "candidate_implementation" => {
            Ok(AntigravityReviewMode::CandidateImplementation)
        }
        other => anyhow::bail!("unknown Antigravity review mode: {other}"),
    }
}

fn mcp_antigravity_tools_governed_only() -> bool {
    AntigravityMcpBoundaryService.exposes_only_governed(governed_tool_names())
}

fn parse_external_review_role(value: &str) -> Result<ExternalReviewRole> {
    match value {
        "auditor" => Ok(ExternalReviewRole::Auditor),
        "reviewer" => Ok(ExternalReviewRole::Reviewer),
        "critic" => Ok(ExternalReviewRole::Critic),
        "worker" => Ok(ExternalReviewRole::Worker),
        other => anyhow::bail!("unknown external review role: {other}"),
    }
}

fn external_output_schema_for(
    request: &ExternalReviewRequest,
    profile: &ExternalProviderProfile,
) -> ExternalOutputSchemaKind {
    if request.role == ExternalReviewRole::Worker
        || profile.provider_id == "mock-proposed-change"
        || profile
            .output_schemas
            .contains(&ExternalOutputSchemaKind::ProposedChanges)
    {
        ExternalOutputSchemaKind::ProposedChanges
    } else if profile
        .output_schemas
        .contains(&ExternalOutputSchemaKind::MixedReview)
    {
        ExternalOutputSchemaKind::MixedReview
    } else {
        ExternalOutputSchemaKind::AuditFindings
    }
}

fn ensure_external_review_work_lease(
    state: &McpState,
    request: &mut ExternalReviewRequest,
) -> Result<(WorkState, Option<WorkLease>)> {
    let mut work_state = load_work_state(&state.root)?;
    let controller = AgentSessionService.create_controller(&mut work_state, request.project_id);
    let item = WorkQueueService.create_work_item(
        &mut work_state,
        WorkCreateRequest {
            project_id: request.project_id,
            task_id: request.task_id,
            project: request.project.clone(),
            task: request.task.clone(),
            goal: request.question.clone(),
            scope: default_work_scope(
                std::env::current_dir()?.display().to_string(),
                request.allowed_paths.clone(),
                Vec::new(),
                vec!["provider-integration".to_owned()],
            ),
            required: true,
            created_by: controller.agent_session_id,
            required_verifiers: Vec::new(),
        },
    );
    let decision = WorkLeaseService.claim(
        &mut work_state,
        WorkClaimRequest {
            work_item_id: item.work_item_id,
            agent_session_id: controller.agent_session_id,
            role: AgentRole::Auditor,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let work_lease = decision.work_lease_id.and_then(|lease_id| {
        work_state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == lease_id)
            .cloned()
    });
    request.work_lease_id = work_lease.as_ref().map(|lease| lease.work_lease_id);
    Ok((work_state, work_lease))
}

fn external_review_report_status(root: &Path, report_dir: &str) -> Value {
    let path = external_review_latest_path(root, report_dir);
    json!({
        "path": path,
        "exists": path.is_file()
    })
}

fn external_review_tools_governed_only() -> bool {
    [
        "eliot_external_review_providers",
        "eliot_external_review_request",
        "eliot_external_review_job_status",
        "eliot_external_review_result",
        "eliot_external_review_report",
        "eliot_external_review_run_mock",
    ]
    .into_iter()
    .all(|tool| GOVERNED_TOOLS.contains(&tool))
        && GOVERNED_TOOLS.iter().all(|tool| {
            ![
                "raw_exec",
                "raw_secret",
                "raw_patch",
                "raw_truth",
                "run_gemini",
                "run_antigravity",
            ]
            .into_iter()
            .any(|forbidden| tool.contains(forbidden))
        })
}

fn filter_report_item(report: &Value, array_key: &str, id_key: &str, id_value: &str) -> Value {
    report
        .get(array_key)
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .find(|value| value.get(id_key).and_then(Value::as_str) == Some(id_value))
        })
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "status": "not_found",
                "array": array_key,
                "id_key": id_key,
                "id_value": id_value
            })
        })
}

fn read_json_file<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
}

async fn write_work_entities(
    state: &McpState,
    work_state: &mut WorkState,
    session_id: Option<AgentSessionId>,
    item_id: Option<WorkItemId>,
    lease_id: Option<WorkLeaseId>,
    conflict_ids: &[String],
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    if let Some(session_id) = session_id
        && let Some(session) = work_state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == session_id)
    {
        WorkMemoryWriter::write_session(&handle, &admission, session).await?;
    }
    if let Some(item_id) = item_id
        && let Some(item) = work_state
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == item_id)
    {
        WorkMemoryWriter::write_work_item(&handle, &admission, item).await?;
    }
    if let Some(lease_id) = lease_id
        && let Some(lease) = work_state
            .leases
            .iter_mut()
            .find(|lease| lease.work_lease_id == lease_id)
    {
        WorkMemoryWriter::write_work_lease(&handle, &admission, lease).await?;
    }
    for conflict_id in conflict_ids {
        if let Some(conflict) = work_state
            .conflicts
            .iter()
            .find(|conflict| &conflict.conflict_id == conflict_id)
            && let Some(item) = work_state
                .work_items
                .iter()
                .find(|item| item.work_item_id == conflict.work_item_id)
        {
            let agent_id = work_state
                .leases
                .iter()
                .find(|lease| lease.work_item_id == item.work_item_id)
                .map_or_else(eliot_types::AgentId::new_v7, |lease| lease.agent_id);
            let _ = WorkMemoryWriter::write_conflict(
                &handle,
                &admission,
                item.project_id,
                item.task_id,
                agent_id,
                conflict,
            )
            .await?;
        }
    }
    Ok(())
}

fn load_work_state(root: &Path) -> Result<WorkState> {
    let path = root.join("reports").join("work").join("state.json");
    if !path.is_file() {
        return Ok(WorkState::default());
    }
    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
}

fn save_work_state_and_report(
    root: &Path,
    state: &WorkState,
    report: &eliot_engine::WorkStatusReport,
) -> Result<()> {
    let work_dir = root.join("reports").join("work");
    std::fs::create_dir_all(&work_dir)?;
    serde_json::to_writer_pretty(std::fs::File::create(work_dir.join("state.json"))?, state)?;
    std::fs::write(work_dir.join("state.md"), "# Work State\n")?;
    write_json_report(&work_dir.join("latest.json"), report)?;
    std::fs::write(work_dir.join("latest.md"), work_report_markdown(report))?;
    Ok(())
}

fn save_worktree_state_and_reports(root: &Path, state: &WorkState) -> Result<()> {
    let work_dir = root.join("reports").join("work");
    std::fs::create_dir_all(&work_dir)?;
    serde_json::to_writer_pretty(std::fs::File::create(work_dir.join("state.json"))?, state)?;
    std::fs::write(work_dir.join("state.md"), "# Work State\n")?;

    let worktree_report = json!({
        "component": "worktree",
        "worktree_lease_count": state.worktree_leases.len(),
        "latest_worktree_lease": state.worktree_leases.last(),
        "final_status": if state.worktree_leases.is_empty() { "NO_WORKTREE" } else { "DONE_VERIFIED" }
    });
    write_json_report(
        &root.join("reports").join("worktree").join("latest.json"),
        &worktree_report,
    )?;
    write_markdown_report(
        &root.join("reports").join("worktree").join("latest.md"),
        &worktree_report_markdown(&worktree_report),
    )?;

    let candidate_report = json!({
        "component": "candidate_diff",
        "candidate_diff_count": state.candidate_diffs.len(),
        "candidate_review_count": state.candidate_reviews.len(),
        "latest_candidate_diff": state.candidate_diffs.last(),
        "latest_candidate_review": state.candidate_reviews.last(),
        "final_status": if state.candidate_diffs.is_empty() { "NO_CANDIDATE_DIFF" } else { "DONE_VERIFIED" }
    });
    write_json_report(
        &root
            .join("reports")
            .join("candidate-diff")
            .join("latest.json"),
        &candidate_report,
    )?;
    write_markdown_report(
        &root
            .join("reports")
            .join("candidate-diff")
            .join("latest.md"),
        &candidate_diff_report_markdown(&candidate_report),
    )?;
    Ok(())
}

fn write_markdown_report(path: &Path, markdown: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, markdown)?;
    Ok(())
}

fn typed_report_markdown<T: serde::Serialize>(title: &str, report: &T) -> Result<String> {
    Ok(format!(
        "# {title}\n\n```json\n{}\n```\n",
        serde_json::to_string_pretty(report)?
    ))
}

fn worktree_report_markdown(report: &Value) -> String {
    format!(
        "# Worktree\n\n- worktree_lease_count: `{}`\n- final_status: `{}`\n",
        report
            .get("worktree_lease_count")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        report
            .get("final_status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    )
}
