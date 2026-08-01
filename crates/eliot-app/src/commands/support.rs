fn write_report(report: &StartupHealthReport) -> Result<()> {
    write_json(report)
}

fn write_json<T>(value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value)?;
    writeln!(lock)?;
    Ok(())
}

fn db_report_path(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("db")
        .join("smoke-latest.md")
}

fn runtime_root(config_path: &Path) -> PathBuf {
    let resolved = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(config_path)
    };
    resolved
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(".eliot-governor"))
        .to_path_buf()
}

fn surreal_logical_config(config_path: &Path) -> Result<SurrealLogicalConfig> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let surreal = config.db.surreal;
    let password_file = resolve_runtime_config_path(&root, &surreal.password_file);
    let legacy_password_file_authorized =
        std::env::var("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION").as_deref() == Ok("1")
            || (std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref() == Ok("1")
                && std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")
                    .ok()
                    .map(|path| resolve_runtime_config_path(&root, &path))
                    .as_ref()
                    == Some(&password_file));
    Ok(SurrealLogicalConfig {
        executable: resolve_runtime_executable_path(&root, &surreal.exe),
        endpoint: surreal.endpoint,
        namespace: surreal.ns,
        database: surreal.db,
        username: surreal.user,
        credential_provider: surreal.credential_provider,
        credential_id: surreal.credential_id,
        password_file,
        legacy_password_file_authorized,
        storage_root: surreal
            .storage
            .strip_prefix("rocksdb:")
            .map(|path| resolve_runtime_config_path(&root, path)),
    })
}

fn target_store_fingerprint(config_path: &Path) -> Result<String> {
    let config = load_config(config_path)?;
    Ok(format!(
        "{}|{}|{}",
        config.db.surreal.endpoint, config.db.surreal.ns, config.db.surreal.db
    ))
}

fn resolve_runtime_config_path(root: &Path, configured: &str) -> PathBuf {
    for prefix in ["%LOCALAPPDATA%/", "%LOCALAPPDATA%\\"] {
        if let Some(relative) = configured.strip_prefix(prefix)
            && let Some(local) = std::env::var_os("LOCALAPPDATA")
        {
            return PathBuf::from(local).join(relative);
        }
    }
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        return path;
    }
    let normalized = configured.replace('\\', "/");
    if normalized.starts_with(".eliot-governor/")
        && root.file_name().and_then(|name| name.to_str()) == Some(".eliot-governor")
    {
        return root.parent().unwrap_or_else(|| Path::new(".")).join(path);
    }
    root.join(path)
}

fn resolve_runtime_executable_path(root: &Path, configured: &str) -> PathBuf {
    let path = PathBuf::from(configured);
    if path.components().count() == 1 {
        path
    } else {
        resolve_runtime_config_path(root, configured)
    }
}

fn parse_project_id(value: &str) -> Result<ProjectId> {
    ProjectId::from_str(value).with_context(|| format!("parse project id {value}"))
}

fn lifecycle_policy_from_cli(
    project: &str,
    memory_ref: &str,
    operator: &str,
    reason: &str,
) -> Result<ForgettingPolicy> {
    let operator = parse_forgetting_operator(operator)?;
    let reason = parse_forgetting_reason(reason)?;
    let superseding_ref =
        (operator == ForgettingOperator::Supersede).then(|| format!("{memory_ref}:superseding"));
    Ok(ForgettingPolicyService::propose(
        project_id_from_label(project),
        memory_ref,
        operator,
        reason,
        vec!["cli:memory-lifecycle:proposal".to_owned()],
        superseding_ref,
        None,
    ))
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
        "purge" => bail!("purge is not supported by the governed memory lifecycle"),
        other => bail!("unknown memory lifecycle operator: {other}"),
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
        other => bail!("unknown memory lifecycle reason: {other}"),
    }
}

fn smoke_context(
    project_id: ProjectId,
    agent_id: AgentId,
    task_id: Option<TaskId>,
) -> CommandContext {
    CommandContext {
        write_id: eliot_types::WriteId::new_v7(),
        agent_id,
        session_id: None,
        project_id,
        task_id,
        scope: "writer-smoke".to_owned(),
        authority: "local-smoke".to_owned(),
        visibility: Visibility::Internal,
        taint: TaintClass::LocalVerified,
        lifecycle_status: LifecycleStatus::Active,
    }
}

struct PatchCliInput {
    request: PatchRequest,
    lease: ActionLease,
    work_lease: WorkLease,
    report: CodeCortexReport,
    verifier_plan: VerifierPlan,
}

fn load_patch_cli_input(root: &Path, lease_id: &str, diff_path: &Path) -> Result<PatchCliInput> {
    let lease = latest_action_lease(root)?;
    if lease.lease_id.to_string() != lease_id {
        bail!("requested lease id does not match latest ActionLease report");
    }
    let report = action_plan::latest_codecortex_report(root)?
        .context("no latest CodeCortex report found; run codecortex scan first")?;
    let verifier_plan = lease
        .verifier_plan
        .clone()
        .context("latest ActionLease does not contain a VerifierPlan")?;
    let scope = lease
        .allowed_scope
        .as_ref()
        .context("latest ActionLease does not contain an ActionScope")?;
    let diff_text = std::fs::read_to_string(diff_path)
        .with_context(|| format!("read diff {}", diff_path.display()))?;
    let request = PatchRequest {
        patch_request_id: PatchRequestId::new_v7(),
        project_id: lease.project_id,
        task_id: lease.task_id,
        agent_id: lease.agent_id,
        action_lease_id: lease.lease_id,
        repo_root: scope.repo_root.clone(),
        git_head_before: scope.git_head.clone(),
        codecortex_report_refs: vec![codecortex_report_ref(&report)],
        verifier_plan_ref: format!("verifier_plan:{}", lease.lease_id),
        diff: UnifiedDiff {
            byte_len: diff_text.len(),
            text: diff_text,
        },
        created_at: time::OffsetDateTime::now_utc(),
    };
    let work_lease = patch_work_lease(&lease, &report, &verifier_plan);
    Ok(PatchCliInput {
        request,
        lease,
        work_lease,
        report,
        verifier_plan,
    })
}

fn latest_action_lease(root: &Path) -> Result<ActionLease> {
    let latest = action_plan::latest_action_lease_report(root)?
        .context("no latest ActionLease report found; run action plan first")?;
    serde_json::from_value(
        latest
            .get("record")
            .and_then(|record| record.get("lease"))
            .cloned()
            .context("latest ActionLease report is missing record.lease")?,
    )
    .context("parse latest ActionLease report")
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
            message: "bounded patch runner work scope".to_owned(),
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

async fn write_e2_runs_to_memory(
    config_path: &Path,
    patch_run: &mut PatchRun,
    verifier_runs: &mut [VerifierRun],
) -> Result<()> {
    write_e2_runs_to_memory_optional_patch(config_path, Some(patch_run), verifier_runs).await
}

async fn write_e2_runs_to_memory_optional_patch(
    config_path: &Path,
    patch_run: Option<&mut PatchRun>,
    verifier_runs: &mut [VerifierRun],
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    for verifier_run in verifier_runs {
        PatchMemoryWriter::write_verifier_run(&handle, &admission, verifier_run).await?;
    }
    if let Some(patch_run) = patch_run {
        PatchMemoryWriter::write_patch_run(&handle, &admission, patch_run).await?;
    }
    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn write_codecortex_report_to_memory(
    config_path: &Path,
    report: &mut CodeCortexReport,
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let writer_config = WriterConfig::default();
    let (handle, actor) = WriterActor::channel(wal, store, &writer_config);
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    CodeCortexMemoryWriter::write_report(&handle, &admission, report).await?;
    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn apply_lifecycle_policy_to_memory(
    config_path: &Path,
    policy: &ForgettingPolicy,
) -> Result<eliot_engine::MemoryLifecycleApplyOutcome> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let latest_transition = store
        .canonical_records_by_subject_ref::<MemoryStateTransition>(
            policy.project_id,
            None,
            &["state_transition"],
            &policy.target_ref,
            1,
        )
        .await?
        .into_iter()
        .next();
    let lifecycle = latest_transition.map_or_else(MemoryLifecycleService::new, |record| {
        MemoryLifecycleService::new().with_state(&policy.target_ref, record.receipt_body.to_state)
    });
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let outcome = lifecycle
        .apply_policy_through_writer(
            &handle,
            &WriteAdmissionService,
            policy,
            "eliot-governor-cli",
        )
        .await?;
    drop(handle);
    actor_task.await?;
    Ok(outcome)
}

async fn write_memory_influence_to_memory(
    config_path: &Path,
    report: &mut MemoryInfluenceReport,
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    MemoryLifecycleMemoryWriter::write_influence_report(&handle, &WriteAdmissionService, report)
        .await?;
    drop(handle);
    actor_task.await?;
    Ok(())
}

fn write_memory_lifecycle_report(root: &Path, report: &MemoryLifecycleReport) -> Result<()> {
    write_report_pair(
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.md"),
        report,
        &typed_report_markdown("Memory Lifecycle", report)?,
    )
}

fn write_memory_vitality_report(root: &Path, score: &MemoryVitalityScore) -> Result<()> {
    write_report_pair(
        &root
            .join("reports")
            .join("memory-vitality")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-vitality")
            .join("latest.md"),
        score,
        &typed_report_markdown("Memory Vitality", score)?,
    )
}

fn write_memory_gravity_report(root: &Path, gravity: &MemoryGravity) -> Result<()> {
    write_report_pair(
        &root
            .join("reports")
            .join("memory-gravity")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-gravity")
            .join("latest.md"),
        gravity,
        &typed_report_markdown("Memory Gravity", gravity)?,
    )
}

fn write_memory_influence_report(root: &Path, report: &MemoryInfluenceReport) -> Result<()> {
    write_report_pair(
        &root
            .join("reports")
            .join("memory-influence")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-influence")
            .join("latest.md"),
        report,
        &typed_report_markdown("Memory Influence", report)?,
    )
}

fn write_skill_report_pair<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn write_skill_influence_report(root: &Path, report: &SkillInfluenceReport) -> Result<()> {
    write_skill_report_pair(root, "skill-influence", "Skill Influence", report)
}

fn read_optional_report<T>(root: &Path, name: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    let path = root.join("reports").join(name).join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

async fn write_skill_card_to_memory(
    config_path: &Path,
    skill: &SkillCardV2,
) -> Result<eliot_types::WriteReceiptRef> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    let receipt = SkillRegistryService::write_skill_card(&handle, &admission, skill).await?;
    drop(handle);
    actor_task.await?;
    Ok(receipt)
}

async fn write_skill_execution_proof_to_memory(
    config_path: &Path,
    proof: &mut eliot_types::SkillExecutionProof,
) -> Result<eliot_types::WriteReceiptRef> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    let receipt = SkillExecutionProofService::write_proof(&handle, &admission, proof).await?;
    drop(handle);
    actor_task.await?;
    Ok(receipt)
}

async fn write_skill_influence_to_memory(
    config_path: &Path,
    report: &mut SkillInfluenceReport,
) -> Result<eliot_types::WriteReceiptRef> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    let receipt = SkillInfluenceService::write_report(&handle, &admission, report).await?;
    drop(handle);
    actor_task.await?;
    Ok(receipt)
}

async fn write_skill_curator_run_to_memory(
    config_path: &Path,
    run: &mut SkillCuratorRun,
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    SkillCuratorMemoryWriter::write_run(&handle, &admission, run).await?;
    for proposal in &mut run.proposals {
        SkillCuratorMemoryWriter::write_proposal(&handle, &admission, proposal).await?;
    }
    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn write_skill_curation_receipt_to_memory(
    config_path: &Path,
    receipt: &mut SkillCurationReceipt,
) -> Result<eliot_types::WriteReceiptRef> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let write_receipt =
        SkillCuratorMemoryWriter::write_receipt(&handle, &WriteAdmissionService, receipt).await?;
    drop(handle);
    actor_task.await?;
    Ok(write_receipt)
}

fn write_skill_curator_reports(
    root: &Path,
    run: &SkillCuratorRun,
    gate_decisions: &[SkillCurationGateDecision],
) -> Result<()> {
    let report = SkillCurationReport {
        component: "skill_curator".to_owned(),
        run: run.clone(),
        open_proposals: run.proposals.clone(),
        gate_decisions: gate_decisions.to_vec(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_skill_report_pair(root, "skill-curator", "Skill Curator", &report)?;

    let proposals_report = serde_json::json!({
        "component": "skill_curation_proposals",
        "run_id": run.run_id,
        "project_id": run.project_id,
        "open_proposals": run.proposals,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_skill_report_pair(
        root,
        "skill-curation-proposals",
        "Skill Curation Proposals",
        &proposals_report,
    )?;
    write_skill_curator_gate_report(root, gate_decisions)
}

fn write_skill_curator_gate_report(
    root: &Path,
    gate_decisions: &[SkillCurationGateDecision],
) -> Result<()> {
    let gate_report = serde_json::json!({
        "component": "skill_curation_gate",
        "gate_decisions": gate_decisions,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_skill_report_pair(
        root,
        "skill-curation-gate",
        "Skill Curation Gate",
        &gate_report,
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

fn latest_skill_curation_proposals(root: &Path) -> Result<Vec<SkillCurationProposal>> {
    let Some(run) = latest_skill_curator_run(root)? else {
        return Ok(Vec::new());
    };
    Ok(run.proposals)
}

fn find_skill_curation_proposal(root: &Path, proposal_id: &str) -> Result<SkillCurationProposal> {
    let proposals = latest_skill_curation_proposals(root)?;
    if proposal_id == "latest" {
        return proposals
            .into_iter()
            .next()
            .context("no latest skill curation proposal found");
    }
    if let Some(action) = parse_skill_curation_action(proposal_id) {
        return proposals
            .into_iter()
            .find(|proposal| proposal.action == action)
            .with_context(|| {
                format!("no latest skill curation proposal for action {proposal_id}")
            });
    }
    proposals
        .into_iter()
        .find(|proposal| proposal.proposal_id == proposal_id)
        .with_context(|| format!("skill curation proposal not found: {proposal_id}"))
}

fn parse_skill_curation_action(value: &str) -> Option<SkillCurationAction> {
    match normalized_arg(value).as_str() {
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

async fn write_work_entities(
    config_path: &Path,
    state: &mut WorkState,
    session_id: Option<AgentSessionId>,
    item_id: Option<WorkItemId>,
    lease_id: Option<WorkLeaseId>,
    conflict_ids: &[String],
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;

    if let Some(session_id) = session_id
        && let Some(session) = state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == session_id)
    {
        WorkMemoryWriter::write_session(&handle, &admission, session).await?;
    }
    if let Some(item_id) = item_id
        && let Some(item) = state
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == item_id)
    {
        WorkMemoryWriter::write_work_item(&handle, &admission, item).await?;
    }
    if let Some(lease_id) = lease_id
        && let Some(lease) = state
            .leases
            .iter_mut()
            .find(|lease| lease.work_lease_id == lease_id)
    {
        WorkMemoryWriter::write_work_lease(&handle, &admission, lease).await?;
    }
    for conflict_id in conflict_ids {
        if let Some(conflict) = state
            .conflicts
            .iter()
            .find(|conflict| &conflict.conflict_id == conflict_id)
            && let Some(item) = state
                .work_items
                .iter()
                .find(|item| item.work_item_id == conflict.work_item_id)
        {
            let agent_id = state
                .leases
                .iter()
                .find(|lease| lease.work_item_id == item.work_item_id)
                .map_or_else(AgentId::new_v7, |lease| lease.agent_id);
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

    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn run_work_finish(config_path: &Path, lease_id: &str, release: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let lease_id = WorkLeaseId::from_str(lease_id).context("parse work lease id")?;
    let decision = if release {
        WorkLeaseService.release(&mut state, lease_id)
    } else {
        WorkLeaseService.revoke(&mut state, lease_id)
    };
    write_work_entities(
        config_path,
        &mut state,
        None,
        None,
        decision.work_lease_id,
        &[],
    )
    .await?;
    let (project, task) = labels_for_lease(&state, lease_id);
    let report = WorkQueueService.status_report(&state, &project, &task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

fn load_work_state(root: &Path) -> Result<WorkState> {
    let path = work_state_path(root);
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
    write_report_pair(
        &work_state_path(root),
        &work_state_markdown_path(root),
        state,
        "",
    )?;
    write_report_pair(
        &root.join("reports").join("work").join("latest.json"),
        &root.join("reports").join("work").join("latest.md"),
        report,
        &work_report_markdown(report),
    )
}

fn work_state_path(root: &Path) -> PathBuf {
    root.join("reports").join("work").join("state.json")
}

fn work_state_markdown_path(root: &Path) -> PathBuf {
    root.join("reports").join("work").join("state.md")
}

fn work_report_markdown(report: &eliot_engine::WorkStatusReport) -> String {
    let mut output = String::from("# Work Status\n\n");
    let _ = writeln!(output, "- project: `{}`", report.project);
    let _ = writeln!(output, "- task: `{}`", report.task);
    let _ = writeln!(output, "- work_items: `{}`", report.work_items.len());
    let _ = writeln!(output, "- active_leases: `{}`", report.active_leases.len());
    let _ = writeln!(
        output,
        "- worktree_leases: `{}`",
        report.worktree_leases.len()
    );
    let _ = writeln!(
        output,
        "- candidate_diffs: `{}`",
        report.candidate_diffs.len()
    );
    let _ = writeln!(output, "- conflicts: `{}`", report.conflicts.len());
    let _ = writeln!(
        output,
        "- operation_status: `{}`",
        report.operation_status
    );
    output
}

fn save_worktree_state_and_reports(root: &Path, state: &WorkState) -> Result<()> {
    write_report_pair(
        &work_state_path(root),
        &work_state_markdown_path(root),
        state,
        "",
    )?;
    let worktree_report = serde_json::json!({
        "component": "worktree",
        "worktree_lease_count": state.worktree_leases.len(),
        "latest_worktree_lease": state.worktree_leases.last(),
        "operation_status": if state.worktree_leases.is_empty() {
            OperationStatus::OperationCompleted
        } else {
            OperationStatus::Active
        }
    });
    write_report_pair(
        &root.join("reports").join("worktree").join("latest.json"),
        &root.join("reports").join("worktree").join("latest.md"),
        &worktree_report,
        &worktree_report_markdown(&worktree_report),
    )?;
    let candidate_report = serde_json::json!({
        "component": "candidate_diff",
        "candidate_diff_count": state.candidate_diffs.len(),
        "candidate_review_count": state.candidate_reviews.len(),
        "latest_candidate_diff": state.candidate_diffs.last(),
        "latest_candidate_review": state.candidate_reviews.last(),
        "operation_status": if state.candidate_diffs.is_empty() {
            OperationStatus::Active
        } else {
            OperationStatus::OperationCompleted
        }
    });
    write_report_pair(
        &root
            .join("reports")
            .join("candidate-diff")
            .join("latest.json"),
        &root
            .join("reports")
            .join("candidate-diff")
            .join("latest.md"),
        &candidate_report,
        &candidate_diff_report_markdown(&candidate_report),
    )
}

fn worktree_report_markdown(report: &serde_json::Value) -> String {
    format!(
        "# Worktree\n\n- worktree_lease_count: `{}`\n- operation_status: `{}`\n",
        report
            .get("worktree_lease_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
        report
            .get("operation_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
    )
}

fn candidate_diff_report_markdown(report: &serde_json::Value) -> String {
    format!(
        "# Candidate Diff\n\n- candidate_diff_count: `{}`\n- candidate_review_count: `{}`\n- operation_status: `{}`\n",
        report
            .get("candidate_diff_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
        report
            .get("candidate_review_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
        report
            .get("operation_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
    )
}

async fn write_worktree_records(
    config_path: &Path,
    worktree_lease: Option<&mut WorktreeLease>,
    candidate_diff: Option<&mut CandidateDiff>,
    candidate_review: Option<(&mut CandidateReview, &CandidateDiff)>,
    diff_agent_id: Option<AgentId>,
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    if let Some(lease) = worktree_lease {
        WorktreeMemoryWriter::write_worktree_lease(&handle, &admission, lease).await?;
    }
    if let Some(diff) = candidate_diff {
        WorktreeMemoryWriter::write_candidate_diff(
            &handle,
            &admission,
            diff,
            diff_agent_id.unwrap_or_else(AgentId::new_v7),
        )
        .await?;
    }
    if let Some((review, diff)) = candidate_review {
        WorktreeMemoryWriter::write_candidate_review(&handle, &admission, review, diff).await?;
    }
    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn run_blackboard_status_change(
    config_path: &Path,
    item_id: &str,
    session: Option<&str>,
    action: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let item_id = BlackboardItemId::from_str(item_id).context("parse blackboard item id")?;
    let item = match action {
        "ack" => {
            let session_id = session
                .map(AgentSessionId::from_str)
                .transpose()?
                .unwrap_or_else(|| {
                    state
                        .blackboard_items
                        .iter()
                        .find(|item| item.blackboard_item_id == item_id)
                        .map_or_else(AgentSessionId::new_v7, |item| item.owner_session_id)
                });
            BlackboardService.acknowledge(&mut state, item_id, session_id)?
        }
        "resolve" => BlackboardService.resolve(&mut state, item_id)?,
        "reject" => BlackboardService.reject(&mut state, item_id)?,
        other => bail!("unknown blackboard action: {other}"),
    };
    write_collective_entities(
        config_path,
        &mut state,
        &[item.blackboard_item_id],
        &[],
        &[],
        &[],
    )
    .await?;
    let (project, task) = labels_for_project_task(&state, item.project_id, item.task_id);
    save_collective_reports(&root, &state, &project, &task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, &project, &task),
    )?;
    write_json(&serde_json::json!({
        "component": format!("blackboard_{action}"),
        "blackboard_item": state
            .blackboard_items
            .iter()
            .find(|candidate| candidate.blackboard_item_id == item.blackboard_item_id),
        "operation_status": OperationStatus::OperationCompleted
    }))
}

async fn write_collective_entities(
    config_path: &Path,
    state: &mut WorkState,
    blackboard_item_ids: &[BlackboardItemId],
    mailbox_message_ids: &[MailboxMessageId],
    recovery_ids: &[String],
    collective_trace_ids: &[String],
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    for item_id in blackboard_item_ids {
        if let Some(item) = state
            .blackboard_items
            .iter_mut()
            .find(|item| item.blackboard_item_id == *item_id)
        {
            CollectiveMemoryWriter::write_blackboard_item(&handle, &admission, item).await?;
        }
    }
    for message_id in mailbox_message_ids {
        if let Some(message) = state
            .mailbox_messages
            .iter_mut()
            .find(|message| message.message_id == *message_id)
        {
            CollectiveMemoryWriter::write_mailbox_message(&handle, &admission, message).await?;
        }
    }
    for recovery_id in recovery_ids {
        if let Some(record) = state
            .recovery_records
            .iter_mut()
            .find(|record| &record.recovery_id == recovery_id)
        {
            CollectiveMemoryWriter::write_recovery_record(&handle, &admission, record).await?;
        }
    }
    for collective_trace_id in collective_trace_ids {
        if let Some(trace) = state
            .collective_traces
            .iter_mut()
            .find(|trace| &trace.collective_trace_id == collective_trace_id)
        {
            CollectiveMemoryWriter::write_collective_trace(&handle, &admission, trace).await?;
        }
    }
    drop(handle);
    actor_task.await?;
    Ok(())
}

fn save_collective_reports(
    root: &Path,
    state: &WorkState,
    project: &str,
    task: &str,
) -> Result<()> {
    let blackboard = blackboard_report_value(state, project, task);
    write_report_pair(
        &root.join("reports").join("blackboard").join("latest.json"),
        &root.join("reports").join("blackboard").join("latest.md"),
        &blackboard,
        &report_markdown("Blackboard Report", &blackboard),
    )?;
    let mailbox = mailbox_report_value(state, project, task);
    write_report_pair(
        &root.join("reports").join("mailbox").join("latest.json"),
        &root.join("reports").join("mailbox").join("latest.md"),
        &mailbox,
        &report_markdown("Mailbox Report", &mailbox),
    )?;
    let recovery = recovery_report_value(state, project, task);
    write_report_pair(
        &root.join("reports").join("recovery").join("latest.json"),
        &root.join("reports").join("recovery").join("latest.md"),
        &recovery,
        &report_markdown("Recovery Report", &recovery),
    )?;
    let collective = collective_report_value(state, project, task);
    write_report_pair(
        &root.join("reports").join("collective").join("latest.json"),
        &root.join("reports").join("collective").join("latest.md"),
        &collective,
        &report_markdown("Collective Trace Report", &collective),
    )
}

fn blackboard_report_value(state: &WorkState, project: &str, task: &str) -> serde_json::Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let items = state
        .blackboard_items
        .iter()
        .filter(|item| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    item.project_id == project_id && item.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "component": "blackboard",
        "project": project,
        "task": task,
        "items": items,
        "blackboard_candidate_not_truth": true,
        "operation_status": OperationStatus::OperationCompleted
    })
}

fn mailbox_report_value(state: &WorkState, project: &str, task: &str) -> serde_json::Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let messages = state
        .mailbox_messages
        .iter()
        .filter(|message| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    message.project_id == project_id && message.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "component": "mailbox",
        "project": project,
        "task": task,
        "messages": messages,
        "mailbox_grants_no_authority": true,
        "operation_status": OperationStatus::OperationCompleted
    })
}

fn recovery_report_value(state: &WorkState, project: &str, task: &str) -> serde_json::Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let records = state
        .recovery_records
        .iter()
        .filter(|record| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    record.project_id == project_id && record.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "component": "recovery",
        "project": project,
        "task": task,
        "records": records,
        "silent_candidate_promotion": false,
        "operation_status": OperationStatus::OperationCompleted
    })
}

fn collective_report_value(state: &WorkState, project: &str, task: &str) -> serde_json::Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let traces = state
        .collective_traces
        .iter()
        .filter(|trace| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    trace.project_id == project_id && trace.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "component": "collective_trace",
        "project": project,
        "task": task,
        "traces": traces,
        "operation_status": OperationStatus::OperationCompleted
    })
}

fn replace_worktree_lease(state: &mut WorkState, replacement: WorktreeLease) {
    if let Some(existing) = state
        .worktree_leases
        .iter_mut()
        .find(|lease| lease.worktree_lease_id == replacement.worktree_lease_id)
    {
        *existing = replacement;
    } else {
        state.worktree_leases.push(replacement);
    }
}

fn replace_candidate_diff(state: &mut WorkState, replacement: CandidateDiff) {
    if let Some(existing) = state
        .candidate_diffs
        .iter_mut()
        .find(|diff| diff.candidate_diff_id == replacement.candidate_diff_id)
    {
        *existing = replacement;
    } else {
        state.candidate_diffs.push(replacement);
    }
}

fn replace_candidate_review(state: &mut WorkState, replacement: CandidateReview) {
    if let Some(existing) = state
        .candidate_reviews
        .iter_mut()
        .find(|review| review.review_id == replacement.review_id)
    {
        *existing = replacement;
    } else {
        state.candidate_reviews.push(replacement);
    }
}

fn parse_candidate_review_decision(value: &str) -> Result<CandidateReviewDecision> {
    match value.trim().to_ascii_lowercase().as_str() {
        "accept" | "accept-for-patchrunner" | "accept_for_patchrunner" => {
            Ok(CandidateReviewDecision::AcceptForPatchRunner)
        }
        "reject" => Ok(CandidateReviewDecision::Reject),
        "revise" | "require-revision" | "require_revision" => {
            Ok(CandidateReviewDecision::RequireRevision)
        }
        "human" | "require-human-review" | "require_human_review" => {
            Ok(CandidateReviewDecision::RequireHumanReview)
        }
        other => bail!("unknown candidate review decision: {other}"),
    }
}

fn parse_blackboard_kind(value: &str) -> Result<BlackboardItemKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "finding" | "finding_candidate" | "finding-candidate" => {
            Ok(BlackboardItemKind::FindingCandidate)
        }
        "evidence" | "evidence_handle" | "evidence-handle" => {
            Ok(BlackboardItemKind::EvidenceHandle)
        }
        "unknown" => Ok(BlackboardItemKind::Unknown),
        "hypothesis" | "hypothesis_candidate" | "hypothesis-candidate" => {
            Ok(BlackboardItemKind::HypothesisCandidate)
        }
        "conflict" | "conflict_notice" | "conflict-notice" => {
            Ok(BlackboardItemKind::ConflictNotice)
        }
        "decision" | "decision_request" | "decision-request" => {
            Ok(BlackboardItemKind::DecisionRequest)
        }
        "verifier" | "verifier_result" | "verifier-result" => {
            Ok(BlackboardItemKind::VerifierResult)
        }
        "artifact" | "artifact_handle" | "artifact-handle" => {
            Ok(BlackboardItemKind::ArtifactHandle)
        }
        "blocker" => Ok(BlackboardItemKind::Blocker),
        other => bail!("unknown blackboard kind: {other}"),
    }
}

fn parse_confidence(value: &str) -> Result<ConfidenceLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(ConfidenceLevel::Low),
        "medium" | "med" => Ok(ConfidenceLevel::Medium),
        "high" => Ok(ConfidenceLevel::High),
        other => bail!("unknown confidence level: {other}"),
    }
}

fn parse_mailbox_kind(value: &str) -> Result<MailboxMessageKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "work_assigned" | "work-assigned" | "assigned" => Ok(MailboxMessageKind::WorkAssigned),
        "work_blocked" | "work-blocked" | "blocked" => Ok(MailboxMessageKind::WorkBlocked),
        "lease_expiring" | "lease-expiring" => Ok(MailboxMessageKind::LeaseExpiring),
        "lease_revoked" | "lease-revoked" => Ok(MailboxMessageKind::LeaseRevoked),
        "worktree_captured" | "worktree-captured" => Ok(MailboxMessageKind::WorktreeCaptured),
        "candidate_ready" | "candidate-ready" => Ok(MailboxMessageKind::CandidateReady),
        "review_requested" | "review-requested" => Ok(MailboxMessageKind::ReviewRequested),
        "conflict_raised" | "conflict-raised" => Ok(MailboxMessageKind::ConflictRaised),
        "verifier_failed" | "verifier-failed" => Ok(MailboxMessageKind::VerifierFailed),
        "completion_blocked" | "completion-blocked" => Ok(MailboxMessageKind::CompletionBlocked),
        "agent_expired" | "agent-expired" => Ok(MailboxMessageKind::AgentExpired),
        "ack_required" | "ack-required" => Ok(MailboxMessageKind::AckRequired),
        other => bail!("unknown mailbox kind: {other}"),
    }
}

fn parse_mailbox_recipient(value: &str) -> Result<MailboxRecipient> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("controller") {
        return Ok(MailboxRecipient::Controller);
    }
    if let Some(role) = value.strip_prefix("role:") {
        return Ok(MailboxRecipient::Role(parse_agent_role(role)?));
    }
    if let Some(session_id) = value.strip_prefix("session:") {
        return Ok(MailboxRecipient::Session(AgentSessionId::from_str(
            session_id,
        )?));
    }
    if let Some(work_item_id) = value.strip_prefix("work-item:") {
        return Ok(MailboxRecipient::WorkItem(WorkItemId::from_str(
            work_item_id,
        )?));
    }
    bail!("unknown mailbox recipient: {value}")
}

fn worktree_root_for_repo(repo_root: &Path) -> PathBuf {
    repo_root
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".eliot-governor-worktrees")
        .join(safe_path_segment(
            repo_root
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("repo"),
        ))
}

fn safe_path_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn git_head_blocking(repo_root: &Path) -> Result<String> {
    let output = ProcessCommand::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .with_context(|| format!("run git rev-parse in {}", repo_root.display()))?;
    if !output.status.success() {
        bail!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn find_work_item<'a>(state: &'a WorkState, project: &str, task: &str) -> Option<&'a WorkItem> {
    state
        .work_items
        .iter()
        .rev()
        .find(|item| item.project == project && item.task == task)
}

fn resolve_project_task_ids(state: &WorkState, project: &str, task: &str) -> (ProjectId, TaskId) {
    find_work_item(state, project, task).map_or_else(
        || (project_id_from_label(project), task_id_from_label(task)),
        |item| (item.project_id, item.task_id),
    )
}

fn project_task_ids_for_labels(
    state: &WorkState,
    project: &str,
    task: &str,
) -> Option<(ProjectId, TaskId)> {
    if project.is_empty() && task.is_empty() {
        return None;
    }
    find_work_item(state, project, task)
        .map(|item| (item.project_id, item.task_id))
        .or_else(|| {
            Some((
                ProjectId::from_str(project).ok()?,
                TaskId::from_str(task).ok()?,
            ))
        })
}

fn ensure_controller_session(
    state: &mut WorkState,
    project_id: ProjectId,
) -> eliot_types::AgentSession {
    if let Some(session) = state.sessions.iter().rev().find(|session| {
        session.project_id == project_id
            && session.role == AgentRole::Controller
            && session.status == eliot_types::AgentSessionStatus::Active
    }) {
        return session.clone();
    }
    AgentSessionService.create_controller(state, project_id)
}

fn latest_active_work_lease_id(
    state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Option<WorkLeaseId> {
    let now = time::OffsetDateTime::now_utc();
    state
        .leases
        .iter()
        .rev()
        .find(|lease| {
            lease.project_id == project_id
                && lease.task_id == task_id
                && matches!(
                    lease.state,
                    WorkLeaseState::Granted | WorkLeaseState::Renewed
                )
                && lease.expires_at > now
        })
        .map(|lease| lease.work_lease_id)
}

fn labels_for_project_task(
    state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
) -> (String, String) {
    state
        .work_items
        .iter()
        .rev()
        .find(|item| item.project_id == project_id && item.task_id == task_id)
        .map_or_else(
            || (project_id.to_string(), task_id.to_string()),
            |item| (item.project.clone(), item.task.clone()),
        )
}

fn latest_conflict_ids_for_item(state: &WorkState, item_id: WorkItemId) -> Vec<String> {
    state
        .conflicts
        .iter()
        .filter(|conflict| conflict.work_item_id == item_id)
        .map(|conflict| conflict.conflict_id.clone())
        .collect()
}

fn labels_for_lease(state: &WorkState, lease_id: WorkLeaseId) -> (String, String) {
    state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == lease_id)
        .and_then(|lease| {
            state
                .work_items
                .iter()
                .find(|item| item.work_item_id == lease.work_item_id)
        })
        .map_or_else(
            || ("unknown".to_owned(), "unknown".to_owned()),
            |item| (item.project.clone(), item.task.clone()),
        )
}

fn default_work_verifier(scope: &[String]) -> Vec<VerifierRequirement> {
    vec![VerifierRequirement {
        name: "cargo-check".to_owned(),
        command_kind: VerifierCommandKind::CargoCheck,
        command_display: "cargo check --workspace --all-targets --all-features".to_owned(),
        scope: scope.to_vec(),
        required_for_done: true,
        expected_signal: "workspace type-checks".to_owned(),
    }]
}

fn parse_agent_role(value: &str) -> Result<AgentRole> {
    match value.trim().to_ascii_lowercase().as_str() {
        "controller" => Ok(AgentRole::Controller),
        "implementer" | "impl" => Ok(AgentRole::Implementer),
        "reviewer" => Ok(AgentRole::Reviewer),
        "auditor" | "read_only" | "read-only" => Ok(AgentRole::Auditor),
        "verifier" => Ok(AgentRole::Verifier),
        other => bail!("unknown agent role: {other}"),
    }
}

fn project_id_from_label(value: &str) -> ProjectId {
    ProjectId::from_str(value).unwrap_or_else(|_| ProjectId::new_v7())
}

fn task_id_from_label(value: &str) -> TaskId {
    TaskId::from_str(value).unwrap_or_else(|_| TaskId::new_v7())
}

fn skill_id_from_label(value: &str) -> SkillId {
    SkillId::from_str(value).unwrap_or_else(|_| SkillId::new_v7())
}

fn write_report_pair<T>(
    json_path: &Path,
    markdown_path: &Path,
    value: &T,
    markdown: &str,
) -> Result<()>
where
    T: serde::Serialize,
{
    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write_bytes(json_path, &serde_json::to_vec_pretty(value)?)?;
    atomic_write_bytes(markdown_path, markdown.as_bytes())?;
    Ok(())
}

fn write_safety_report<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn write_external_review_report<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn write_antigravity_report_pair<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn antigravity_resolution_probe_contract() -> (
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

fn antigravity_home() -> Result<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .context("USERPROFILE/HOME is unavailable for Antigravity config discovery")
}

fn project_root_from_config(config_path: &Path) -> PathBuf {
    if let Ok(current) = std::env::current_dir()
        && current.join("Cargo.toml").is_file()
        && current.join("crates").join("eliot-app").is_dir()
    {
        return current;
    }
    let root = runtime_root(config_path);
    let project = root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    if project.is_absolute() {
        project
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(project)
    }
}

fn release_eliot_executable(config_path: &Path) -> Result<PathBuf> {
    let _ = config_path;
    let executable = std::env::current_exe().context("resolve the running ELIOT executable")?;
    executable.canonicalize().with_context(|| {
        format!(
            "running ELIOT MCP executable not found: {}",
            executable.display()
        )
    })
}

fn official_antigravity_plugin_source(config_path: &Path) -> PathBuf {
    let source = project_root_from_config(config_path)
        .join("plugin")
        .join("eliot-antigravity-official");
    if source.is_dir() {
        return source;
    }
    std::env::current_exe()
        .ok()
        .and_then(|executable| executable.parent().map(Path::to_path_buf))
        .map(|root| {
            root.join("integrations")
                .join("antigravity")
                .join("official-plugin")
        })
        .filter(|path| path.is_dir())
        .unwrap_or(source)
}

fn resolved_antigravity_binary() -> Result<PathBuf> {
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    resolution
        .selected_path
        .map(PathBuf::from)
        .context("official signed Antigravity CLI was not resolved")
}

fn antigravity_windows_install_discovery() -> eliot_types::AntigravityWindowsInstallDiscovery {
    let local_app_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    AntigravityWindowsInstallDiscoveryService.discover(local_app_data.as_deref())
}

fn installed_plugin_files(status: &eliot_types::AntigravityOfficialPluginStatus) -> Vec<String> {
    let mut files = Vec::new();
    for root in [&status.gui_plugin_root, &status.cli_plugin_root] {
        collect_file_paths(Path::new(root), &mut files);
    }
    files.sort();
    files.dedup();
    files
}

fn collect_file_paths(root: &Path, files: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_file_paths(&path, files);
        } else if path.is_file() {
            files.push(path.display().to_string());
        }
    }
}

fn antigravity_latest_request_path(root: &Path) -> PathBuf {
    root.join("reports")
        .join("antigravity-runs")
        .join("latest-request.json")
}

fn latest_antigravity_request(root: &Path) -> Result<Option<AntigravityReviewRequest>> {
    let path = antigravity_latest_request_path(root);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn latest_antigravity_run(root: &Path) -> Result<Option<AntigravityRun>> {
    let path = root
        .join("reports")
        .join("antigravity-runs")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn latest_antigravity_auth(root: &Path) -> Result<Option<AntigravityAuthCheck>> {
    latest_antigravity_typed(root, "antigravity-auth")
}

fn latest_antigravity_enablement(root: &Path) -> Result<Option<AntigravityEnablementReceipt>> {
    let path = root
        .join("reports")
        .join("antigravity-enablement")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    if value.get("receipt_id").is_none() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_value(value)?))
}

fn latest_antigravity_live_smoke(root: &Path) -> Result<Option<AntigravityLiveSmokeResult>> {
    latest_antigravity_typed(root, "antigravity-live-smoke")
}

fn latest_antigravity_disable(root: &Path) -> Result<Option<AntigravityDisableReceipt>> {
    latest_antigravity_typed(root, "antigravity-disable")
}

fn latest_antigravity_typed<T>(root: &Path, dir: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    let path = root.join("reports").join(dir).join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn matching_antigravity_mcp_invocation(
    root: &Path,
    run: &AntigravityRun,
) -> Option<AntigravityMcpInvocationReceipt> {
    let completed_at = run.completed_at?;
    let events = root
        .join("reports")
        .join("antigravity-mcp-invocations")
        .join("events");
    let mut receipts = std::fs::read_dir(events)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .filter_map(|path| {
            serde_json::from_reader::<_, AntigravityMcpInvocationReceipt>(
                std::fs::File::open(path).ok()?,
            )
            .ok()
        })
        .filter(|receipt| {
            receipt.succeeded
                && receipt.matching_audit_event
                && receipt.profile == "external_auditor"
                && receipt.tool_name == "eliot_runtime_status"
                && receipt.invoked_at >= run.created_at
                && receipt.invoked_at <= completed_at
                && receipt
                    .audit_event_ref
                    .as_deref()
                    .is_some_and(|reference| root.join(reference).is_file())
        })
        .collect::<Vec<_>>();
    receipts.sort_by_key(|receipt| receipt.invoked_at);
    receipts.pop()
}

fn ensure_antigravity_collective_route(
    root: &Path,
    run: &AntigravityRun,
) -> Result<serde_json::Value> {
    let mut state = latest_antigravity_typed::<WorkState>(root, "antigravity-worktree-state")?
        .context("Antigravity worktree state is missing for collective route")?;
    let work_lease = state
        .leases
        .last()
        .cloned()
        .context("Antigravity WorkLease is missing for collective route")?;
    let candidate_diff = state
        .candidate_diffs
        .last()
        .cloned()
        .context("Antigravity CandidateDiff is missing for collective route")?;
    let payload_ref = format!("reports/antigravity-runs/latest.json#{}", run.run_id);
    let blackboard_item = state
        .blackboard_items
        .iter()
        .find(|item| item.payload_ref == payload_ref)
        .cloned()
        .unwrap_or_else(|| {
            BlackboardService.create_item(
                &mut state,
                BlackboardAddInput {
                    project_id: work_lease.project_id,
                    task_id: work_lease.task_id,
                    owner_session_id: work_lease.agent_session_id,
                    work_item_id: Some(work_lease.work_item_id),
                    lease_id: Some(work_lease.work_lease_id),
                    kind: BlackboardItemKind::FindingCandidate,
                    scope: BlackboardScope {
                        files: candidate_diff.changed_files.clone(),
                        work_items: vec![work_lease.work_item_id],
                        ..BlackboardScope::default()
                    },
                    payload_ref: payload_ref.clone(),
                    evidence_refs: vec![
                        format!("candidate-diff: {}", candidate_diff.candidate_diff_id),
                        "reports/antigravity-mcp-invocation-proof/latest.json".to_owned(),
                    ],
                    confidence: None,
                    expires_at: None,
                },
            )
        });
    let mailbox_message = state
        .mailbox_messages
        .iter()
        .find(|message| message.payload_ref == payload_ref)
        .cloned()
        .unwrap_or_else(|| {
            MailboxService.send(
                &mut state,
                MailboxSendInput {
                    message_id: None,
                    project_id: work_lease.project_id,
                    task_id: work_lease.task_id,
                    sender_session_id: work_lease.agent_session_id,
                    recipient: MailboxRecipient::Controller,
                    kind: MailboxMessageKind::CandidateReady,
                    payload_ref: payload_ref.clone(),
                    requires_ack: Some(false),
                    expires_at: None,
                },
            )
        });
    let report = serde_json::json!({
        "component": "antigravity_collective_route",
        "run_id": run.run_id,
        "candidate_diff_id": candidate_diff.candidate_diff_id,
        "blackboard_item": blackboard_item,
        "mailbox_message": mailbox_message,
        "candidate_only": true,
        "taint": TaintClass::ExternalAgent,
        "created_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        root,
        "antigravity-collective-route",
        "Antigravity Collective Route",
        &report,
    )?;
    write_antigravity_report_pair(
        root,
        "antigravity-worktree-state",
        "Antigravity Worktree State",
        &state,
    )?;
    Ok(report)
}

fn parse_antigravity_enablement_scope(value: &str) -> Result<AntigravityEnablementScope> {
    match value {
        "disposable-worktree-smoke"
        | "disposable-worktree-audit"
        | "read-only-smoke"
        | "read-only" => Ok(AntigravityEnablementScope::DisposableWorktreeAuditOnly),
        "disposable-worktree-candidate" | "worktree-candidate-smoke" | "worktree-candidate" => {
            Ok(AntigravityEnablementScope::DisposableWorktreeCandidateOnly)
        }
        "session" | "session-only" => Ok(AntigravityEnablementScope::SessionOnly),
        "persistent-local-admin" | "persistent" => {
            Ok(AntigravityEnablementScope::PersistentLocalAdmin)
        }
        other => bail!("unsupported Antigravity enablement scope: {other}"),
    }
}

fn parse_antigravity_live_smoke_mode(value: &str) -> Result<AntigravityLiveSmokeMode> {
    match value {
        "disposable-worktree" | "disposable-worktree-audit" | "read-only" | "read-only-audit" => {
            Ok(AntigravityLiveSmokeMode::DisposableWorktreeAudit)
        }
        "disposable-worktree-candidate" | "worktree-candidate" | "worktree-candidate-no-apply" => {
            Ok(AntigravityLiveSmokeMode::DisposableWorktreeCandidateNoApply)
        }
        other => bail!("unsupported Antigravity live-smoke mode: {other}"),
    }
}

fn antigravity_smoke_work_lease(root: &Path, task: &str) -> Result<(WorkState, WorkLease)> {
    let mut state = WorkState::default();
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let controller = AgentSessionService.create_controller(&mut state, project_id);
    let item = WorkQueueService.create_work_item(
        &mut state,
        WorkCreateRequest {
            project_id,
            task_id,
            project: "eliot-governor".to_owned(),
            task: task.to_owned(),
            goal: "Run governed Antigravity smoke in a detached disposable worktree".to_owned(),
            scope: default_work_scope(
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .display()
                    .to_string(),
                vec![".".to_owned()],
                Vec::new(),
                vec!["cargo run -p eliot-app -- verify provider-gate".to_owned()],
            ),
            required: true,
            created_by: controller.agent_session_id,
            required_verifiers: Vec::new(),
        },
    );
    let decision = WorkLeaseService.claim(
        &mut state,
        WorkClaimRequest {
            work_item_id: item.work_item_id,
            agent_session_id: controller.agent_session_id,
            role: AgentRole::Auditor,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let lease_id = decision
        .work_lease_id
        .context("Antigravity smoke did not receive a WorkLease")?;
    let lease = state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == lease_id)
        .cloned()
        .context("Antigravity smoke WorkLease missing after grant")?;
    let report = WorkQueueService.status_report(&state, "eliot-governor", task);
    write_report_pair(
        &root
            .join("reports")
            .join("antigravity-live-smoke")
            .join("work-lease.json"),
        &root
            .join("reports")
            .join("antigravity-live-smoke")
            .join("work-lease.md"),
        &report,
        &typed_report_markdown("Antigravity Live Smoke WorkLease", &report)?,
    )?;
    Ok((state, lease))
}

fn provider_gate_verification_passed(root: &Path) -> Result<bool> {
    let path = root
        .join("reports")
        .join("verification-verdicts")
        .join("latest.json");
    if !path.is_file() {
        return Ok(false);
    }
    let report: VerificationVerdictsReport = serde_json::from_reader(std::fs::File::open(path)?)?;
    Ok(report.verdict.profile_id == "provider-gate"
        && matches!(
            report.verdict.decision,
            VerificationDecision::Allow | VerificationDecision::AllowWithWarnings
        ))
}

fn write_antigravity_real_report_snapshot(
    root: &Path,
    resolution: AntigravityBinaryResolution,
    probe: AntigravityCapabilityProbe,
    contract: AntigravityCommandContract,
    auth: AntigravityAuthCheck,
) -> Result<AntigravityRealReport> {
    let enablement = latest_antigravity_enablement(root)?;
    let live_smoke = latest_antigravity_live_smoke(root)?;
    let disable = latest_antigravity_disable(root)?;
    let runs = latest_antigravity_run(root)?
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let telemetry = AntigravityTelemetryService.report(&probe, &runs);
    let current_state = enablement.as_ref().map_or_else(
        || AntigravityEnablementService.state_from_probe(&probe, Some(&auth)),
        |receipt| receipt.requested_state,
    );
    let doctor = AntigravityRealExecutionDoctor.status(
        &resolution,
        &probe,
        &contract,
        &auth,
        current_state,
        live_smoke.as_ref(),
        disable.as_ref(),
        !runs.is_empty() || live_smoke.is_some(),
    );
    let report = antigravity_real_report(
        resolution, probe, contract, auth, enablement, live_smoke, disable, doctor, telemetry,
    );
    write_antigravity_report_pair(root, "antigravity-real", "Antigravity Real", &report)?;
    Ok(report)
}

fn parse_antigravity_mode(value: &str) -> Result<AntigravityReviewMode> {
    match value {
        "audit-plan" | "audit_plan" => Ok(AntigravityReviewMode::AuditPlan),
        "candidate-implementation" | "candidate_implementation" => {
            Ok(AntigravityReviewMode::CandidateImplementation)
        }
        other => bail!("unknown Antigravity review mode: {other}"),
    }
}

fn antigravity_mcp_tools_governed_only() -> bool {
    let catalog_tools = mcp_stdio::governed_tool_names();
    AntigravityMcpBoundaryService.exposes_only_governed(catalog_tools, catalog_tools)
}

fn parse_external_review_role(value: &str) -> Result<ExternalReviewRole> {
    match value {
        "auditor" => Ok(ExternalReviewRole::Auditor),
        "reviewer" => Ok(ExternalReviewRole::Reviewer),
        "critic" => Ok(ExternalReviewRole::Critic),
        "worker" => Ok(ExternalReviewRole::Worker),
        other => bail!("unknown external review role: {other}"),
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
    root: &Path,
    request: &mut ExternalReviewRequest,
) -> Result<(WorkState, Option<WorkLease>)> {
    let mut state = load_work_state(root)?;
    let controller = AgentSessionService.create_controller(&mut state, request.project_id);
    let item = WorkQueueService.create_work_item(
        &mut state,
        WorkCreateRequest {
            project_id: request.project_id,
            task_id: request.task_id,
            project: request.project.clone(),
            task: request.task.clone(),
            goal: request.question.clone(),
            scope: default_work_scope(
                repo_root().display().to_string(),
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
        &mut state,
        WorkClaimRequest {
            work_item_id: item.work_item_id,
            agent_session_id: controller.agent_session_id,
            role: AgentRole::Auditor,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let work_lease = decision.work_lease_id.and_then(|lease_id| {
        state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == lease_id)
            .cloned()
    });
    request.work_lease_id = work_lease.as_ref().map(|lease| lease.work_lease_id);
    Ok((state, work_lease))
}

fn read_report_json<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
}

fn read_json_value(path: &Path) -> Result<serde_json::Value> {
    read_report_json(path)
}

fn filter_report_item(
    report: &serde_json::Value,
    array_key: &str,
    id_key: &str,
    id_value: &str,
) -> serde_json::Value {
    report
        .get(array_key)
        .and_then(serde_json::Value::as_array)
        .and_then(|values| {
            values.iter().find(|value| {
                value.get(id_key).and_then(serde_json::Value::as_str) == Some(id_value)
            })
        })
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "status": "not_found",
                "array": array_key,
                "id_key": id_key,
                "id_value": id_value
            })
        })
}

fn report_path_status(root: &Path, report_dir: &str) -> serde_json::Value {
    let path = root.join("reports").join(report_dir).join("latest.json");
    serde_json::json!({
        "path": path,
        "exists": path.is_file()
    })
}

fn external_review_mcp_tools_governed_only() -> bool {
    let tools = mcp_stdio::governed_tool_names();
    [
        "eliot_external_review_providers",
        "eliot_external_review_request",
        "eliot_external_review_job_status",
        "eliot_external_review_result",
        "eliot_external_review_report",
        "eliot_external_review_run_mock",
    ]
    .into_iter()
    .all(|tool| tools.contains(&tool))
        && tools.iter().all(|tool| {
            ![
                "raw_exec",
                "raw_secret",
                "raw_patch",
                "raw_truth",
                "run_gemini",
                "run_antigravity",
                "eliot_run_gemini",
                "eliot_run_antigravity",
            ]
            .into_iter()
            .any(|forbidden| tool.contains(forbidden))
        })
}

fn write_h1_report<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn h1_service_manager(config_path: &Path) -> Result<WindowsServiceManager> {
    let executable_path = std::env::current_exe().context("resolve current executable")?;
    Ok(WindowsServiceManager::new(
        WindowsServiceManager::default_config(&runtime_root(config_path), &executable_path),
    ))
}

fn run_service_control(
    config_path: &Path,
    action: ServiceInstallAction,
    title: &str,
) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let receipt = manager.control(action);
    write_h1_report(&runtime_root(config_path), "service", title, &receipt)?;
    write_json(&receipt)
}

fn h1_started_ipc(config_path: &Path) -> Result<(NamedPipeIpcServer, String)> {
    let manager = h1_service_manager(config_path)?;
    let token = "h1-local-ipc-token".to_owned();
    let mut server =
        NamedPipeIpcServer::in_memory(manager.config().ipc.clone(), hash_secret(&token));
    server.start()?;
    Ok((server, token))
}

fn h1_credentials_report(config_path: &Path) -> Result<eliot_types::CredentialDiagnosticsReport> {
    let config = load_config(config_path)?;
    let surreal = &config.db.surreal;
    let generated_at = time::OffsetDateTime::now_utc();
    let (present, version) = match surreal.credential_provider {
        CredentialProviderKind::WindowsCredentialManager => {
            let status = eliot_windows_ipc::credential_status_current_user(&surreal.credential_id)?;
            (
                status.present,
                status.version.map(|value| value.to_string()),
            )
        }
        CredentialProviderKind::LegacyPasswordFile => {
            let path =
                resolve_runtime_config_path(&runtime_root(config_path), &surreal.password_file);
            let metadata = std::fs::metadata(path).ok();
            let version = metadata
                .as_ref()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs().to_string());
            (metadata.is_some(), version)
        }
        _ => (false, None),
    };
    let config_text = std::fs::read_to_string(config_path).unwrap_or_default();
    Ok(eliot_types::CredentialDiagnosticsReport {
        component: "credentials_report".to_owned(),
        refs: vec![CredentialRef {
            credential_id: surreal.credential_id.clone(),
            provider: surreal.credential_provider,
            purpose: CredentialPurpose::SurrealDbRuntime,
            created_at: generated_at,
        }],
        statuses: vec![CredentialStatus {
            credential_id: surreal.credential_id.clone(),
            provider: surreal.credential_provider,
            present,
            version,
            fingerprint: None,
        }],
        resolved_count: usize::from(present),
        secret_values_redacted: true,
        toml_contains_secret_values: eliot_types::inspect_secret_bytes(config_text.as_bytes())
            .is_err(),
        command_line_contains_secret_values: false,
        warnings: vec![
            "credential status exposes metadata only; values are resolved inside the governed runtime"
                .to_owned(),
        ],
        generated_at,
    })
}

fn service_readiness_probe(root: &Path) -> Result<eliot_types::ServiceReadinessProbe> {
    let change_gate_passed = fast_deterministic_eval_gate_passed(root)?;
    service_readiness_probe_with_change_gate(root, change_gate_passed)
}

fn service_readiness_probe_with_change_gate(
    root: &Path,
    fast_deterministic_eval_gate_passed: bool,
) -> Result<eliot_types::ServiceReadinessProbe> {
    let data_root = DataRootService::new(root).validate(DataRootMode::DevProjectLocal)?;
    let fixture = ReadinessFixture {
        data_root_validated: ProductionReadinessService::data_root_validation_passed(
            data_root.status,
        ),
        credential_refs_resolved: true,
        db_reachable: true,
        writer_self_check: true,
        read_self_check: true,
        ipc_listening: true,
        fast_deterministic_eval_gate_passed,
        blocking_incident: IncidentService::new(root).lockdown_active()?,
    };
    Ok(ProductionReadinessService::probe("EliotGovernor", &fixture))
}

fn fast_deterministic_eval_gate_passed(root: &Path) -> Result<bool> {
    let artifacts = ensure_integration_smoke_artifacts(root, "core-smoke")?;
    Ok(artifacts.gate_decision.decision == EvalGateDecisionKind::Allow)
}

fn read_latest_json(config_path: &Path, name: &str) -> Result<()> {
    let path = runtime_root(config_path)
        .join("reports")
        .join(name)
        .join("latest.json");
    if !path.is_file() {
        bail!("no latest {name} report found");
    }
    let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    write_json(&value)
}

fn read_latest_or_generate<T, E, F>(config_path: &Path, name: &str, generate: F) -> Result<()>
where
    T: serde::Serialize,
    E: std::error::Error + Send + Sync + 'static,
    F: FnOnce() -> std::result::Result<T, E>,
{
    let path = runtime_root(config_path)
        .join("reports")
        .join(name)
        .join("latest.json");
    if path.is_file() {
        let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
        write_json(&value)
    } else {
        let value = generate()?;
        write_json(&value)
    }
}

fn read_or_generate_doctor_report(config_path: &Path) -> Result<serde_json::Value> {
    let root = runtime_root(config_path);
    let path = root.join("reports").join("doctor").join("latest.json");
    if path.is_file() {
        Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
    } else {
        let report = DoctorService::new(&root, repo_root()).report()?;
        write_safety_report(&root, "doctor", "Doctor", &report)?;
        Ok(serde_json::to_value(report)?)
    }
}

/// The source tree, found by walking up from the working directory to the
/// workspace that owns the canonical skills. Plain `current_dir` was wrong from
/// any subdirectory, and deriving it from the runtime root stopped working when
/// the runtime moved out of the repository.
fn repo_root() -> PathBuf {
    if let Some(root) = std::env::var_os("ELIOT_GOVERNOR_REPO_ROOT") {
        return PathBuf::from(root);
    }
    let current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    current
        .ancestors()
        .find(|candidate| {
            candidate.join("Cargo.toml").is_file()
                && candidate.join("integrations/agent-skills").is_dir()
        })
        .map_or(current.clone(), Path::to_path_buf)
}

fn parse_data_root_mode(value: &str) -> Result<DataRootMode> {
    match normalized_arg(value).as_str() {
        "dev" | "devprojectlocal" | "devproject-local" | "dev-project-local" => {
            Ok(DataRootMode::DevProjectLocal)
        }
        "production" | "prod" | "productionlocal" | "production-local" => {
            Ok(DataRootMode::ProductionLocal)
        }
        "recovery" | "recoveryoffline" | "recovery-offline" => Ok(DataRootMode::RecoveryOffline),
        "test" | "testisolated" | "test-isolated" => Ok(DataRootMode::TestIsolated),
        other => bail!("unknown data-root profile: {other}"),
    }
}

fn parse_backup_kind(value: &str) -> Result<BackupKind> {
    match normalized_arg(value).as_str() {
        "logical" | "logicalexport" | "logical-export" => Ok(BackupKind::LogicalExport),
        "offline" | "offlinesnapshot" | "offline-snapshot" => Ok(BackupKind::OfflineSnapshot),
        "incremental" | "incrementallogical" | "incremental-logical" => {
            Ok(BackupKind::IncrementalLogical)
        }
        "premigration" | "pre-migration" => Ok(BackupKind::PreMigration),
        "test" | "testfixture" | "test-fixture" => Ok(BackupKind::TestFixture),
        other => bail!("unknown backup kind: {other}"),
    }
}

fn parse_export_kind(value: &str) -> Result<ExportKind> {
    match normalized_arg(value).as_str() {
        "reports" | "reportsonly" | "reports-only" => Ok(ExportKind::ReportsOnly),
        "projectevidence" | "project-evidence" => Ok(ExportKind::ProjectEvidence),
        "memorysnapshot" | "memory-snapshot" => Ok(ExportKind::MemorySnapshot),
        "incidentbundle" | "incident-bundle" => Ok(ExportKind::IncidentBundle),
        "debugbundle" | "debug-bundle" => Ok(ExportKind::DebugBundle),
        other => bail!("unknown export kind: {other}"),
    }
}

fn parse_maintenance_job_kind(value: &str) -> Result<MaintenanceJobKind> {
    match normalized_arg(value).as_str() {
        "backup" => Ok(MaintenanceJobKind::Backup),
        "restoreverify" | "restore-verify" => Ok(MaintenanceJobKind::RestoreVerify),
        "export" => Ok(MaintenanceJobKind::Export),
        "importvalidate" | "import-validate" => Ok(MaintenanceJobKind::ImportValidate),
        "blobgc" | "blob-gc" => Ok(MaintenanceJobKind::BlobGc),
        "doctor" => Ok(MaintenanceJobKind::Doctor),
        "incidentreview" | "incident-review" => Ok(MaintenanceJobKind::IncidentReview),
        "configsnapshot" | "config-snapshot" => Ok(MaintenanceJobKind::ConfigSnapshot),
        "policysnapshot" | "policy-snapshot" => Ok(MaintenanceJobKind::PolicySnapshot),
        "ulcapsulemaintenance" | "ul-capsule-maintenance" => {
            Ok(MaintenanceJobKind::UlCapsuleMaintenance)
        }
        other => bail!("unknown maintenance job kind: {other}"),
    }
}

fn parse_incident_kind(value: &str) -> Result<IncidentKind> {
    match normalized_arg(value).as_str() {
        "backupmanifestmismatch" | "backup-manifest-mismatch" => {
            Ok(IncidentKind::BackupManifestMismatch)
        }
        "restoreintegrityfailure" | "restore-integrity-failure" => {
            Ok(IncidentKind::RestoreIntegrityFailure)
        }
        "blobchecksummismatch" | "blob-checksum-mismatch" => Ok(IncidentKind::BlobChecksumMismatch),
        "writerunavailable" | "writer-unavailable" => Ok(IncidentKind::WriterUnavailable),
        "dbunavailable" | "db-unavailable" => Ok(IncidentKind::DbUnavailable),
        "outboxmismatch" | "outbox-mismatch" => Ok(IncidentKind::OutboxMismatch),
        "deadletterthreshold" | "dead-letter-threshold" => Ok(IncidentKind::DeadLetterThreshold),
        "directdbbypassdetected" | "direct-db-bypass-detected" => {
            Ok(IncidentKind::DirectDbBypassDetected)
        }
        "invalidconfig" | "invalid-config" => Ok(IncidentKind::InvalidConfig),
        "invalidpolicy" | "invalid-policy" => Ok(IncidentKind::InvalidPolicy),
        "repeatedservicefailure" | "repeated-service-failure" => {
            Ok(IncidentKind::RepeatedServiceFailure)
        }
        "unknownsequencebase" | "unknown-sequence-base" => Ok(IncidentKind::UnknownSequenceBase),
        "campaignprovidercallbudgetexceeded" | "campaign-provider-call-budget-exceeded" => {
            Ok(IncidentKind::CampaignProviderCallBudgetExceeded)
        }
        other => bail!("unknown incident kind: {other}"),
    }
}

fn parse_incident_severity(value: &str) -> Result<IncidentSeverity> {
    match normalized_arg(value).as_str() {
        "info" => Ok(IncidentSeverity::Info),
        "warning" => Ok(IncidentSeverity::Warning),
        "degraded" => Ok(IncidentSeverity::Degraded),
        "blocking" => Ok(IncidentSeverity::Blocking),
        "critical" => Ok(IncidentSeverity::Critical),
        other => bail!("unknown incident severity: {other}"),
    }
}

fn normalized_arg(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

fn write_patch_reports(
    root: &Path,
    patch_run: &PatchRun,
    verifier_runs: &[VerifierRun],
) -> Result<()> {
    let patch_report = patch_report_value(patch_run, verifier_runs);
    write_report_pair(
        &root.join("reports").join("patch").join("latest.json"),
        &root.join("reports").join("patch").join("latest.md"),
        &patch_report,
        &patch_report_markdown(&patch_report),
    )?;
    write_verifier_report(root, &patch_run.patch_request_id.to_string(), verifier_runs)
}

fn write_verifier_report(root: &Path, plan_ref: &str, verifier_runs: &[VerifierRun]) -> Result<()> {
    let report = verifier_report_value(plan_ref, verifier_runs);
    write_report_pair(
        &root.join("reports").join("verifier").join("latest.json"),
        &root.join("reports").join("verifier").join("latest.md"),
        &report,
        &report_markdown("Verifier Report", &report),
    )
}

fn latest_patch_report(root: &Path) -> Result<Option<serde_json::Value>> {
    let path = root.join("reports").join("patch").join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn latest_verifier_report(root: &Path) -> Result<Option<serde_json::Value>> {
    let path = root.join("reports").join("verifier").join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn patch_report_value(patch_run: &PatchRun, verifier_runs: &[VerifierRun]) -> serde_json::Value {
    serde_json::json!({
        "component": "patch",
        "patch_run": patch_run,
        "verifier_runs": verifier_runs,
        "operation_status": patch_run_operation_status(patch_run)
    })
}

fn verifier_report_value(plan_ref: &str, verifier_runs: &[VerifierRun]) -> serde_json::Value {
    serde_json::json!({
        "component": "verifier",
        "plan_ref": plan_ref,
        "verifier_runs": verifier_runs,
        "operation_status": verifier_runs_operation_status(verifier_runs)
    })
}

fn patch_run_operation_status(patch_run: &PatchRun) -> OperationStatus {
    match patch_run.status {
        PatchRunStatus::AppliedVerifierPassed | PatchRunStatus::PreflightPassed => {
            OperationStatus::OperationCompleted
        }
        PatchRunStatus::Denied => OperationStatus::Blocked,
        PatchRunStatus::AppliedVerifierFailed
        | PatchRunStatus::RolledBack
        | PatchRunStatus::RollbackFailed => OperationStatus::Failed,
    }
}

fn verifier_runs_operation_status(verifier_runs: &[VerifierRun]) -> OperationStatus {
    if verifier_runs.is_empty() {
        return OperationStatus::Active;
    }
    if verifier_runs
        .iter()
        .filter(|run| run.required_for_done)
        .all(|run| run.status == VerifierStatus::Passed)
    {
        OperationStatus::OperationCompleted
    } else if verifier_runs.iter().any(|run| {
        run.required_for_done
            && matches!(run.status, VerifierStatus::Failed | VerifierStatus::TimedOut)
    }) {
        OperationStatus::Failed
    } else {
        OperationStatus::Blocked
    }
}

fn patch_report_markdown(report: &serde_json::Value) -> String {
    let mut output = String::from("# Patch Report\n\n");
    if let Some(patch_run) = report.get("patch_run") {
        let status = patch_run
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let patch_run_id = patch_run
            .get("patch_run_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let _ = writeln!(output, "- patch_run_id: `{patch_run_id}`");
        let _ = writeln!(output, "- status: `{status}`");
    }
    let operation_status = report
        .get("operation_status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("UNKNOWN");
    let _ = writeln!(output, "- operation_status: `{operation_status}`");
    output
}

fn codecortex_report_markdown(report: &CodeCortexReport) -> String {
    let mut output = String::from("# CodeCortex D1 Report\n\n");
    let _ = writeln!(output, "- project: `{}`", report.project);
    let _ = writeln!(output, "- task: `{}`", report.task);
    let _ = writeln!(
        output,
        "- operation_status: `{}`",
        report.operation_status
    );
    let _ = writeln!(output, "- repo_root: `{}`", report.repo_root);
    let _ = writeln!(
        output,
        "- git_head: `{}`",
        report.git_head.as_deref().unwrap_or("unknown")
    );
    let _ = writeln!(output, "- dirty: `{}`", report.dirty);
    let _ = writeln!(output, "- tracked_files: `{}`", report.tracked_files.len());
    let _ = writeln!(output, "- crates: `{}`", report.crates.join(", "));
    let _ = writeln!(output, "- file_evidence: `{}`", report.file_evidence.len());
    let _ = writeln!(
        output,
        "- symbol_evidence: `{}`",
        report.symbol_evidence.len()
    );
    let _ = writeln!(
        output,
        "- diagnostic_evidence: `{}`",
        report.diagnostic_evidence.len()
    );
    let _ = writeln!(
        output,
        "- memory_receipt: `{}`",
        report
            .memory_receipt
            .as_ref()
            .map_or_else(|| "none".to_owned(), |receipt| receipt.write_id.to_string())
    );
    output.push_str("\n## Adapters\n\n");
    for evidence in &report.verifier_evidence {
        let _ = writeln!(
            output,
            "- {}: `{}` - {}",
            evidence.name, evidence.status, evidence.summary
        );
    }
    output
}

fn writer_status_markdown(report: &eliot_types::WriterStatusResponse) -> String {
    format!(
        concat!(
            "# Writer Status\n\n",
            "- transport_status: `{}`\n",
            "- db_version: `{}`\n",
            "- pending_count: `{}`\n",
            "- committed_count: `{}`\n",
            "- failed_permanent_count: `{}`\n",
            "- rejected_count: `{}`\n",
            "- dead_letter_count: `{}`\n",
            "- unknown_commit_count: `{}`\n",
            "- idempotent_replay_count: `{}`\n",
            "- idempotency_conflict_count: `{}`\n",
            "- operation_status: `{}`\n"
        ),
        report.transport_status,
        report.db_version,
        report.pending_count,
        report.committed_count,
        report.failed_permanent_count,
        report.rejected_count,
        report.dead_letter_count,
        report.unknown_commit_count,
        report.idempotent_replay_count,
        report.idempotency_conflict_count,
        report.operation_status
    )
}

fn graph_health_markdown(report: &eliot_types::GraphHealthResponse) -> String {
    format!(
        concat!(
            "# Graph Health\n\n",
            "- project_id: `{}`\n",
            "- scan_limit: `{}`\n",
            "- scan_truncated: `{}`\n",
            "- scope_head_supported: `{}`\n",
            "- unsupported_relation_families: `{}`\n",
            "- orphan_claims: `{}`\n",
            "- claims_without_support: `{}`\n",
            "- claims_without_verification: `{}`\n",
            "- verified_claims: `{}`\n",
            "- supported_claims: `{}`\n",
            "- weak_claims: `{}`\n",
            "- contested_claims: `{}`\n",
            "- duplicate_write_ids: `{}`\n"
        ),
        report.project_id,
        report.scan_limit,
        report.scan_truncated,
        report.scope_head_supported,
        report.unsupported_relation_families.join(", "),
        report.orphan_claims,
        report.claims_without_support,
        report.claims_without_verification,
        report.verified_claims,
        report.supported_claims,
        report.weak_claims,
        report.contested_claims,
        report.duplicate_write_ids
    )
}

/// Renders a report as Markdown. Named for the verification reports it used to
/// render; those commands are gone and this is the generic renderer.
fn report_markdown(title: &str, report: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(checks) = report.get("checks").and_then(serde_json::Value::as_object) {
        for (name, status) in checks {
            let status = status.as_str().unwrap_or("unknown");
            let _ = writeln!(output, "- {name}: `{status}`");
        }
    }
    let status = report
        .get("operation_status")
        .or_else(|| report.get("final_status"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("UNKNOWN");
    let _ = writeln!(output, "\n- operation_status: `{status}`");
    output
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalCasesReport {
    component: String,
    cases: Vec<EvalCase>,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalSuitesReport {
    component: String,
    suites: Vec<EvalSuite>,
    latest: EvalSuite,
    manifest: Option<EvalDatasetManifest>,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalRunsReport {
    component: String,
    run: EvalRun,
    profile: EvalRunProfile,
    blocked_mutation_run: EvalRun,
    experiment: HarnessExperimentRecord,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalVerdictsReport {
    component: String,
    verdict: EvalVerdict,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalFailuresReport {
    component: String,
    clusters: Vec<EvalFailureCluster>,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BenchmarkIntegrityReport {
    component: String,
    valid_receipt: BenchmarkIntegrityReceipt,
    mismatch_receipt: BenchmarkIntegrityReceipt,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalCoverageReport {
    component: String,
    coverage: EvalCoverageMatrix,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalBaselinesReport {
    component: String,
    suite_id: String,
    baselines: Vec<EvalBaseline>,
    active: Option<EvalBaseline>,
    incident_lockdown_blocks_mutation: bool,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalComparisonsReport {
    component: String,
    baseline: EvalBaseline,
    candidate_run: EvalRun,
    comparison: EvalCandidateComparison,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalGatesReport {
    component: String,
    profile: EvalRegressionGateProfile,
    comparison: Option<EvalCandidateComparison>,
    decision: EvalGateDecision,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalProfilesReport {
    component: String,
    profiles: Vec<EvalRegressionGateProfile>,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalTrendsReport {
    component: String,
    trend: EvalTrendReport,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalFixtureStabilityReportEnvelope {
    component: String,
    repeat: u8,
    stability: EvalFixtureStabilityReport,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

struct CoreSmokeArtifacts {
    cases: Vec<EvalCase>,
    suite: EvalSuite,
    manifest: EvalDatasetManifest,
    profile: EvalRunProfile,
    integrity_receipt: BenchmarkIntegrityReceipt,
    mismatch_receipt: BenchmarkIntegrityReceipt,
    run: EvalRun,
    blocked_mutation_run: EvalRun,
    verdict: EvalVerdict,
    fixture_failure_cluster: EvalFailureCluster,
    experiment: HarnessExperimentRecord,
}

struct IntegrationSmokeArtifacts {
    core: CoreSmokeArtifacts,
    coverage: EvalCoverageMatrix,
    baseline: EvalBaseline,
    comparison: EvalCandidateComparison,
    gate_decision: EvalGateDecision,
    critical_comparison: EvalCandidateComparison,
    critical_gate_decision: EvalGateDecision,
    trend: EvalTrendReport,
    stability: EvalFixtureStabilityReport,
    doctor_status: serde_json::Value,
}

fn governed_trace_contract(project: &str, task: &str, complete: bool) -> TraceCompletenessContract {
    let present_refs = if complete {
        full_trace_refs()
    } else {
        vec!["user_prompt".to_owned(), "task_contract".to_owned()]
    };
    TraceCompletenessService::build(TraceCompletenessInput {
        project_id: project_id_from_label(project),
        task_id: Some(task_id_from_label(task)),
        trace_ref: format!("trace:{project}:{task}"),
        present_refs,
    })
}

fn full_trace_refs() -> Vec<String> {
    [
        "user_prompt",
        "task_contract",
        "context_packet",
        "understanding_proof",
        "cognitive_gate_decision",
        "verifier_run",
        "completion_proof",
        "policy_snapshot",
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect()
}

fn parse_replay_case_kind(value: &str) -> Result<ReplayCaseKind> {
    match normalized_cli_value(value).as_str() {
        "regression" => Ok(ReplayCaseKind::Regression),
        "negativememory" => Ok(ReplayCaseKind::NegativeMemory),
        "skillactivation" => Ok(ReplayCaseKind::SkillActivation),
        "skillcuration" => Ok(ReplayCaseKind::SkillCuration),
        "memorylifecycle" => Ok(ReplayCaseKind::MemoryLifecycle),
        "contextcompilation" => Ok(ReplayCaseKind::ContextCompilation),
        "completiongate" => Ok(ReplayCaseKind::CompletionGate),
        "adapterobservation" => Ok(ReplayCaseKind::AdapterObservation),
        "incidentrecovery" => Ok(ReplayCaseKind::IncidentRecovery),
        other => bail!("unknown replay case kind: {other}"),
    }
}

fn parse_sleep_trigger(value: &str) -> Result<SleepTrigger> {
    match normalized_cli_value(value).as_str() {
        "manual" => Ok(SleepTrigger::Manual),
        "posttask" => Ok(SleepTrigger::PostTask),
        "repeatedfailure" => Ok(SleepTrigger::RepeatedFailure),
        "contextbloat" => Ok(SleepTrigger::ContextBloat),
        "skilldecay" => Ok(SleepTrigger::SkillDecay),
        "maintenancewindow" => Ok(SleepTrigger::MaintenanceWindow),
        other => bail!("unknown sleep trigger: {other}"),
    }
}

fn parse_dream_candidate_kind(value: &str) -> Result<DreamCandidateKind> {
    match normalized_cli_value(value).as_str() {
        "hypothesis" => Ok(DreamCandidateKind::Hypothesis),
        "procedure" => Ok(DreamCandidateKind::Procedure),
        "relation" => Ok(DreamCandidateKind::Relation),
        "forgettingaction" => Ok(DreamCandidateKind::ForgettingAction),
        "test" => Ok(DreamCandidateKind::Test),
        "invariant" => Ok(DreamCandidateKind::Invariant),
        "risk" => Ok(DreamCandidateKind::Risk),
        "researchquestion" => Ok(DreamCandidateKind::ResearchQuestion),
        other => bail!("unknown dream candidate kind: {other}"),
    }
}

fn normalized_cli_value(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_', ' '], "")
}

fn write_replay_report<T>(root: &Path, dir: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    let json_value = serde_json::to_value(value)?;
    write_report_pair(
        &latest_report_path(root, dir),
        &latest_markdown_path(root, dir),
        value,
        &value_report_markdown(title, &json_value),
    )
}

fn read_latest_typed<T>(root: &Path, dir: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(read_latest_value(root, dir)?).with_context(|| {
        format!(
            "parse latest report {}",
            latest_report_path(root, dir).display()
        )
    })
}

fn read_latest_value(root: &Path, dir: &str) -> Result<serde_json::Value> {
    let path = latest_report_path(root, dir);
    if !path.is_file() {
        bail!("latest report not found: {}", path.display());
    }
    serde_json::from_reader(std::fs::File::open(path)?).context("parse latest report JSON")
}

fn latest_report_path(root: &Path, dir: &str) -> PathBuf {
    root.join("reports").join(dir).join("latest.json")
}

fn latest_markdown_path(root: &Path, dir: &str) -> PathBuf {
    root.join("reports").join(dir).join("latest.md")
}

fn value_report_markdown(title: &str, value: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(status) = value.get("status").and_then(serde_json::Value::as_str) {
        let _ = writeln!(output, "- status: `{status}`");
    }
    if let Some(operation_status) = value
        .get("operation_status")
        .or_else(|| value.get("final_status"))
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- operation_status: `{operation_status}`");
    }
    if let Some(replay_allowed) = value
        .get("replay_allowed")
        .and_then(serde_json::Value::as_bool)
    {
        let _ = writeln!(output, "- replay_allowed: `{replay_allowed}`");
    }
    let _ = writeln!(
        output,
        "- candidate_only: `true`\n- authority: `marker-only; no apply authority`"
    );
    output
}

fn provider_integration_eval_gate_passed(root: &Path) -> Result<bool> {
    let artifacts = ensure_integration_smoke_artifacts(root, "core-smoke")?;
    Ok(artifacts.gate_decision.decision == EvalGateDecisionKind::Allow)
}
