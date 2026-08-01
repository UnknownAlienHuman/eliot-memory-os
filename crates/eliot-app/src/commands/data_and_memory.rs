pub async fn run_db_start(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let server = SurrealServerSupervisor::new(config.db.surreal)
        .start_or_connect()
        .await?;
    write_json(&serde_json::json!({
        "component": "surrealdb",
        "status": "ready",
        "server_started": server.started_pid().is_some()
    }))
}

pub async fn run_db_stop(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let stopped = SurrealServerSupervisor::new(config.db.surreal)
        .stop()
        .await?;
    write_json(&serde_json::json!({
        "component": "surrealdb",
        "status": if stopped { "stopped" } else { "not_running" }
    }))
}

pub async fn run_db_status(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let ready = SurrealServerSupervisor::new(config.db.surreal)
        .status()
        .await?;
    write_json(&serde_json::json!({
        "component": "surrealdb",
        "status": if ready { "ready" } else { "not_ready" }
    }))
}

pub async fn run_db_smoke(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let report = SurrealStore::new(config.db.surreal).smoke().await?;
    let report_path = db_report_path(config_path);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&report_path, report.to_markdown())?;
    write_json(&serde_json::json!({
        "component": "surrealdb",
        "status": if report.is_ready() { "ready" } else { "not_ready" },
        "report_path": report_path,
        "report": report
    }))?;

    if !report.is_ready() {
        bail!("SurrealDB smoke write/read failed");
    }
    Ok(())
}

pub async fn run_db_migrate(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let _ = CanonicalStore::new(config.db.surreal.clone())
        .migrate_schema()
        .await?;
    let record = SurrealStore::new(config.db.surreal)
        .apply_migration(NamedSurqlOp::SchemaMigrate.name(), "RETURN true;")
        .await?;
    write_json(&serde_json::json!({
        "component": record.component,
        "status": record.status,
        "detail": record.detail
    }))
}

pub async fn run_writer_status(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let wal = ControlWal::open(&config.control_wal)?;
    let store = CanonicalStore::new(config.db.surreal);
    let report = WriterReportService::new(wal, store).status().await?;
    let root = runtime_root(config_path);
    write_report_pair(
        &root.join("reports").join("writer").join("latest.json"),
        &root.join("reports").join("writer").join("latest.md"),
        &report,
        &writer_status_markdown(&report),
    )?;
    write_json(&report)
}

pub async fn run_writer_smoke(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;

    let wal = ControlWal::open(&config.control_wal)?;
    let writer_config = WriterConfig::default();
    let (handle, actor) = WriterActor::channel(wal, store.clone(), &writer_config);
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;

    let project_id = ProjectId::new_v7();
    let agent_id = AgentId::new_v7();
    let task_id = Some(TaskId::new_v7());
    let claim_id = ClaimId::new_v7();
    let evidence_id = EvidenceId::new_v7();
    let source_id = format!("source-{evidence_id}");
    let statement = "writer smoke verified claim".to_owned();

    let mut receipts = Vec::new();
    let evidence_command = SemanticCommand::EvidenceIngest(EvidenceIngestCommand {
        context: smoke_context(project_id, agent_id, task_id),
        source: SourceSnapshotInput {
            source_id: source_id.clone(),
            uri: "local://writer-smoke".to_owned(),
            authority: "local-smoke".to_owned(),
            content_hash: "writer-smoke".to_owned(),
            excerpt: "writer smoke source".to_owned(),
        },
        evidence: EvidenceAtomInput {
            evidence_id,
            source_id,
            summary: "writer smoke evidence".to_owned(),
            payload: serde_json::json!({ "smoke": true }),
        },
    });
    receipts.push(handle.submit(admission.admit(&evidence_command)?).await?);

    let claim_command = SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: smoke_context(project_id, agent_id, task_id),
        claim: ClaimCardInput {
            claim_id,
            statement: statement.clone(),
            status: EpistemicStatus::Candidate,
            payload: serde_json::json!({ "phase": "candidate" }),
        },
    });
    receipts.push(handle.submit(admission.admit(&claim_command)?).await?);

    let support_command = SemanticCommand::ClaimSupport(eliot_types::ClaimSupportCommand {
        context: smoke_context(project_id, agent_id, task_id),
        claim_id,
        evidence_id,
        statement: Some(statement.clone()),
        payload: serde_json::json!({ "phase": "supported" }),
    });
    receipts.push(handle.submit(admission.admit(&support_command)?).await?);

    let verify_command = SemanticCommand::ClaimVerify(eliot_types::ClaimVerifyCommand {
        context: smoke_context(project_id, agent_id, task_id),
        claim_id,
        verification: VerificationRunInput {
            verification_id: eliot_types::VerificationId::new_v7(),
            claim_id: Some(claim_id),
            verifier: "local-writer-smoke".to_owned(),
            result: VerificationResult::Passed,
            summary: "writer smoke verification passed".to_owned(),
            payload: serde_json::json!({ "passed": true }),
        },
        statement: Some(statement),
        payload: serde_json::json!({ "phase": "verified" }),
    });
    receipts.push(handle.submit(admission.admit(&verify_command)?).await?);

    drop(handle);
    actor_task.await?;

    let read_service = ReadService::new(store);
    let current_state = read_service
        .current_state(&CurrentStateRequest {
            project_id,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?;

    let report = serde_json::json!({
        "component": "writer",
        "status": if current_state.verified_now.is_empty() { "not_ready" } else { "ready" },
        "project_id": project_id,
        "receipt_count": receipts.len(),
        "verified_now": current_state.verified_now,
        "receipts": receipts
    });
    let root = runtime_root(config_path);
    write_report_pair(
        &root
            .join("reports")
            .join("writer")
            .join("smoke-latest.json"),
        &root.join("reports").join("writer").join("smoke-latest.md"),
        &report,
        "# Writer Smoke\n\n- status: `ready`\n",
    )?;
    write_json(&report)
}

pub fn run_writer_drain(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let pending = ControlWal::open(&config.control_wal)?.recover_pending()?;
    write_json(&serde_json::json!({
        "component": "writer",
        "status": "drained",
        "pending_recovered": pending.len(),
        "detail": "no background writer queue is running in this CLI process"
    }))
}

pub async fn run_memory_current_state(config_path: &Path, project: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let project_id = parse_project_id(project)?;
    let request = CurrentStateRequest {
        project_id,
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
    };
    let service = ReadService::new(CanonicalStore::new(config.db.surreal));
    let response = service.current_state(&request).await?;
    write_json(&response)
}

pub async fn run_memory_recall_l0(config_path: &Path, project: &str, query: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let request = RecallL0Request {
        project_id: parse_project_id(project)?,
        query: query.to_owned(),
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
        lifecycle_audit: false,
        task_id: None,
        task_class_cues: Vec::new(),
        scope_refs: Vec::new(),
        concept_refs: Vec::new(),
    };
    let service = ReadService::new(CanonicalStore::new(config.db.surreal));
    let response = service.recall_l0(&request).await?;
    write_json(&response)
}

pub async fn run_memory_fetch_l2(config_path: &Path, project: &str, handles: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let request = FetchAtomsL2Request {
        project_id: parse_project_id(project)?,
        handles: handles
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        continuation: None,
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
    };
    let service = ReadService::new(CanonicalStore::new(config.db.surreal));
    let response = service.fetch_atoms_l2(&request).await?;
    write_json(&response)
}

pub async fn run_memory_lifecycle_status(
    config_path: &Path,
    project: &str,
    memory_ref: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let config = load_config(config_path)?;
    let latest = CanonicalStore::new(config.db.surreal)
        .canonical_records_by_subject_ref::<MemoryStateTransition>(
            project_id,
            None,
            &["state_transition"],
            memory_ref,
            1,
        )
        .await?
        .into_iter()
        .next();
    let lifecycle = latest.as_ref().map_or_else(MemoryLifecycleService::new, |record| {
        MemoryLifecycleService::new().with_state(memory_ref, record.receipt_body.to_state)
    });
    let mut report = lifecycle.status(project_id, memory_ref);
    report.related_receipts = latest
        .map(|record| vec![format!("receipt:{}", record.canonical_receipt.receipt_id)])
        .unwrap_or_default();
    write_report_pair(
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.md"),
        &report,
        &typed_report_markdown("Memory Lifecycle Status", &report)?,
    )?;
    write_json(&report)
}

pub fn run_memory_lifecycle_propose(
    config_path: &Path,
    project: &str,
    memory_ref: &str,
    operator: &str,
    reason: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let policy = lifecycle_policy_from_cli(project, memory_ref, operator, reason)?;
    let decision = MemoryLifecycleGate::decide(&policy, &[]);
    let report = serde_json::json!({
        "component": "memory_lifecycle_proposal",
        "policy": policy,
        "decision": decision
    });
    write_report_pair(
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.md"),
        &report,
        &report_markdown("Memory Lifecycle Proposal", &report),
    )?;
    write_json(&report)
}

pub async fn run_memory_lifecycle_apply(config_path: &Path, policy_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let latest = root
        .join("reports")
        .join("memory-lifecycle")
        .join("latest.json");
    if !latest.is_file() {
        bail!("no latest memory lifecycle proposal found; run memory-lifecycle propose first");
    }
    let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(&latest)?)?;
    let policy_value = value
        .get("policy")
        .cloned()
        .context("latest memory lifecycle report does not contain a policy")?;
    let policy: ForgettingPolicy = serde_json::from_value(policy_value)?;
    if policy.policy_id != policy_id {
        bail!("latest memory lifecycle policy id does not match {policy_id}");
    }
    let outcome = apply_lifecycle_policy_to_memory(config_path, &policy).await?;
    let report = serde_json::json!({
        "component": "memory_lifecycle_apply",
        "policy_id": policy_id,
        "decision": outcome.decision,
        "transition": outcome.transition,
        "write_receipt": outcome.write_receipt
    });
    write_report_pair(
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.md"),
        &report,
        &report_markdown("Memory Lifecycle Apply", &report),
    )?;
    write_json(&report)
}

pub async fn run_memory_lifecycle_vitality(
    config_path: &Path,
    project: &str,
    memory_ref: Option<&str>,
) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let (_, _, ledger) = cli_memory_distillation_projection(config_path, project_id).await?;
    let target_ref = memory_ref
        .map(str::to_owned)
        .or_else(|| ledger.entries.first().map(|entry| entry.target_ref.clone()))
        .unwrap_or_else(|| "memory-lifecycle:empty-corpus".to_owned());
    let score =
        MemoryDistillationService::vitality_from_ledger(project_id, &target_ref, &ledger);
    write_memory_vitality_report(&root, &score)?;
    write_json(&score)
}

pub async fn run_memory_lifecycle_gravity(
    config_path: &Path,
    project: &str,
    memory_ref: Option<&str>,
) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let (_, _, ledger) = cli_memory_distillation_projection(config_path, project_id).await?;
    let target_ref = memory_ref
        .map(str::to_owned)
        .or_else(|| ledger.entries.first().map(|entry| entry.target_ref.clone()))
        .unwrap_or_else(|| "memory-lifecycle:empty-corpus".to_owned());
    let score =
        MemoryDistillationService::vitality_from_ledger(project_id, &target_ref, &ledger);
    let gravity = MemoryGravityService::gravity(&score);
    write_memory_gravity_report(&root, &gravity)?;
    write_json(&gravity)
}

pub async fn run_memory_distillation_preview(
    config_path: &Path,
    project: &str,
) -> Result<()> {
    let project_id = project_id_from_label(project);
    let (records, snapshot_revision, utility_ledger) =
        cli_memory_distillation_projection(config_path, project_id).await?;
    let plan = MemoryDistillationService::plan(MemoryDistillationInput {
        project_id,
        snapshot_revision,
        ruleset_version: eliot_engine::MEMORY_DISTILLATION_RULESET_VERSION.to_owned(),
        complete: utility_ledger.complete,
        items: mcp_stdio::canonical_distillation_items(&records)?,
        utility_ledger,
    })?;
    write_memory_distillation_run(config_path, &plan, None, None)?;
    write_json(&plan)
}

pub fn run_memory_distillation_schedule(
    project: &str,
    trigger: &str,
    new_evidence_count: u64,
    minimum_evidence_count: u64,
    interactive_load_active: bool,
    cursor: Option<String>,
    batch_size: u16,
) -> Result<()> {
    let trigger = match trigger {
        "verified_task_closure" => MemoryDistillationTrigger::VerifiedTaskClosure,
        "nightly" => MemoryDistillationTrigger::Nightly,
        "idle" => MemoryDistillationTrigger::Idle,
        "manual" => MemoryDistillationTrigger::Manual,
        other => bail!("unsupported distillation trigger: {other}"),
    };
    let checkpoint = MemoryDistillationService::schedule(&MemoryDistillationScheduleRequest {
        project_id: project_id_from_label(project),
        trigger,
        new_evidence_count,
        minimum_evidence_count,
        interactive_load_active,
        cursor,
        batch_size,
    });
    write_json(&checkpoint)
}

pub async fn run_memory_distillation_apply(
    config_path: &Path,
    project: &str,
    selected_candidate_ids: &[String],
) -> Result<()> {
    if selected_candidate_ids.is_empty() || selected_candidate_ids.len() > 100 {
        bail!("distillation apply requires between 1 and 100 candidate ids");
    }
    let project_id = project_id_from_label(project);
    let (records, snapshot_revision, utility_ledger) =
        cli_memory_distillation_projection(config_path, project_id).await?;
    let plan = MemoryDistillationService::plan(MemoryDistillationInput {
        project_id,
        snapshot_revision,
        ruleset_version: eliot_engine::MEMORY_DISTILLATION_RULESET_VERSION.to_owned(),
        complete: utility_ledger.complete,
        items: mcp_stdio::canonical_distillation_items(&records)?,
        utility_ledger,
    })?;
    let mut receipt =
        MemoryDistillationService::select_reversible_actions(&plan, selected_candidate_ids)?;
    if !receipt.rejected_candidate_ids.is_empty() {
        bail!(
            "distillation apply rejected unsafe, missing, or non-reversible candidates: {:?}",
            receipt.rejected_candidate_ids
        );
    }
    let mut outcomes = Vec::new();
    for selection in &receipt.selected {
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == selection.candidate_id)
            .context("selected candidate disappeared from the exact plan")?;
        let reason = match candidate.finding {
            eliot_types::MemoryDistillationFinding::ExactDuplicate => ForgettingReason::Duplicate,
            eliot_types::MemoryDistillationFinding::StaleSuperseded
            | eliot_types::MemoryDistillationFinding::ObsoleteArtifact => {
                ForgettingReason::Superseded
            }
            eliot_types::MemoryDistillationFinding::WrongScope => ForgettingReason::WrongScope,
            eliot_types::MemoryDistillationFinding::RepeatedLowDelta => {
                ForgettingReason::LowUtility
            }
            other => bail!("finding is not safe for CLI apply: {other:?}"),
        };
        let mut policy = ForgettingPolicyService::propose(
            project_id,
            &selection.target_ref,
            selection.operator,
            reason,
            selection.evidence_refs.clone(),
            None,
            None,
        );
        policy.policy_id = format!("{}:{}", plan.plan_id, selection.candidate_id);
        let outcome = apply_lifecycle_policy_to_memory(config_path, &policy).await?;
        if let Some(write_receipt) = outcome.write_receipt.clone() {
            receipt.write_receipts.push(write_receipt);
        }
        outcomes.push(serde_json::json!({
            "decision": outcome.decision,
            "transition": outcome.transition,
            "write_receipt": outcome.write_receipt,
        }));
    }
    let (after_records, after_revision, after_ledger) =
        cli_memory_distillation_projection(config_path, project_id).await?;
    let after = MemoryDistillationService::plan(MemoryDistillationInput {
        project_id,
        snapshot_revision: after_revision,
        ruleset_version: eliot_engine::MEMORY_DISTILLATION_RULESET_VERSION.to_owned(),
        complete: after_ledger.complete,
        items: mcp_stdio::canonical_distillation_items(&after_records)?,
        utility_ledger: after_ledger,
    })?;
    write_memory_distillation_run(config_path, &plan, Some(&after), Some(&receipt))?;
    write_json(&serde_json::json!({
        "receipt": receipt,
        "outcomes": outcomes,
        "after_profile": after.corpus_profile_before,
    }))
}

async fn cli_memory_distillation_projection(
    config_path: &Path,
    project_id: ProjectId,
) -> Result<(
    Vec<CanonicalRecord<Value>>,
    MemoryRevision,
    eliot_types::CanonicalMemoryUtilityLedger,
)> {
    const PAGE_SIZE: u16 = 100;
    const MAX_RECORDS: usize = 1_000_000;
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    let snapshot_revision = store
        .current_state(&CurrentStateRequest {
            project_id,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?
        .memory_revision;
    let mut records = Vec::new();
    let mut start = 0_u64;
    let mut complete = false;
    while records.len() < MAX_RECORDS {
        let remaining = MAX_RECORDS.saturating_sub(records.len());
        let limit = u16::try_from(remaining.min(usize::from(PAGE_SIZE)))?;
        let page = store
            .canonical_record_page_at_revision(
                project_id,
                None,
                &[],
                Some(snapshot_revision),
                start,
                limit,
            )
            .await?;
        let returned = page.len();
        records.extend(page);
        start = start.saturating_add(u64::try_from(returned)?);
        if returned < usize::from(limit) {
            complete = true;
            break;
        }
    }
    if !complete && records.len() == MAX_RECORDS {
        complete = store
            .canonical_record_page_at_revision(
                project_id,
                None,
                &[],
                Some(snapshot_revision),
                start,
                1,
            )
            .await?
            .is_empty();
    }
    let utility_ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &mcp_stdio::canonical_utility_sources(&records)?,
        complete,
    );
    Ok((records, snapshot_revision, utility_ledger))
}

fn write_memory_distillation_run(
    config_path: &Path,
    plan: &MemoryDistillationPlan,
    after: Option<&MemoryDistillationPlan>,
    receipts: Option<&eliot_types::MemoryDistillationApplyReceipt>,
) -> Result<()> {
    let run_id = plan.plan_id.replace(':', "-");
    let root = runtime_root(config_path)
        .join("reports")
        .join("memory-distillation")
        .join(run_id);
    std::fs::create_dir_all(&root)?;
    std::fs::write(
        root.join("plan.json"),
        serde_json::to_vec_pretty(plan)?,
    )?;
    std::fs::write(
        root.join("before.json"),
        serde_json::to_vec_pretty(&plan.corpus_profile_before)?,
    )?;
    if let Some(after) = after {
        std::fs::write(
            root.join("after.json"),
            serde_json::to_vec_pretty(&after.corpus_profile_before)?,
        )?;
    }
    if let Some(receipts) = receipts {
        std::fs::write(
            root.join("receipts.json"),
            serde_json::to_vec_pretty(receipts)?,
        )?;
    }
    Ok(())
}

pub async fn run_memory_lifecycle_influence(
    config_path: &Path,
    project: &str,
    task: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let task_id = Some(task_id_from_label(task));
    let lifecycle = MemoryLifecyclePacketView::default();
    let mut report = MemoryInfluenceService::report(
        project_id,
        task_id,
        Some(task.to_owned()),
        vec!["memory-lifecycle:baseline".to_owned()],
        &lifecycle,
    );
    write_memory_influence_to_memory(config_path, &mut report).await?;
    write_memory_influence_report(&root, &report)?;
    write_json(&report)
}

pub fn run_memory_lifecycle_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = ProjectId::new_v7();
    let report = MemoryLifecycleReport {
        component: "memory_lifecycle_report".to_owned(),
        statuses: vec![
            MemoryLifecycleService::new().status(project_id, "memory-lifecycle:baseline"),
        ],
        proposals: Vec::new(),
        influence: read_optional_report::<MemoryInfluenceReport>(&root, "memory-influence")?,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_memory_lifecycle_report(&root, &report)?;
    write_json(&report)
}

pub async fn run_skill_create(config_path: &Path, project: &str, name: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let skill = SkillRegistryService::create_candidate(name, "codex");
    let receipt = write_skill_card_to_memory(config_path, &skill).await?;
    let report = serde_json::json!({
        "component": "skill_create",
        "project_id": project_id,
        "skill": skill,
        "write_receipt": receipt,
        "operation_status": OperationStatus::OperationCompleted
    });
    write_skill_report_pair(&root, "skills", "Skills", &report)?;
    write_json(&report)
}

pub fn run_skill_list(config_path: &Path, project: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let skills = smoke_skill_cards();
    let normal = SkillDistractorFilterService::filter(
        project_id,
        TaskId::new_v7(),
        &skills,
        &smoke_skill_context("skill-lifecycle-smoke"),
    );
    let report = serde_json::json!({
        "component": "skill_list",
        "project_id": project_id,
        "skills": skills,
        "normal_recall_included": normal.skills_included,
        "normal_recall_removed": normal.distractors_removed,
        "operation_status": OperationStatus::OperationCompleted
    });
    write_skill_report_pair(&root, "skills", "Skills", &report)?;
    write_json(&report)
}

pub fn run_skill_inspect(config_path: &Path, skill: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let skill_id = skill_id_from_label(skill);
    let card = smoke_active_skill_with_id(skill_id, SkillState::Active);
    let record = SkillLifecycleService::record_for(&card, None);
    let report = serde_json::json!({
        "component": "skill_inspect",
        "skill": card,
        "lifecycle_record": record
    });
    write_skill_report_pair(&root, "skills", "Skill Inspect", &report)?;
    write_json(&report)
}

pub fn run_skill_activate(config_path: &Path, skill: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let skill_id = skill_id_from_label(skill);
    let card = smoke_active_skill_with_id(skill_id, SkillState::Candidate);
    let (activated, record) =
        SkillLifecycleService::activate(&card, vec!["evidence:skill-activation".to_owned()])
            .map_err(|decision| anyhow::anyhow!("skill activation denied: {decision:?}"))?;
    let report = serde_json::json!({
        "component": "skill_activate",
        "skill": activated,
        "lifecycle_record": record,
        "operation_status": OperationStatus::OperationCompleted
    });
    write_skill_report_pair(&root, "skill-lifecycle", "Skill Lifecycle", &report)?;
    write_json(&report)
}

pub fn run_skill_archive(config_path: &Path, skill: &str, reason: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let skill_id = skill_id_from_label(skill);
    let card = smoke_active_skill_with_id(skill_id, SkillState::Active);
    let (archived, record) = SkillLifecycleService::archive(&card, reason);
    let report = serde_json::json!({
        "component": "skill_archive",
        "skill": archived,
        "lifecycle_record": record,
        "reason": reason
    });
    write_skill_report_pair(&root, "skill-lifecycle", "Skill Lifecycle", &report)?;
    write_json(&report)
}

pub fn run_skill_quarantine(config_path: &Path, skill: &str, reason: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let skill_id = skill_id_from_label(skill);
    let card = smoke_active_skill_with_id(skill_id, SkillState::Active);
    let (quarantined, record) = SkillLifecycleService::quarantine(&card, reason);
    let report = serde_json::json!({
        "component": "skill_quarantine",
        "skill": quarantined,
        "lifecycle_record": record,
        "reason": reason
    });
    write_skill_report_pair(&root, "skill-lifecycle", "Skill Lifecycle", &report)?;
    write_json(&report)
}

pub fn run_skill_estimate(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let task_id = task_id_from_label(task);
    let skill = smoke_active_skill();
    let estimate =
        SkillNeedEstimator::estimate(project_id, task_id, &skill, &smoke_skill_context(task));
    write_skill_report_pair(&root, "skill-activation", "Skill Activation", &estimate)?;
    write_json(&estimate)
}

pub fn run_skill_filter(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let task_id = task_id_from_label(task);
    let report = SkillDistractorFilterService::filter(
        project_id,
        task_id,
        &smoke_filter_skill_cards(),
        &smoke_skill_context(task),
    );
    write_skill_report_pair(&root, "skill-activation", "Skill Activation", &report)?;
    write_json(&report)
}

pub async fn run_skill_execution_proof(config_path: &Path, skill: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = ProjectId::new_v7();
    let task_id = task_id_from_label(task);
    let skill_id = skill_id_from_label(skill);
    let mut proof = SkillExecutionProofService::proof(
        skill_id,
        project_id,
        task_id,
        vec!["inspect-scope".to_owned(), "run-verifier".to_owned()],
        vec!["skill output was verified".to_owned()],
        vec!["just verify".to_owned()],
        SkillExecutionOutcome::Succeeded,
    );
    let receipt = write_skill_execution_proof_to_memory(config_path, &mut proof).await?;
    let report = serde_json::json!({
        "component": "skill_execution_proof",
        "proof": proof,
        "write_receipt": receipt
    });
    write_skill_report_pair(&root, "skill-lifecycle", "Skill Execution Proof", &report)?;
    write_json(&report)
}

pub async fn run_skill_influence(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let task_id = task_id_from_label(task);
    let skill = smoke_active_skill();
    let mut report = SkillInfluenceService::report(SkillInfluenceReportInput {
        project_id,
        task_id,
        packet_id: Some(task.to_owned()),
        considered: vec![skill.skill_id],
        included: vec![skill.skill_id],
        executed: Vec::new(),
        execution_proofs: Vec::new(),
        estimated_context_cost: 128,
    });
    write_skill_influence_to_memory(config_path, &mut report).await?;
    write_skill_influence_report(&root, &report)?;
    write_json(&report)
}

pub fn run_skill_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let skills = smoke_filter_skill_cards();
    let context = smoke_skill_context("skill-lifecycle-smoke");
    let filter = SkillDistractorFilterService::filter(project_id, task_id, &skills, &context);
    let influence = SkillInfluenceService::report(SkillInfluenceReportInput {
        project_id,
        task_id,
        packet_id: Some("skill-report".to_owned()),
        considered: filter.skills_considered.clone(),
        included: filter.skills_included.clone(),
        executed: Vec::new(),
        execution_proofs: Vec::new(),
        estimated_context_cost: 128,
    });
    let report = serde_json::json!({
        "component": "skill_report",
        "skills": skills,
        "filter": filter,
        "influence": influence
    });
    write_skill_report_pair(&root, "skills", "Skills", &report)?;
    write_json(&report)
}

pub async fn run_skill_curator_run(config_path: &Path, project: &str, dry_run: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let mut run = smoke_curator_run(project, dry_run);
    write_skill_curator_run_to_memory(config_path, &mut run).await?;
    let gate_decisions = smoke_curator_gate_decisions(&run);
    write_skill_curator_reports(&root, &run, &gate_decisions)?;
    let report = SkillCurationReportService::report(run);
    write_json(&report)
}

pub fn run_skill_curator_inspect(config_path: &Path, run_id: &str) -> Result<()> {
    let run = latest_skill_curator_run(&runtime_root(config_path))?
        .context("no latest skill-curator run found; run skill-curator run first")?;
    if run_id != "latest" && run.run_id != run_id {
        bail!("requested run id does not match latest skill-curator run");
    }
    write_json(&run)
}

pub async fn run_skill_curator_proposals(config_path: &Path, project: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let run = if let Some(run) = latest_skill_curator_run(&root)? {
        run
    } else {
        let mut run = smoke_curator_run(project, true);
        write_skill_curator_run_to_memory(config_path, &mut run).await?;
        run
    };
    let gate_decisions = smoke_curator_gate_decisions(&run);
    write_skill_curator_reports(&root, &run, &gate_decisions)?;
    let report = serde_json::json!({
        "component": "skill_curation_proposals",
        "project": project,
        "run_id": run.run_id,
        "open_proposals": run.proposals,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_json(&report)
}

pub fn run_skill_curator_gate(config_path: &Path, proposal_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let proposal = find_skill_curation_proposal(&root, proposal_id)?;
    let decision =
        SkillCurationGate::decide(&proposal, IncidentService::new(&root).lockdown_active()?);
    write_skill_curator_gate_report(&root, std::slice::from_ref(&decision))?;
    write_json(&decision)
}

pub async fn run_skill_curator_apply(config_path: &Path, proposal_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let proposal = find_skill_curation_proposal(&root, proposal_id)?;
    let decision =
        SkillCurationGate::decide(&proposal, IncidentService::new(&root).lockdown_active()?);
    write_skill_curator_gate_report(&root, std::slice::from_ref(&decision))?;
    if decision.decision != SkillCurationDecisionKind::Allow {
        bail!("skill-curator apply denied by gate: {:?}", decision.reasons);
    }
    if matches!(
        proposal.action,
        SkillCurationAction::Promote | SkillCurationAction::Merge | SkillCurationAction::Split
    ) {
        bail!("skill-curator apply supports only safe patch/archive/quarantine in I2");
    }

    let base_skill = smoke_active_skill_with_id(proposal.skill_ref, SkillState::Active);
    let summary = match proposal.action {
        SkillCurationAction::Patch => {
            let _patched = SkillPatchService::apply_narrow_patch(&base_skill, &proposal).map_err(
                |decision| anyhow::anyhow!("skill patch denied: {:?}", decision.reasons),
            )?;
            "safe narrow skill patch applied through governed CLI"
        }
        SkillCurationAction::Archive => {
            let _archived = SkillArchiveQuarantineService::safe_archive(
                &base_skill,
                "skill curator safe archive",
            );
            "safe archive receipt retained for audit"
        }
        SkillCurationAction::Quarantine => {
            let _quarantined = SkillArchiveQuarantineService::safe_quarantine(
                &base_skill,
                "skill curator safe quarantine",
            );
            "safe quarantine receipt retained for audit"
        }
        SkillCurationAction::Keep => {
            bail!("keep is read-only in I2 and has no apply action")
        }
        SkillCurationAction::Merge | SkillCurationAction::Split | SkillCurationAction::Promote => {
            unreachable!("high-risk actions are rejected before apply")
        }
    };
    let mut receipt = skill_curation_receipt(&proposal, true, summary);
    write_skill_curation_receipt_to_memory(config_path, &mut receipt).await?;
    let report = serde_json::json!({
        "component": "skill_curator_apply",
        "proposal": proposal,
        "gate_decision": decision,
        "receipt": receipt,
        "operation_status": OperationStatus::OperationCompleted
    });
    write_skill_report_pair(&root, "skill-curation-gate", "Skill Curation Gate", &report)?;
    write_json(&report)
}

pub fn run_skill_curator_rollback_plan(config_path: &Path, proposal_id: &str) -> Result<()> {
    let proposal = find_skill_curation_proposal(&runtime_root(config_path), proposal_id)?;
    write_json(&proposal.rollback_plan)
}

pub fn run_skill_curator_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "skill-curator")
}

pub async fn run_graph_health(config_path: &Path, project: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let service = GraphHealthService::new(CanonicalStore::new(config.db.surreal));
    let report = service.health(parse_project_id(project)?).await?;
    let root = runtime_root(config_path);
    write_report_pair(
        &root.join("reports").join("graph").join("latest.json"),
        &root.join("reports").join("graph").join("latest.md"),
        &report,
        &graph_health_markdown(&report),
    )?;
    write_json(&report)
}

pub fn run_codecortex_health(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = CodeCortexService::new(std::env::current_dir()?).health("eliot-governor")?;
    write_report_pair(
        &root.join("reports").join("codecortex").join("health.json"),
        &root.join("reports").join("codecortex").join("health.md"),
        &report,
        &codecortex_report_markdown(&report),
    )?;
    write_json(&report)
}

pub async fn run_codecortex_scan(
    config_path: &Path,
    project: &str,
    task: &str,
    goal: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let request = CodeCortexRequest {
        project: project.to_owned(),
        task: task.to_owned(),
        goal: goal.to_owned(),
        exact_patterns: Vec::new(),
        max_files: 160,
        max_matches_per_pattern: 24,
        include_diagnostics: true,
    };
    let mut report = CodeCortexService::new(std::env::current_dir()?).scan(&request)?;
    write_codecortex_report_to_memory(config_path, &mut report).await?;
    write_report_pair(
        &root.join("reports").join("codecortex").join("latest.json"),
        &root.join("reports").join("codecortex").join("latest.md"),
        &report,
        &codecortex_report_markdown(&report),
    )?;
    write_json(&report)
}

pub fn run_codecortex_report(config_path: &Path, latest: bool) -> Result<()> {
    if !latest {
        bail!("only codecortex report --latest is supported in D1");
    }
    let path = runtime_root(config_path)
        .join("reports")
        .join("codecortex")
        .join("latest.json");
    if !path.is_file() {
        bail!("no latest CodeCortex report found; run codecortex scan first");
    }
    let report: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    write_json(&report)
}

pub fn run_trace_completeness(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let contract = governed_trace_contract(project, task, true);
    write_replay_report(&root, "trace-completeness", "Trace Completeness", &contract)?;
    write_json(&contract)
}

pub fn run_trace_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "trace-completeness")
}

pub fn run_replay_case_create(
    config_path: &Path,
    project: &str,
    task: &str,
    kind: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let contract = read_latest_typed::<TraceCompletenessContract>(&root, "trace-completeness")
        .unwrap_or_else(|_| governed_trace_contract(project, task, true));
    if !contract.replay_allowed {
        bail!("replay case requires complete trace contract");
    }
    let case = ReplayCaseService::create(ReplayCaseInput {
        project_id: project_id_from_label(project),
        source_task_id: Some(task_id_from_label(task)),
        case_kind: parse_replay_case_kind(kind)?,
        trace_contract_ref: contract.contract_id.clone(),
        input_snapshot_refs: vec![contract.trace_ref.clone(), contract.contract_id],
    })?;
    write_replay_report(&root, "replay-cases", "Replay Case", &case)?;
    write_json(&case)
}

pub fn run_replay_set_create(
    config_path: &Path,
    project: &str,
    name: &str,
    fixed: bool,
    holdout: bool,
) -> Result<()> {
    let root = runtime_root(config_path);
    let case = read_latest_typed::<ReplayCase>(&root, "replay-cases")
        .context("no latest replay case found; run replay case create first")?;
    let set = ReplaySetService::create(ReplaySetInput {
        project_id: project_id_from_label(project),
        name: name.to_owned(),
        purpose: "Deterministic governed replay set".to_owned(),
        cases: vec![case.replay_case_id],
        fixed,
        holdout,
        created_from_refs: vec![case.trace_contract_ref.clone()],
    });
    write_replay_report(&root, "replay-cases", "Replay Case", &case)?;
    write_replay_report(&root, "replay-sets", "Replay Set", &set)?;
    write_json(&set)
}

pub fn run_replay_set_add(config_path: &Path, case: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut set = read_latest_typed::<ReplaySet>(&root, "replay-sets")
        .context("no latest replay set found; run replay set create first")?;
    let latest_case = read_latest_typed::<ReplayCase>(&root, "replay-cases")
        .context("no latest replay case found; run replay case create first")?;
    if case != "latest" && latest_case.replay_case_id.to_string() != case {
        bail!("only the latest replay case is available through this CLI");
    }
    ReplaySetService::add_case(&mut set, latest_case.replay_case_id)?;
    write_replay_report(&root, "replay-sets", "Replay Set", &set)?;
    write_json(&set)
}

pub fn run_replay_run(config_path: &Path, set: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let replay_set = read_latest_typed::<ReplaySet>(&root, "replay-sets")
        .context("no latest replay set found; run replay set create first")?;
    if set != "latest" && replay_set.name != set && replay_set.replay_set_id.to_string() != set {
        bail!("only the latest replay set or its name/id is available through this CLI");
    }
    let case = read_latest_typed::<ReplayCase>(&root, "replay-cases")
        .context("no latest replay case found; run replay case create first")?;
    let (run, audit) = ReplayRunnerService::run(
        replay_set.project_id,
        &replay_set,
        &[case],
        Some("dream:latest".to_owned()),
        Some("apply current truth"),
    );
    let report = serde_json::json!({ "run": run, "audit": audit });
    write_report_pair(
        &latest_report_path(&root, "replay-runs"),
        &latest_markdown_path(&root, "replay-runs"),
        &report,
        &value_report_markdown("Replay Run", &report),
    )?;
    write_json(&report)
}

pub fn run_replay_verdict(config_path: &Path, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let latest = read_latest_value(&root, "replay-runs")?;
    let replay_run: ReplayRun = serde_json::from_value(
        latest
            .get("run")
            .cloned()
            .context("latest replay run report has no run field")?,
    )?;
    if run != "latest" && replay_run.replay_run_id.to_string() != run {
        bail!("only the latest replay run or its id is available through this CLI");
    }
    let verdict = ReplayVerdictService::verdict(&replay_run);
    write_replay_report(&root, "replay-verdicts", "Replay Verdict", &verdict)?;
    write_json(&verdict)
}

pub fn run_replay_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let run = read_latest_value(&root, "replay-runs").ok();
    let verdict = read_latest_value(&root, "replay-verdicts").ok();
    let report = serde_json::json!({
        "component": "replay_report",
        "run": run,
        "verdict": verdict
    });
    write_json(&report)
}

pub fn run_sleep_run(
    config_path: &Path,
    project: &str,
    trigger: &str,
    dry_run: bool,
) -> Result<()> {
    let root = runtime_root(config_path);
    let run = SleepConsolidationService::run(
        SleepRunInput {
            project_id: project_id_from_label(project),
            trigger: parse_sleep_trigger(trigger)?,
            dry_run,
            input_traces: vec!["trace:latest".to_owned()],
            max_input_bytes: 8_192,
            reasoning_retry_limit: 1,
        },
        IncidentService::new(&root).lockdown_active()?,
    )?;
    write_replay_report(&root, "sleep", "Sleep Consolidation", &run)?;
    write_json(&run)
}

pub fn run_sleep_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "sleep")
}

pub fn run_dream_candidate_create(
    config_path: &Path,
    project: &str,
    kind: &str,
    source_trace: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let (candidate, taint) = DreamCandidateService::create(
        project_id_from_label(project),
        parse_dream_candidate_kind(kind)?,
        source_trace.to_owned(),
    );
    let report = serde_json::json!({
        "component": "dream_candidate",
        "candidate": candidate,
        "taint": taint
    });
    write_report_pair(
        &latest_report_path(&root, "dream"),
        &latest_markdown_path(&root, "dream"),
        &report,
        &value_report_markdown("Dream Candidate", &report),
    )?;
    write_json(&report)
}

pub fn run_dream_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "dream")
}

pub fn run_verify_inventory(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_verification_inventory_report(&root)?;
    write_json(&report)
}

pub fn run_verify_profiles(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_verification_profiles_report(&root)?;
    write_json(&report)
}

pub fn run_verify_plan(config_path: &Path, profile: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let report = write_verification_plan_report(&root, &inventory, profile)?;
    write_json(&report)
}

pub fn run_verify_run(config_path: &Path, profile: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let plan = write_verification_plan_report(&root, &inventory, profile)?.plan;
    let (run_report, verdict_report) = write_verification_run_and_verdict(&root, &plan)?;
    write_json(&serde_json::json!({
        "component": "verification_run_with_verdict",
        "run": run_report.run,
        "verdict": verdict_report.verdict,
        "generated_at": time::OffsetDateTime::now_utc()
    }))
}

pub fn run_verify_verdict(config_path: &Path, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let run_report: VerificationRunsReport = read_latest_typed(&root, "verification-runs")
        .context("no latest verification run found; run verify run --profile <profile> first")?;
    if run != "latest" && run != run_report.run.run_id {
        bail!("only the latest verification run or its run_id is available through this CLI");
    }
    let verdict = VerificationVerdictService.verdict(&run_report.run);
    let report = VerificationVerdictsReport {
        component: "verification_verdicts".to_owned(),
        verdict,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(
        &root,
        "verification-verdicts",
        "Verification Verdicts",
        &report,
    )?;
    write_json(&report)
}

pub fn run_verify_cost_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let last_run = read_latest_typed::<VerificationRunsReport>(&root, "verification-runs")
        .ok()
        .map(|report| report.run);
    let report = write_test_cost_report(&root, &inventory, last_run.as_ref())?;
    write_json(&report)
}

pub fn run_verify_flake(config_path: &Path, profile: &str, repeat: u64) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let report = write_flake_report(&root, profile, repeat, &inventory)?;
    write_json(&report)
}

pub fn run_verify_db_isolation(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let report = write_db_isolation_report(&root, &inventory)?;
    write_json(&report)
}

pub fn run_verify_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ensure_verification_summary(&root)?;
    write_json(&report)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TestInventoryReport {
    component: String,
    inventory: TestInventory,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerificationProfilesReport {
    component: String,
    profiles: Vec<TestSuiteProfile>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerificationPlansReport {
    component: String,
    plan: VerificationPlan,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerificationRunsReport {
    component: String,
    run: ProfileVerificationRun,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerificationVerdictsReport {
    component: String,
    verdict: VerificationVerdict,
    generated_at: time::OffsetDateTime,
}

fn ensure_verification_summary(root: &Path) -> Result<serde_json::Value> {
    let inventory = write_verification_inventory_report(root)?.inventory;
    let profiles = write_verification_profiles_report(root)?.profiles;
    let change_gate_plan = write_verification_plan_report(root, &inventory, "change-gate")?.plan;
    let (run_report, verdict_report) = write_verification_run_and_verdict(root, &change_gate_plan)?;
    let cost = write_test_cost_report(root, &inventory, Some(&run_report.run))?;
    let flake = write_flake_report(root, "change-gate", 2, &inventory)?;
    let db_isolation = write_db_isolation_report(root, &inventory)?;
    let doctor = VerificationDoctorIntegration.status(
        &inventory,
        &cost,
        &flake,
        &db_isolation,
        Some(&run_report.run),
    );
    let report = serde_json::json!({
        "component": "verification_report",
        "inventory": inventory,
        "profiles": profiles,
        "latest_plan": change_gate_plan,
        "latest_run": run_report.run,
        "latest_verdict": verdict_report.verdict,
        "cost": cost,
        "flake": flake,
        "db_isolation": db_isolation,
        "doctor_status": doctor,
        "authority": "profile-governance-only; no raw shell, raw db, or DONE override",
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_verification_report(root, "verification", "Verification", &report)?;
    Ok(report)
}

fn write_verification_inventory_report(root: &Path) -> Result<TestInventoryReport> {
    let inventory = TestInventoryService.generate(project_id_from_label("eliot-governor"));
    let report = TestInventoryReport {
        component: "test_inventory".to_owned(),
        inventory,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(root, "test-inventory", "Test Inventory", &report)?;
    Ok(report)
}

fn write_verification_profiles_report(root: &Path) -> Result<VerificationProfilesReport> {
    let report = VerificationProfilesReport {
        component: "verification_profiles".to_owned(),
        profiles: VerificationProfileService.profiles(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(
        root,
        "verification-profiles",
        "Verification Profiles",
        &report,
    )?;
    Ok(report)
}

fn write_verification_plan_report(
    root: &Path,
    inventory: &TestInventory,
    profile: &str,
) -> Result<VerificationPlansReport> {
    let plan = VerificationPlannerService.plan(
        inventory,
        profile,
        vec!["workspace:current".to_owned(), "phase:k2".to_owned()],
    )?;
    let report = VerificationPlansReport {
        component: "verification_plans".to_owned(),
        plan,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(root, "verification-plans", "Verification Plans", &report)?;
    Ok(report)
}

fn write_verification_run_and_verdict(
    root: &Path,
    plan: &VerificationPlan,
) -> Result<(VerificationRunsReport, VerificationVerdictsReport)> {
    let run = VerificationRunnerService.run_profile_record(plan)?;
    let run_report = VerificationRunsReport {
        component: "verification_runs".to_owned(),
        run,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(root, "verification-runs", "Verification Runs", &run_report)?;
    let verdict = VerificationVerdictService.verdict(&run_report.run);
    let verdict_report = VerificationVerdictsReport {
        component: "verification_verdicts".to_owned(),
        verdict,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(
        root,
        "verification-verdicts",
        "Verification Verdicts",
        &verdict_report,
    )?;
    Ok((run_report, verdict_report))
}

fn write_test_cost_report(
    root: &Path,
    inventory: &TestInventory,
    last_run: Option<&ProfileVerificationRun>,
) -> Result<TestCostReport> {
    let report = TestCostService.report(inventory, last_run);
    write_verification_report(root, "test-cost", "Test Cost", &report)?;
    Ok(report)
}

fn write_flake_report(
    root: &Path,
    profile: &str,
    repeat: u64,
    inventory: &TestInventory,
) -> Result<FlakeReport> {
    let report = FlakeDetectionService.report(profile, repeat, inventory);
    write_verification_report(root, "flake", "Flake", &report)?;
    Ok(report)
}

fn write_db_isolation_report(
    root: &Path,
    inventory: &TestInventory,
) -> Result<StatefulDbIsolationReport> {
    let report = StatefulDbTestIsolationService.report(inventory);
    write_verification_report(root, "db-isolation", "DB Isolation", &report)?;
    Ok(report)
}

fn write_verification_report<T>(root: &Path, dir: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(dir).join("latest.json"),
        &root.join("reports").join(dir).join("latest.md"),
        value,
        &verification_value_markdown(title, &serde_json::to_value(value)?),
    )
}

fn verification_value_markdown(title: &str, value: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(component) = value.get("component").and_then(serde_json::Value::as_str) {
        let _ = writeln!(output, "- component: `{component}`");
    }
    if let Some(profile) = value
        .get("plan")
        .or_else(|| value.get("run"))
        .or_else(|| value.get("verdict"))
        .and_then(|inner| inner.get("profile_id"))
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- profile: `{profile}`");
    }
    if let Some(decision) = value
        .get("verdict")
        .and_then(|verdict| verdict.get("decision"))
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- decision: `{decision}`");
    }
    let _ = writeln!(
        output,
        "- authority: `profile-governance-only; no raw shell, raw db, or DONE override`"
    );
    output
}
