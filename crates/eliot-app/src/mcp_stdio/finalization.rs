//! Finalizing a managed invocation exactly once.
//!
//! A managed run can be interrupted anywhere: after the provider answered but
//! before the receipt was canonicalized, after the intent was written but
//! before the aggregate was. So finalization is idempotent by construction --
//! a deterministic id derived from the invocation, a process lock, an intent
//! that is written once and re-read on retry, and a heal path that reconciles
//! whatever the last attempt left. The authority validation belongs here too,
//! because "may this session finalize" and "has it already" are answered
//! against the same records.

use super::*;

pub(super) fn managed_finalization_mutex(invocation_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: StdOnceLock<StdMutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
        StdOnceLock::new();
    let locks = LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut locks = locks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks
        .entry(invocation_id.to_owned())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

pub(super) async fn acquire_managed_finalization_process_lock(
    root: &Path,
    invocation_id: &str,
) -> Result<ManagedFinalizationProcessLock> {
    let lock_root = root.join("reports").join("managed-finalizations");
    std::fs::create_dir_all(&lock_root)?;
    let path = lock_root.join(format!(
        "{}.lock",
        blake3::hash(invocation_id.as_bytes()).to_hex()
    ));
    let started = std::time::Instant::now();
    loop {
        let record = serde_json::to_vec(&ManagedFinalizationProcessLockRecord {
            schema_version: "eliot-managed-finalization-process-lock-v1".to_owned(),
            invocation_id: invocation_id.to_owned(),
            owner_pid: std::process::id(),
            created_unix_seconds: time::OffsetDateTime::now_utc().unix_timestamp(),
        })?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(&record)?;
                file.sync_all()?;
                return Ok(ManagedFinalizationProcessLock { path, record });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::read(&path).unwrap_or_default();
                let metadata_age = std::fs::metadata(&path)
                    .and_then(|metadata| metadata.modified())
                    .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
                    .unwrap_or_default();
                let active =
                    serde_json::from_slice::<ManagedFinalizationProcessLockRecord>(&existing)
                        .ok()
                        .filter(|record| {
                            record.schema_version == "eliot-managed-finalization-process-lock-v1"
                                && record.invocation_id == invocation_id
                                && record.owner_pid != 0
                        })
                        .is_some_and(|record| {
                            eliot_windows_ipc::process_is_alive(record.owner_pid).unwrap_or(true)
                        });
                if !active
                    && metadata_age >= std::time::Duration::from_secs(2)
                    && std::fs::read(&path).is_ok_and(|bytes| bytes == existing)
                {
                    match std::fs::remove_file(&path) {
                        Ok(()) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => {}
                    }
                }
                if started.elapsed() >= std::time::Duration::from_mins(3) {
                    anyhow::bail!(
                        "timed out waiting for managed finalization process lock for {invocation_id}"
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(super) async fn acquire_task_transition_process_lock(
    root: &Path,
    task_id: TaskId,
) -> Result<TaskTransitionProcessLock> {
    const SCHEMA: &str = "eliot-task-transition-process-lock-v1";
    let lock_root = root.join("reports").join("task-transitions");
    std::fs::create_dir_all(&lock_root)?;
    let path = lock_root.join(format!("{task_id}.lock"));
    let started = std::time::Instant::now();
    loop {
        let record = serde_json::to_vec(&TaskTransitionProcessLockRecord {
            schema_version: SCHEMA.to_owned(),
            task_id,
            owner_pid: std::process::id(),
            created_unix_seconds: time::OffsetDateTime::now_utc().unix_timestamp(),
        })?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(&record)?;
                file.sync_all()?;
                return Ok(TaskTransitionProcessLock { path, record });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::read(&path).unwrap_or_default();
                let metadata_age = std::fs::metadata(&path)
                    .and_then(|metadata| metadata.modified())
                    .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
                    .unwrap_or_default();
                let active = serde_json::from_slice::<TaskTransitionProcessLockRecord>(&existing)
                    .ok()
                    .filter(|record| {
                        record.schema_version == SCHEMA
                            && record.task_id == task_id
                            && record.owner_pid != 0
                    })
                    .is_some_and(|record| {
                        eliot_windows_ipc::process_is_alive(record.owner_pid).unwrap_or(true)
                    });
                if !active
                    && metadata_age >= std::time::Duration::from_secs(2)
                    && std::fs::read(&path).is_ok_and(|bytes| bytes == existing)
                {
                    match std::fs::remove_file(&path) {
                        Ok(()) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => {}
                    }
                }
                if started.elapsed() >= std::time::Duration::from_mins(3) {
                    anyhow::bail!("timed out waiting for task transition lock for {task_id}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(super) fn deterministic_managed_uuid(label: &str, finalization_id: &str) -> uuid::Uuid {
    let digest = blake3::hash(format!("{label}:{finalization_id}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

pub(super) fn managed_finalization_id(invocation_id: &str, provider_output_hash: &str) -> String {
    format!(
        "managed-finalization:{}",
        blake3::hash(format!("{invocation_id}:{provider_output_hash}").as_bytes()).to_hex()
    )
}

pub(super) fn managed_finalization_key(intent: &ManagedFinalizationIntent, suffix: &str) -> String {
    format!("{}:{suffix}", intent.finalization_id)
}

pub(super) fn managed_finalization_failure(stage: &str) -> Result<()> {
    if std::env::var("ELIOT_TEST_MANAGED_FINALIZATION_FAIL_AFTER").as_deref() == Ok(stage) {
        anyhow::bail!("injected managed finalization failure after {stage}");
    }
    Ok(())
}

pub(super) async fn managed_finalization_test_pause_after_authority(root: &Path) -> Result<()> {
    let Ok(raw_millis) = std::env::var("ELIOT_TEST_MANAGED_FINALIZATION_PAUSE_AFTER_AUTHORITY_MS")
    else {
        return Ok(());
    };
    let millis = raw_millis
        .parse::<u64>()
        .context("parse managed finalization test pause")?;
    if millis == 0 || millis > 10_000 {
        anyhow::bail!("managed finalization test pause must be within 1..=10000 milliseconds");
    }
    let reports = root.join("reports");
    std::fs::create_dir_all(&reports)?;
    std::fs::write(
        reports.join("managed-finalization-authority-held.marker"),
        std::process::id().to_string(),
    )?;
    tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
    Ok(())
}

pub(super) async fn load_managed_finalization_authority(
    state: &McpState,
    context: AuthenticatedRequestContext,
    input: &AgentResultFinalizeToolInput,
) -> Result<ManagedFinalizationAuthority> {
    if state.profile != McpAccessProfile::CodexController {
        anyhow::bail!("managed AgentResult finalization is controller-only");
    }
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    validate_broker_refs("verifier_refs", &input.verifier_refs)?;
    let managed = crate::host_runtime::load_managed_controller_candidate(
        &state.root,
        &state.store,
        &input.invocation_id,
        &input.expected_provider_output_hash,
    )
    .await?;
    let (actual_verifier_refs, task) =
        validate_managed_actual_verifier_refs(state, &managed, &input.verifier_refs, true).await?;
    let controller_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
    let broker = delegation_runtime::load_state(&state.root)?;
    let work = load_work_state(&state.root)?;
    let (provider_result, authority_receipts) =
        validate_managed_broker_authority(state, &broker, &work, &managed, controller_session_id)
            .await?;
    Ok(ManagedFinalizationAuthority {
        managed,
        controller_session_id,
        broker,
        work,
        provider_result,
        actual_verifier_refs,
        task_revision: task.memory_revision,
        task_write_id: task.write_id,
        authority_receipts,
    })
}

fn managed_finalization_lease_is_active(state: eliot_types::AuthorityLeaseState) -> bool {
    state == eliot_types::AuthorityLeaseState::Active
}

#[allow(clippy::too_many_lines)]
pub(super) async fn validate_managed_broker_authority(
    state: &McpState,
    broker: &eliot_types::DelegationState,
    work: &WorkState,
    managed: &crate::host_runtime::ManagedControllerCandidate,
    controller_session_id: AgentSessionId,
) -> Result<(AgentResultEnvelope, BTreeMap<String, WriteReceiptRef>)> {
    let request = broker
        .agent_invocations
        .iter()
        .find(|item| item.invocation_id == managed.invocation_id)
        .context("managed invocation has no broker request")?;
    if request.invocation_id != managed.invocation_id
        || request.idempotency_key != managed.idempotency_key
        || request.project_id != managed.project_id
        || request.task_id != managed.task_id
        || request.work_item_id != managed.work_item_id
        || request.role_lease_id != managed.role_lease_id
        || request.work_lease_id != Some(managed.work_lease_id)
        || request.verifier_ref != managed.planned_verifier_ref
    {
        anyhow::bail!("managed result scope differs from the canonical broker request");
    }
    let provider_result = broker
        .agent_results
        .iter()
        .find(|item| item.result_id == managed.provider_result_id)
        .cloned()
        .context("managed provider result is absent from the broker")?;
    if provider_result.invocation_id != managed.invocation_id
        || provider_result.host_id != managed.provider_host_id
        || provider_result.host_session_id.as_deref()
            != Some(managed.provider_host_session_id.as_str())
        || provider_result.status != AgentResultStatus::Succeeded
        || !provider_result.candidate_only
        || !provider_result.verifier_refs.is_empty()
    {
        anyhow::bail!("broker provider result does not match managed execution evidence");
    }
    let job = broker
        .operation_jobs
        .iter()
        .find(|item| item.invocation_id == managed.invocation_id)
        .context("managed provider result has no broker job")?;
    if job.job_id != managed.broker_job_id
        || job.host_id != managed.provider_host_id
        || job.idempotency_key != managed.idempotency_key
        || job.resume_session_id.as_deref() != Some(managed.provider_host_session_id.as_str())
        || job.state != OperationJobState::Completed
        || job.result_ref.as_deref() != Some(managed.provider_result_id.as_str())
    {
        anyhow::bail!("broker job is not bound to the managed provider result");
    }
    let now = time::OffsetDateTime::now_utc();
    let controller = broker
        .controller_leases
        .iter()
        .find(|lease| {
            lease.task_id == managed.task_id
                && lease.agent_session_id == controller_session_id
                && managed_finalization_lease_is_active(lease.state)
                && lease.expires_at > now
        })
        .context("managed finalization requires the active ControllerLease")?;
    let controller_role = broker
        .task_role_leases
        .iter()
        .find(|role| {
            role.task_id == managed.task_id
                && role.agent_session_id == controller_session_id
                && role.role == AgentRole::Controller
                && managed_finalization_lease_is_active(role.state)
                && role.expires_at > now
                && role
                    .capability_scope
                    .iter()
                    .any(|capability| capability == "review")
                && role
                    .capability_scope
                    .iter()
                    .any(|capability| capability == "verify")
        })
        .context(
            "managed finalization requires current controller review and verify capabilities",
        )?;
    let provider_role = broker
        .task_role_leases
        .iter()
        .find(|role| role.role_lease_id == request.role_lease_id)
        .context("managed provider TaskRoleLease is absent")?;
    if provider_role.role_lease_id != managed.role_lease_id
        || provider_role.task_id != managed.task_id
        || provider_role.agent_session_id != managed.agent_session_id
        || !managed_finalization_lease_is_active(provider_role.state)
        || provider_role.expires_at <= now
        || provider_role.role == AgentRole::Controller
        || request
            .requested_capabilities
            .iter()
            .any(|capability| !provider_role.capability_scope.contains(capability))
    {
        anyhow::bail!("managed provider TaskRoleLease is stale or scope-mismatched");
    }
    let host_binding = broker
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == managed.agent_session_id)
        .context("managed provider host binding is absent")?;
    if host_binding.host_identity.host_id != managed.provider_host_id
        || host_binding.host_identity.client_instance_id != managed.provider_host_session_id
        || provider_result.host_id != host_binding.host_identity.host_id
        || provider_result.host_session_id.as_deref()
            != Some(host_binding.host_identity.client_instance_id.as_str())
    {
        anyhow::bail!("managed provider result host identity differs from the canonical binding");
    }
    let provider_session = work
        .sessions
        .iter()
        .find(|session| session.agent_session_id == managed.agent_session_id)
        .context("managed provider AgentSession projection is absent")?;
    let controller_session = work
        .sessions
        .iter()
        .find(|session| session.agent_session_id == controller_session_id)
        .context("managed controller AgentSession projection is absent")?;
    let work_lease = work
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == managed.work_lease_id)
        .context("managed result WorkLease is absent")?;
    let worktree = work
        .worktree_leases
        .iter()
        .find(|item| item.worktree_lease_id == managed.worktree_lease_id)
        .context("managed result WorktreeLease is absent")?;
    assert_production_worktree_cleanup_path(worktree)?;
    if work_lease.project_id != managed.project_id
        || work_lease.task_id != managed.task_id
        || work_lease.work_item_id != managed.work_item_id
        || work_lease.agent_session_id != managed.agent_session_id
        || !eliot_engine::work_lease_is_active(work_lease)
        || worktree.project_id != managed.project_id
        || worktree.task_id != managed.task_id
        || worktree.work_item_id != managed.work_item_id
        || worktree.work_lease_id != managed.work_lease_id
        || worktree.holder_session_id != managed.agent_session_id
        || Path::new(&worktree.worktree_path) != managed.worktree_path
        || worktree.allowed_write_set != managed.allowed_paths
        || worktree.state != WorktreeLeaseState::Active
        || worktree.expires_at <= now
    {
        anyhow::bail!("managed result is not bound to current active work authority");
    }
    let mut receipts = BTreeMap::new();
    macro_rules! current {
        ($key:literal, $task:expr, $entity:literal, $reference:expr, $field:literal, $kind:expr, $body:expr) => {{
            let receipt = require_exact_current_projection(
                state,
                managed.project_id,
                $task,
                $entity,
                $reference,
                $field,
                $kind,
                $body,
            )
            .await?;
            receipts.insert($key.to_owned(), receipt.clone());
            receipt
        }};
    }
    current!(
        "agent_invocation_request",
        Some(managed.task_id),
        "agent_invocation_request",
        &managed.invocation_id,
        "receipt_body",
        Some("agent_invocation_request"),
        request
    );
    let provider_receipt = current!(
        "provider_result",
        Some(managed.task_id),
        "agent_result",
        &provider_result.result_id,
        "receipt_body",
        Some("agent_result"),
        &provider_result
    );
    if provider_result.canonical_receipt.as_ref() != Some(&provider_receipt) {
        anyhow::bail!("managed provider result local receipt is stale");
    }
    current!(
        "operation_job",
        Some(managed.task_id),
        "operation_job",
        &job.job_id,
        "receipt_body",
        Some("operation_job"),
        job
    );
    current!(
        "controller_lease",
        Some(managed.task_id),
        "controller_lease",
        &controller.controller_lease_id,
        "receipt_body",
        Some("controller_lease"),
        controller
    );
    current!(
        "controller_role",
        Some(managed.task_id),
        "task_role_lease",
        &controller_role.role_lease_id,
        "receipt_body",
        Some("host_role_lease_authority"),
        controller_role
    );
    current!(
        "provider_role",
        Some(managed.task_id),
        "task_role_lease",
        &provider_role.role_lease_id,
        "receipt_body",
        Some("host_role_lease_authority"),
        provider_role
    );
    current!(
        "host_binding",
        Some(managed.task_id),
        "host_binding",
        &managed.agent_session_id.to_string(),
        "receipt_body",
        Some("host_binding_authority"),
        host_binding
    );
    current!(
        "provider_session",
        None,
        "agent_session",
        &managed.agent_session_id.to_string(),
        "agent_session",
        None,
        provider_session
    );
    current!(
        "controller_session",
        None,
        "agent_session",
        &controller_session_id.to_string(),
        "agent_session",
        None,
        controller_session
    );
    let work_receipt = current!(
        "work_lease",
        Some(managed.task_id),
        "work_lease",
        &managed.work_lease_id.to_string(),
        "work_lease",
        None,
        work_lease
    );
    if work_lease.write_receipt.as_ref() != Some(&work_receipt) {
        anyhow::bail!("managed WorkLease local receipt is stale");
    }
    let worktree_receipt = current!(
        "worktree_lease",
        Some(managed.task_id),
        "worktree_lease",
        &managed.worktree_lease_id.to_string(),
        "worktree_lease",
        None,
        worktree
    );
    if worktree.write_receipt.as_ref() != Some(&worktree_receipt) {
        anyhow::bail!("managed WorktreeLease local receipt is stale");
    }
    receipts.insert(
        "managed_result".to_owned(),
        managed.managed_result_receipt.clone(),
    );
    Ok((provider_result, receipts))
}

pub(super) async fn finalize_managed_broker_records(
    state: &McpState,
    context: AuthenticatedRequestContext,
    intent: &ManagedFinalizationIntent,
    authority: &mut ManagedFinalizationAuthority,
    artifacts: &FinalizedCandidateArtifacts,
) -> Result<FinalizedBrokerRecords> {
    let mut result = build_finalized_agent_result(authority, artifacts, intent);
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        authority.managed.project_id,
        Some(authority.managed.task_id),
        CanonicalReceiptKind::AgentResult,
        &managed_finalization_key(intent, "agent-result"),
        &result,
    )
    .await?;
    result.canonical_receipt = Some(receipt);
    let mut disposition = build_finalized_agent_result_disposition(authority, artifacts, intent);
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        authority.managed.project_id,
        Some(authority.managed.task_id),
        CanonicalReceiptKind::AgentResultDisposition,
        &managed_finalization_key(intent, "agent-result-disposition"),
        &disposition,
    )
    .await?;
    disposition.canonical_receipt = Some(receipt);
    Ok(FinalizedBrokerRecords {
        result,
        disposition,
    })
}

pub(super) fn build_finalized_agent_result(
    authority: &ManagedFinalizationAuthority,
    artifacts: &FinalizedCandidateArtifacts,
    intent: &ManagedFinalizationIntent,
) -> AgentResultEnvelope {
    let managed = &authority.managed;
    AgentResultEnvelope {
        result_id: intent.result_id.clone(),
        invocation_id: managed.invocation_id.clone(),
        host_id: authority.provider_result.host_id,
        host_session_id: authority.provider_result.host_session_id.clone(),
        status: AgentResultStatus::Succeeded,
        role_lease_epoch: authority.provider_result.role_lease_epoch,
        operation_generation: authority.provider_result.operation_generation,
        summary: "controller finalized exact managed provider CandidateDiff".to_owned(),
        artifact_refs: vec![
            artifacts.diff.diff_ref.clone(),
            format!("commit:{}", artifacts.commit_ref),
            format!("candidate-diff-id:{}", artifacts.diff.candidate_diff_id),
        ],
        evidence_refs: vec![
            format!("managed-provider-output:{}", managed.provider_output_hash),
            format!("candidate-review:{}", artifacts.review.review_id),
            format!(
                "managed-result-write:{}",
                managed.managed_result_receipt.write_id
            ),
        ],
        verifier_refs: intent.verifier_refs.clone(),
        candidate_only: true,
        exit_status: authority.provider_result.exit_status,
        token_or_cost_telemetry: authority.provider_result.token_or_cost_telemetry.clone(),
        unknown_outcome_evidence_refs: Vec::new(),
        supersedes_result_id: Some(managed.provider_result_id.clone()),
        provider_output_hash: Some(managed.provider_output_hash.clone()),
        canonical_receipt: None,
    }
}

pub(super) fn replace_finalized_agent_result(
    broker: &mut eliot_types::DelegationState,
    result: AgentResultEnvelope,
) -> Result<()> {
    let stored = broker
        .agent_results
        .iter_mut()
        .find(|item| item.result_id == result.result_id)
        .context("finalized AgentResult disappeared before canonical receipt binding")?;
    *stored = result;
    Ok(())
}

pub(super) fn build_finalized_agent_result_disposition(
    authority: &ManagedFinalizationAuthority,
    artifacts: &FinalizedCandidateArtifacts,
    intent: &ManagedFinalizationIntent,
) -> eliot_types::AgentResultDisposition {
    eliot_types::AgentResultDisposition {
        disposition_id: intent.disposition_id.clone(),
        result_id: intent.result_id.clone(),
        invocation_id: intent.invocation_id.clone(),
        task_id: intent.task_id,
        controller_session_id: authority.controller_session_id,
        kind: AgentResultDispositionKind::Accepted,
        reason: "accepted exact diff and commit bound to managed provider output".to_owned(),
        evidence_refs: vec![
            artifacts.diff.diff_ref.clone(),
            format!("commit:{}", artifacts.commit_ref),
            authority.managed.provider_output_hash.clone(),
        ],
        idempotency_key: managed_finalization_key(intent, "agent-result-disposition"),
        created_at: intent.created_at,
        canonical_receipt: None,
    }
}

pub(super) struct ManagedCandidateFileSets {
    pub(super) changed: Vec<String>,
    pub(super) added: Vec<String>,
    pub(super) modified: Vec<String>,
    pub(super) deleted: Vec<String>,
}

pub(super) fn new_managed_finalization_intent(
    authority: &ManagedFinalizationAuthority,
) -> Result<ManagedFinalizationIntent> {
    let managed = &authority.managed;
    let finalization_id =
        managed_finalization_id(&managed.invocation_id, &managed.provider_output_hash);
    let files = managed_candidate_file_sets(&managed.candidate_diff)?;
    let baseline_commit = authority
        .work
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == managed.worktree_lease_id)
        .context("managed WorktreeLease disappeared before intent")?
        .base_commit
        .clone();
    Ok(ManagedFinalizationIntent {
        schema_version: "eliot-managed-finalization-intent-v2".to_owned(),
        finalization_id: finalization_id.clone(),
        invocation_id: managed.invocation_id.clone(),
        project_id: managed.project_id,
        task_id: managed.task_id,
        task_revision: authority.task_revision,
        task_write_id: authority.task_write_id,
        work_item_id: managed.work_item_id,
        controller_session_id: authority.controller_session_id,
        provider_result_id: managed.provider_result_id.clone(),
        provider_output_hash: managed.provider_output_hash.clone(),
        candidate_diff_hash: managed.candidate_diff_hash.clone(),
        verifier_refs: authority.actual_verifier_refs.clone(),
        candidate_diff_id: CandidateDiffId::from_uuid(deterministic_managed_uuid(
            "candidate-diff",
            &finalization_id,
        )),
        review_id: format!(
            "candidate_review:{}",
            deterministic_managed_uuid("candidate-review", &finalization_id)
        ),
        result_id: format!(
            "agent-result-final:{}",
            deterministic_managed_uuid("agent-result", &finalization_id)
        ),
        disposition_id: format!(
            "agent-result-disposition:{}",
            deterministic_managed_uuid("agent-result-disposition", &finalization_id)
        ),
        work_lease_id: managed.work_lease_id,
        worktree_lease_id: managed.worktree_lease_id,
        baseline_commit,
        changed_files: files.changed,
        added_files: files.added,
        modified_files: files.modified,
        deleted_files: files.deleted,
        authority_receipts: authority.authority_receipts.clone(),
        created_at: managed.completed_at,
    })
}

pub(super) async fn load_or_write_managed_finalization_intent(
    state: &McpState,
    context: AuthenticatedRequestContext,
    authority: &ManagedFinalizationAuthority,
) -> Result<(ManagedFinalizationIntent, WriteReceiptRef)> {
    let proposed = new_managed_finalization_intent(authority)?;
    let key = managed_finalization_key(&proposed, "intent");
    let write_id = deterministic_canonical_write_id(
        proposed.project_id,
        Some(proposed.task_id),
        CanonicalReceiptKind::ManagedFinalizationIntent,
        &key,
    );
    if let Some(existing) = state
        .store
        .canonical_record_by_write_id::<ManagedFinalizationIntent>(
            proposed.project_id,
            Some(proposed.task_id),
            &["managed_finalization_intent"],
            write_id,
        )
        .await?
    {
        let immutable_matches = existing.receipt_body.finalization_id == proposed.finalization_id
            && existing.receipt_body.schema_version == "eliot-managed-finalization-intent-v2"
            && existing.receipt_body.invocation_id == proposed.invocation_id
            && existing.receipt_body.project_id == proposed.project_id
            && existing.receipt_body.task_id == proposed.task_id
            && existing.receipt_body.task_revision == proposed.task_revision
            && existing.receipt_body.task_write_id == proposed.task_write_id
            && existing.receipt_body.controller_session_id == proposed.controller_session_id
            && existing.receipt_body.provider_result_id == proposed.provider_result_id
            && existing.receipt_body.provider_output_hash == proposed.provider_output_hash
            && existing.receipt_body.candidate_diff_hash == proposed.candidate_diff_hash
            && existing.receipt_body.verifier_refs == proposed.verifier_refs
            && existing.receipt_body.baseline_commit == proposed.baseline_commit
            && existing.receipt_body.changed_files == proposed.changed_files
            && existing.receipt_body.added_files == proposed.added_files
            && existing.receipt_body.modified_files == proposed.modified_files
            && existing.receipt_body.deleted_files == proposed.deleted_files
            && existing.receipt_body.authority_receipts == proposed.authority_receipts;
        if !immutable_matches {
            anyhow::bail!("managed finalization intent CAS conflicts with current authority");
        }
        return Ok((existing.receipt_body, existing.canonical_receipt));
    }
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        proposed.project_id,
        Some(proposed.task_id),
        CanonicalReceiptKind::ManagedFinalizationIntent,
        &key,
        &proposed,
    )
    .await?;
    Ok((proposed, receipt))
}

pub(super) async fn load_managed_finalization_intent(
    state: &McpState,
    managed: &crate::host_runtime::ManagedControllerCandidate,
) -> Result<ManagedFinalizationIntent> {
    let finalization_id =
        managed_finalization_id(&managed.invocation_id, &managed.provider_output_hash);
    let key = format!("{finalization_id}:intent");
    let write_id = deterministic_canonical_write_id(
        managed.project_id,
        Some(managed.task_id),
        CanonicalReceiptKind::ManagedFinalizationIntent,
        &key,
    );
    let record = state
        .store
        .canonical_record_by_write_id::<ManagedFinalizationIntent>(
            managed.project_id,
            Some(managed.task_id),
            &["managed_finalization_intent"],
            write_id,
        )
        .await?
        .context("managed finalization aggregate has no canonical intent")?;
    let intent = record.receipt_body;
    if intent.schema_version != "eliot-managed-finalization-intent-v2"
        || intent.finalization_id != finalization_id
        || intent.invocation_id != managed.invocation_id
        || intent.project_id != managed.project_id
        || intent.task_id != managed.task_id
        || intent.work_item_id != managed.work_item_id
        || intent.provider_result_id != managed.provider_result_id
        || intent.provider_output_hash != managed.provider_output_hash
        || intent.candidate_diff_hash != managed.candidate_diff_hash
        || intent.work_lease_id != managed.work_lease_id
        || intent.worktree_lease_id != managed.worktree_lease_id
        || !intent
            .authority_receipts
            .contains_key("agent_invocation_request")
    {
        anyhow::bail!("managed finalization intent differs from exact managed authority");
    }
    Ok(intent)
}

pub(super) async fn load_managed_finalization_aggregate(
    state: &McpState,
    managed: &crate::host_runtime::ManagedControllerCandidate,
) -> Result<Option<(ManagedFinalizationAggregate, WriteReceiptRef)>> {
    let finalization_id =
        managed_finalization_id(&managed.invocation_id, &managed.provider_output_hash);
    let key = format!("{finalization_id}:aggregate");
    let write_id = deterministic_canonical_write_id(
        managed.project_id,
        Some(managed.task_id),
        CanonicalReceiptKind::ManagedFinalizationAggregate,
        &key,
    );
    let Some(record) = state
        .store
        .canonical_record_by_write_id::<ManagedFinalizationAggregate>(
            managed.project_id,
            Some(managed.task_id),
            &["managed_finalization_aggregate"],
            write_id,
        )
        .await?
    else {
        return Ok(None);
    };
    if record.receipt_body.finalization_id != finalization_id
        || record.receipt_body.invocation_id != managed.invocation_id
        || record.receipt_body.provider_output_hash != managed.provider_output_hash
    {
        anyhow::bail!("managed finalization aggregate identity differs");
    }
    Ok(Some((record.receipt_body, record.canonical_receipt)))
}

pub(super) fn finalized_authority_projections(
    authority: &ManagedFinalizationAuthority,
    intent: &ManagedFinalizationIntent,
    records: &FinalizedBrokerRecords,
) -> Result<(WorktreeLease, WorkLease, OperationJob)> {
    let mut worktree = authority
        .work
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == intent.worktree_lease_id)
        .cloned()
        .context("managed WorktreeLease disappeared before aggregate")?;
    worktree.state = WorktreeLeaseState::Accepted;
    worktree.write_receipt = None;
    let mut work_lease = authority
        .work
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == intent.work_lease_id)
        .cloned()
        .context("managed WorkLease disappeared before aggregate")?;
    work_lease.write_receipt = None;
    let mut job = authority
        .broker
        .operation_jobs
        .iter()
        .find(|job| job.invocation_id == intent.invocation_id)
        .cloned()
        .context("managed OperationJob disappeared before aggregate")?;
    job.result_ref = Some(records.result.result_id.clone());
    job.updated_at = intent.created_at;
    Ok((worktree, work_lease, job))
}

pub(super) fn upsert_managed_finalization_projections(
    authority: &mut ManagedFinalizationAuthority,
    aggregate: &ManagedFinalizationAggregate,
) {
    replace_candidate_diff(&mut authority.work, aggregate.candidate_diff.clone());
    replace_candidate_review(&mut authority.work, aggregate.candidate_review.clone());
    replace_worktree_lease(&mut authority.work, aggregate.worktree_lease.clone());
    if let Some(lease) = authority
        .work
        .leases
        .iter_mut()
        .find(|lease| lease.work_lease_id == aggregate.work_lease.work_lease_id)
    {
        *lease = aggregate.work_lease.clone();
    } else {
        authority.work.leases.push(aggregate.work_lease.clone());
    }
    if let Some(result) = authority
        .broker
        .agent_results
        .iter_mut()
        .find(|result| result.result_id == aggregate.result.result_id)
    {
        *result = aggregate.result.clone();
    } else {
        authority
            .broker
            .agent_results
            .push(aggregate.result.clone());
    }
    if let Some(disposition) = authority
        .broker
        .agent_result_dispositions
        .iter_mut()
        .find(|item| item.disposition_id == aggregate.disposition.disposition_id)
    {
        *disposition = aggregate.disposition.clone();
    } else {
        authority
            .broker
            .agent_result_dispositions
            .push(aggregate.disposition.clone());
    }
    if let Some(job) = authority
        .broker
        .operation_jobs
        .iter_mut()
        .find(|job| job.job_id == aggregate.operation_job.job_id)
    {
        *job = aggregate.operation_job.clone();
    } else {
        authority
            .broker
            .operation_jobs
            .push(aggregate.operation_job.clone());
    }
}

pub(super) async fn heal_managed_finalization(
    state: &McpState,
    context: AuthenticatedRequestContext,
    authority: &mut ManagedFinalizationAuthority,
    aggregate: &mut ManagedFinalizationAggregate,
) -> Result<()> {
    let key = |suffix| format!("{}:{suffix}", aggregate.finalization_id);
    let mut diff = aggregate.candidate_diff.clone();
    diff.write_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::CandidateDiff,
        &key("candidate-diff"),
        &diff,
    )
    .await?;
    if aggregate.candidate_diff.write_receipt.as_ref() != Some(&receipt) {
        anyhow::bail!("managed aggregate CandidateDiff receipt differs from exact write");
    }
    let mut review = aggregate.candidate_review.clone();
    review.write_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::CandidateReview,
        &key("candidate-review"),
        &review,
    )
    .await?;
    if aggregate.candidate_review.write_receipt.as_ref() != Some(&receipt) {
        anyhow::bail!("managed aggregate CandidateReview receipt differs from exact write");
    }
    let mut result = aggregate.result.clone();
    result.canonical_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::AgentResult,
        &key("agent-result"),
        &result,
    )
    .await?;
    if aggregate.result.canonical_receipt.as_ref() != Some(&receipt) {
        anyhow::bail!("managed aggregate AgentResult receipt differs from exact write");
    }
    let mut disposition = aggregate.disposition.clone();
    disposition.canonical_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::AgentResultDisposition,
        &key("agent-result-disposition"),
        &disposition,
    )
    .await?;
    if aggregate.disposition.canonical_receipt.as_ref() != Some(&receipt) {
        anyhow::bail!("managed aggregate disposition receipt differs from exact write");
    }
    let mut worktree = aggregate.worktree_lease.clone();
    write_canonical_worktree_lease(state, context, &mut worktree, &key("worktree-lease")).await?;
    aggregate.worktree_lease = worktree;
    let mut work_lease = aggregate.work_lease.clone();
    write_canonical_work_lease(state, context, &mut work_lease, &key("work-lease")).await?;
    aggregate.work_lease = work_lease;
    write_canonical_observation(
        state,
        context,
        aggregate.worktree_lease.project_id,
        Some(aggregate.worktree_lease.task_id),
        CanonicalReceiptKind::OperationJob,
        &key("operation-job"),
        &aggregate.operation_job,
    )
    .await?;
    managed_finalization_failure("authority_secondaries")?;
    upsert_managed_finalization_projections(authority, aggregate);
    managed_finalization_failure("local_save")?;
    save_worktree_state_and_reports(&state.root, &authority.work)?;
    delegation_runtime::save_host_broker_state(&state.root, &authority.broker)?;
    Ok(())
}

pub(super) fn managed_finalization_response(
    aggregate: &ManagedFinalizationAggregate,
    aggregate_receipt: &WriteReceiptRef,
) -> Value {
    json!({
        "schema_version": "eliot-agent-result-finalize-v2",
        "finalization_id": aggregate.finalization_id,
        "candidate_diff": aggregate.candidate_diff,
        "candidate_review": aggregate.candidate_review,
        "result": aggregate.result,
        "disposition": aggregate.disposition,
        "commit_ref": aggregate.commit_ref,
        "provider_output_hash": aggregate.provider_output_hash,
        "canonical_aggregate_receipt": aggregate_receipt,
        "completion_authority_granted": false
    })
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_agent_result_finalize(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AgentResultFinalizeToolInput = serde_json::from_value(arguments)?;
    if state.profile != McpAccessProfile::CodexController {
        anyhow::bail!("managed AgentResult finalization is controller-only");
    }
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    let lock = managed_finalization_mutex(&input.invocation_id);
    let _guard = lock.lock().await;
    let _process_guard =
        acquire_managed_finalization_process_lock(&state.root, &input.invocation_id).await?;
    let managed = crate::host_runtime::load_managed_controller_candidate(
        &state.root,
        &state.store,
        &input.invocation_id,
        &input.expected_provider_output_hash,
    )
    .await?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard =
        acquire_task_transition_process_lock(&state.root, managed.task_id).await?;
    if let Some((mut aggregate, receipt)) =
        load_managed_finalization_aggregate(state, &managed).await?
    {
        let intent = load_managed_finalization_intent(state, &managed).await?;
        if intent.verifier_refs != input.verifier_refs
            || aggregate.verifier_refs != input.verifier_refs
        {
            anyhow::bail!(
                "managed finalization replay verifier refs differ from the sealed intent"
            );
        }
        let (actual_verifier_refs, _) =
            validate_managed_actual_verifier_refs(state, &managed, &input.verifier_refs, false)
                .await?;
        validate_managed_finalization_aggregate_replay(&managed, &intent, &aggregate)?;
        let controller_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
        if aggregate.disposition.controller_session_id != controller_session_id {
            anyhow::bail!("managed finalization replay belongs to another controller session");
        }
        let broker = delegation_runtime::load_state(&state.root)?;
        let work = load_work_state(&state.root)?;
        let mut authority = ManagedFinalizationAuthority {
            managed,
            controller_session_id,
            broker,
            work,
            // Terminal replay is authorized by the canonical aggregate. The
            // original mutable provider projection may have been lost; this
            // placeholder is never consulted by the healing path.
            provider_result: aggregate.result.clone(),
            actual_verifier_refs,
            task_revision: intent.task_revision,
            task_write_id: intent.task_write_id,
            authority_receipts: BTreeMap::new(),
        };
        heal_managed_finalization(state, context, &mut authority, &mut aggregate).await?;
        return Ok(managed_finalization_response(&aggregate, &receipt));
    }
    let mut authority = load_managed_finalization_authority(state, context, &input).await?;
    managed_finalization_test_pause_after_authority(&state.root).await?;
    let (intent, _intent_receipt) =
        load_or_write_managed_finalization_intent(state, context, &authority).await?;
    managed_finalization_failure("intent")?;
    let mut artifacts = materialize_managed_candidate(state, &intent, &mut authority)?;
    canonicalize_candidate_artifacts(state, context, &intent, &authority, &mut artifacts).await?;
    managed_finalization_failure("candidate_secondaries")?;
    let records =
        finalize_managed_broker_records(state, context, &intent, &mut authority, &artifacts)
            .await?;
    managed_finalization_failure("result_secondaries")?;
    let (worktree_lease, work_lease, operation_job) =
        finalized_authority_projections(&authority, &intent, &records)?;
    let mut aggregate = ManagedFinalizationAggregate {
        schema_version: "eliot-managed-finalization-aggregate-v2".to_owned(),
        finalization_id: intent.finalization_id.clone(),
        invocation_id: intent.invocation_id.clone(),
        provider_output_hash: intent.provider_output_hash.clone(),
        verifier_refs: intent.verifier_refs.clone(),
        candidate_diff: artifacts.diff,
        candidate_review: artifacts.review,
        result: records.result,
        disposition: records.disposition,
        worktree_lease,
        work_lease,
        operation_job,
        commit_ref: artifacts.commit_ref,
    };
    let (aggregate_receipt, _) = write_canonical_observation(
        state,
        context,
        intent.project_id,
        Some(intent.task_id),
        CanonicalReceiptKind::ManagedFinalizationAggregate,
        &managed_finalization_key(&intent, "aggregate"),
        &aggregate,
    )
    .await?;
    managed_finalization_failure("aggregate")?;
    heal_managed_finalization(state, context, &mut authority, &mut aggregate).await?;
    Ok(managed_finalization_response(
        &aggregate,
        &aggregate_receipt,
    ))
}

pub(super) fn git_managed_bytes(worktree: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(args)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

pub(super) fn git_managed_stdout(worktree: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_managed_bytes(worktree, args)?)?
        .trim()
        .to_owned())
}

pub(super) fn managed_finalization_commit_message(intent: &ManagedFinalizationIntent) -> String {
    format!(
        "eliot: finalize {}\n\nEliot-Finalization-Id: {}\nEliot-Provider-Output-Hash: {}\nEliot-Candidate-Diff-Hash: {}",
        intent.invocation_id,
        intent.finalization_id,
        intent.provider_output_hash,
        intent.candidate_diff_hash
    )
}

pub(super) fn validate_managed_finalization_commit(
    worktree: &Path,
    intent: &ManagedFinalizationIntent,
    commit_ref: &str,
) -> Result<()> {
    let parent = git_managed_stdout(worktree, &["rev-parse", &format!("{commit_ref}^")])?;
    let message = git_managed_stdout(worktree, &["show", "-s", "--format=%B", commit_ref])?;
    let diff = git_managed_bytes(
        worktree,
        &[
            "diff",
            "--binary",
            "--no-ext-diff",
            &intent.baseline_commit,
            commit_ref,
            "--",
        ],
    )?;
    let status = git_managed_stdout(worktree, &["status", "--porcelain=v1"])?;
    if parent != intent.baseline_commit
        || message != managed_finalization_commit_message(intent)
        || managed_candidate_hash(&diff) != intent.candidate_diff_hash
        || !status.is_empty()
    {
        anyhow::bail!("existing managed finalization commit differs from exact intent");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn validate_managed_finalization_aggregate_replay(
    managed: &crate::host_runtime::ManagedControllerCandidate,
    intent: &ManagedFinalizationIntent,
    aggregate: &ManagedFinalizationAggregate,
) -> Result<()> {
    let expected_diff_hash = intent
        .candidate_diff_hash
        .strip_prefix("blake3:")
        .unwrap_or(&intent.candidate_diff_hash);
    if aggregate.schema_version != "eliot-managed-finalization-aggregate-v2"
        || aggregate.finalization_id != intent.finalization_id
        || aggregate.invocation_id != intent.invocation_id
        || aggregate.provider_output_hash != intent.provider_output_hash
        || aggregate.verifier_refs != intent.verifier_refs
        || aggregate.commit_ref.is_empty()
        || aggregate.candidate_diff.candidate_diff_id != intent.candidate_diff_id
        || aggregate.candidate_diff.worktree_lease_id != intent.worktree_lease_id
        || aggregate.candidate_diff.project_id != intent.project_id
        || aggregate.candidate_diff.task_id != intent.task_id
        || aggregate.candidate_diff.work_item_id != intent.work_item_id
        || aggregate.candidate_diff.base_commit != intent.baseline_commit
        || aggregate.candidate_diff.worktree_head.as_deref() != Some(aggregate.commit_ref.as_str())
        || aggregate.candidate_diff.diff_hash != expected_diff_hash
        || aggregate.candidate_diff.changed_files != intent.changed_files
        || aggregate.candidate_diff.added_files != intent.added_files
        || aggregate.candidate_diff.modified_files != intent.modified_files
        || aggregate.candidate_diff.deleted_files != intent.deleted_files
        || aggregate.candidate_diff.capture_status != CandidateDiffStatus::AcceptedForPatchRunner
        || aggregate.candidate_review.review_id != intent.review_id
        || aggregate.candidate_review.candidate_diff_id != intent.candidate_diff_id
        || aggregate.candidate_review.reviewer_session_id != intent.controller_session_id
        || aggregate.candidate_review.decision != CandidateReviewDecision::AcceptForPatchRunner
        || aggregate.result.result_id != intent.result_id
        || aggregate.result.invocation_id != intent.invocation_id
        || aggregate.result.host_id != managed.provider_host_id
        || aggregate.result.host_session_id.as_deref()
            != Some(managed.provider_host_session_id.as_str())
        || aggregate.result.provider_output_hash.as_deref()
            != Some(intent.provider_output_hash.as_str())
        || aggregate.result.supersedes_result_id.as_deref()
            != Some(intent.provider_result_id.as_str())
        || aggregate.result.verifier_refs != intent.verifier_refs
        || aggregate.disposition.disposition_id != intent.disposition_id
        || aggregate.disposition.result_id != intent.result_id
        || aggregate.disposition.invocation_id != intent.invocation_id
        || aggregate.disposition.task_id != intent.task_id
        || aggregate.disposition.controller_session_id != intent.controller_session_id
        || aggregate.disposition.kind != AgentResultDispositionKind::Accepted
        || aggregate.worktree_lease.worktree_lease_id != intent.worktree_lease_id
        || aggregate.worktree_lease.project_id != intent.project_id
        || aggregate.worktree_lease.task_id != intent.task_id
        || aggregate.worktree_lease.work_item_id != intent.work_item_id
        || aggregate.worktree_lease.work_lease_id != intent.work_lease_id
        || aggregate.worktree_lease.holder_session_id != managed.agent_session_id
        || Path::new(&aggregate.worktree_lease.worktree_path) != managed.worktree_path
        || aggregate.worktree_lease.base_commit != intent.baseline_commit
        || aggregate.worktree_lease.allowed_write_set != managed.allowed_paths
        || aggregate.worktree_lease.state != WorktreeLeaseState::Accepted
        || aggregate.work_lease.work_lease_id != intent.work_lease_id
        || aggregate.work_lease.project_id != intent.project_id
        || aggregate.work_lease.task_id != intent.task_id
        || aggregate.work_lease.work_item_id != intent.work_item_id
        || aggregate.work_lease.agent_session_id != managed.agent_session_id
        || aggregate.operation_job.job_id != managed.broker_job_id
        || aggregate.operation_job.invocation_id != intent.invocation_id
        || aggregate.operation_job.host_id != managed.provider_host_id
        || aggregate.operation_job.result_ref.as_deref() != Some(intent.result_id.as_str())
    {
        anyhow::bail!("managed finalization aggregate differs from exact intent authority");
    }
    let persisted_diff = std::fs::read(&aggregate.candidate_diff.diff_ref)
        .context("managed finalization CandidateDiff artifact is absent")?;
    if persisted_diff != managed.candidate_diff
        || aggregate.candidate_diff.byte_len != persisted_diff.len()
        || aggregate.candidate_diff.file_count != intent.changed_files.len()
        || managed_candidate_hash(&persisted_diff) != intent.candidate_diff_hash
    {
        anyhow::bail!("managed finalization CandidateDiff artifact differs from exact intent");
    }
    let head = git_managed_stdout(&managed.worktree_path, &["rev-parse", "HEAD"])?;
    if head != aggregate.commit_ref {
        anyhow::bail!("managed finalization worktree HEAD differs from the canonical aggregate");
    }
    validate_managed_finalization_commit(&managed.worktree_path, intent, &aggregate.commit_ref)?;
    Ok(())
}

#[cfg(test)]
mod authority_state_tests {
    use super::*;

    #[test]
    fn managed_finalization_accepts_only_active_authority_leases() {
        use eliot_types::AuthorityLeaseState::{Active, Consumed, Expired, Pending, Revoked};

        assert!(managed_finalization_lease_is_active(Active));
        for state in [Pending, Consumed, Revoked, Expired] {
            assert!(!managed_finalization_lease_is_active(state));
        }
    }
}
