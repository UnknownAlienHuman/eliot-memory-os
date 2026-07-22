//! The managed invocation chain.
//!
//! One managed launch is a chain, not a call: reserve an idempotent invocation,
//! journal the attempt, run the provider under a job object, canonicalize the
//! receipt, and reconcile whatever the previous attempt left behind. Every step
//! has to agree with the others about what a result means, so they live
//! together rather than beside the unrelated host commands.

use super::*;

pub(super) fn managed_request_hash(
    contract: &eliot_types::HostLaunchContract,
    program: &str,
    args: &[String],
) -> Result<String> {
    Ok(format!(
        "blake3:{}",
        blake3::hash(&serde_json::to_vec(&json!({
            "contract": contract,
            "program": program,
            "args": args,
        }))?)
        .to_hex()
    ))
}

pub(super) async fn canonicalize_managed_receipt(
    config_path: &Path,
    project_id: ProjectId,
    task_id: TaskId,
    session_id: AgentSessionId,
    invocation_id: &str,
    base: Value,
) -> Result<Value> {
    let body_hash = hash_json(&base)?;
    let (canonical_receipt, _) = write_canonical_host_observation(
        config_path,
        project_id,
        task_id,
        session_id,
        &format!("managed-host-result:{invocation_id}"),
        "managed_host_launch_result",
        &base,
    )
    .await?;
    let mut result = base;
    result
        .as_object_mut()
        .context("managed receipt must be a JSON object")?
        .insert(
            "canonical_authority".to_owned(),
            json!({
                "receipt": canonical_receipt,
                "body_hash": body_hash,
                "receipt_kind": "managed_host_launch_result",
            }),
        );
    let receipt_hash = hash_json(&result)?;
    result
        .as_object_mut()
        .context("managed receipt must be a JSON object")?
        .insert("receipt_hash".to_owned(), Value::String(receipt_hash));
    Ok(result)
}

pub(super) fn managed_result_write_id(invocation_id: &str) -> WriteId {
    deterministic_host_write_id(&format!("managed-host-result:{invocation_id}"))
}

pub(super) async fn exact_canonical_managed_result(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: TaskId,
    invocation_id: &str,
    request_hash: &str,
    expected_body: Option<&Value>,
) -> Result<Option<(Value, WriteReceiptRef)>> {
    let write_id = managed_result_write_id(invocation_id);
    let observations = store.tool_observations_by_write_id(&write_id).await?;
    if observations.is_empty() {
        return Ok(None);
    }
    if observations.len() != 1 {
        bail!("managed result write ID does not resolve to exactly one canonical body");
    }
    let observation = observations
        .first()
        .context("canonical managed result observation disappeared")?;
    let body = observation
        .payload
        .get("receipt_body")
        .cloned()
        .context("canonical managed result has no receipt body")?;
    let body_hash = hash_json(&body)?;
    if body.get("invocation_id").and_then(Value::as_str) != Some(invocation_id) {
        bail!("canonical managed result invocation identity differs");
    }
    if body.get("request_hash").and_then(Value::as_str) != Some(request_hash) {
        bail!("canonical managed result request hash differs");
    }
    if let Some(expected) = expected_body
        && expected != &body
    {
        bail!(
            "canonical managed result body differs from the durable result receipt: canonical_hash={} durable_hash={}",
            hash_json(&body)?,
            hash_json(expected)?
        );
    }
    if observation
        .payload
        .get("receipt_kind")
        .and_then(Value::as_str)
        != Some("managed_host_launch_result")
    {
        bail!("canonical managed result receipt kind differs");
    }
    if observation.payload.get("body_hash").and_then(Value::as_str) != Some(body_hash.as_str()) {
        bail!("canonical managed result body hash differs");
    }
    let receipt = store
        .write_receipt_by_id(&write_id)
        .await?
        .context("canonical managed result body has no WriteReceipt")?;
    let reference = WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id,
    };
    let receipt = resolve_canonical_receipt(
        store,
        &reference,
        project_id,
        Some(task_id),
        "managed host result",
    )
    .await?;
    validate_canonical_observation_identity(
        observation,
        &receipt,
        project_id,
        &CanonicalAuthorityBody {
            label: "managed host result",
            task_id: Some(task_id),
            scope: "governed host authority",
            authority: "canonical Eliot host boundary",
            tool_name: "eliot-governor-host",
            payload_key: "receipt_body",
            body: &body,
            normalization: CanonicalBodyNormalization::Exact,
        },
    )?;
    Ok(Some((body, reference)))
}

pub(super) async fn recover_canonical_managed_receipt(
    config_path: &Path,
    attempt: &ManagedHostAttemptJournal,
) -> Result<Option<Value>> {
    let project_id = attempt
        .project_id
        .context("attempt lost project authority")?;
    let task_id = attempt.task_id.context("attempt lost task authority")?;
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    let Some((base, reference)) = exact_canonical_managed_result(
        &store,
        project_id,
        task_id,
        &attempt.invocation_id,
        &attempt.request_hash,
        None,
    )
    .await?
    else {
        return Ok(None);
    };
    let body_hash = hash_json(&base)?;
    let mut result = base;
    result
        .as_object_mut()
        .context("canonical managed result must be an object")?
        .insert(
            "canonical_authority".to_owned(),
            json!({
                "receipt": reference,
                "body_hash": body_hash,
                "receipt_kind": "managed_host_launch_result",
            }),
        );
    let receipt_hash = hash_json(&result)?;
    result
        .as_object_mut()
        .context("canonical managed result must be an object")?
        .insert("receipt_hash".to_owned(), Value::String(receipt_hash));
    Ok(Some(result))
}

pub(super) fn broker_chain_from_attempt(attempt: &ManagedHostAttemptJournal) -> ManagedBrokerChain {
    ManagedBrokerChain {
        job_id: attempt.broker_job_id.clone(),
        result_id: attempt.broker_result_id.clone(),
        host_session_id: attempt.broker_host_session_id.clone(),
        planned_verifier_ref: attempt.planned_verifier_ref.clone(),
    }
}

pub(super) fn broker_status_from_receipt(result: &Value) -> Result<AgentResultStatus> {
    match result.get("status").and_then(Value::as_str) {
        Some("succeeded") => Ok(AgentResultStatus::Succeeded),
        Some("failed" | "failed_before_dispatch" | "failed_immutable_boundary") => {
            Ok(AgentResultStatus::Failed)
        }
        Some("unknown_outcome") => Ok(AgentResultStatus::UnknownOutcome),
        Some(other) => bail!("unknown managed launch result status: {other}"),
        None => bail!("managed launch result has no status"),
    }
}

pub(super) async fn record_managed_broker_result_from_receipt(
    config_path: &Path,
    root: &Path,
    attempt: &ManagedHostAttemptJournal,
    result: &Value,
) -> Result<()> {
    let summary = result
        .get("reason")
        .and_then(Value::as_str)
        .context("managed launch result has no reason")?;
    let candidate_diff_hash = result
        .get("execution_evidence")
        .and_then(|execution| execution.get("candidate_diff_hash"))
        .and_then(Value::as_str);
    let exit_status = result
        .get("exit_evidence")
        .and_then(|execution| execution.get("code"))
        .and_then(Value::as_i64)
        .map(i32::try_from)
        .transpose()
        .context("managed launch exit status does not fit i32")?;
    record_managed_broker_result(
        config_path,
        &attempt.invocation_id,
        &broker_chain_from_attempt(attempt),
        ManagedBrokerResultRecord {
            status: broker_status_from_receipt(result)?,
            summary,
            candidate_diff_hash,
            evidence_refs: vec![
                root.join("attempt.json").to_string_lossy().into_owned(),
                root.join("result.json").to_string_lossy().into_owned(),
            ],
            exit_status,
        },
    )
    .await
}

pub(super) fn managed_receipt_base(result: &Value) -> Result<Value> {
    let mut base = result.clone();
    let object = base
        .as_object_mut()
        .context("managed result must be a JSON object")?;
    object.remove("canonical_authority");
    object.remove("receipt_hash");
    Ok(base)
}

pub(super) fn validate_managed_result_integrity(
    attempt: &ManagedHostAttemptJournal,
    result: &Value,
    request_hash: &str,
) -> Result<()> {
    if result.get("request_hash").and_then(Value::as_str) != Some(request_hash)
        || result.get("contract_hash").and_then(Value::as_str)
            != Some(attempt.contract_hash.as_str())
        || result.get("attempt_hash").and_then(Value::as_str) != Some(attempt.attempt_hash.as_str())
    {
        bail!("managed launch result hashes do not match the exact attempt/request");
    }
    let expected_receipt_hash = result
        .get("receipt_hash")
        .and_then(Value::as_str)
        .context("managed launch result has no receipt hash")?;
    let mut hash_material = result.clone();
    hash_material
        .as_object_mut()
        .context("managed result must be an object")?
        .remove("receipt_hash");
    if hash_json(&hash_material)? != expected_receipt_hash {
        bail!("managed launch result receipt hash is invalid");
    }
    let execution = result
        .get("execution_evidence")
        .context("managed result lacks execution evidence")?;
    for (reference_field, hash_field) in
        [("stdout_ref", "stdout_hash"), ("stderr_ref", "stderr_hash")]
    {
        if let Some(reference) = execution.get(reference_field).and_then(Value::as_str) {
            let expected = execution
                .get(hash_field)
                .and_then(Value::as_str)
                .with_context(|| format!("managed result lacks {hash_field}"))?;
            if hash_file_content(Path::new(reference))? != expected {
                bail!("managed launch result output artifact was modified after completion");
            }
        }
    }
    Ok(())
}

pub(super) async fn validate_reusable_managed_result(
    config_path: &Path,
    root: &Path,
    request_hash: &str,
) -> Result<Value> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    validate_reusable_managed_result_with_store(&store, root, request_hash).await
}

pub(super) async fn validate_reusable_managed_result_with_store(
    store: &CanonicalStore,
    root: &Path,
    request_hash: &str,
) -> Result<Value> {
    let attempt: ManagedHostAttemptJournal =
        serde_json::from_reader(File::open(root.join("attempt.json"))?)?;
    validate_attempt_journal(&attempt)?;
    let result: Value = serde_json::from_reader(File::open(root.join("result.json"))?)?;
    validate_managed_result_integrity(&attempt, &result, request_hash)?;
    let execution = result
        .get("execution_evidence")
        .context("managed result lacks execution evidence")?;
    for (reference_field, hash_field) in
        [("stdout_ref", "stdout_hash"), ("stderr_ref", "stderr_hash")]
    {
        if let Some(reference) = execution.get(reference_field).and_then(Value::as_str) {
            let expected = execution
                .get(hash_field)
                .and_then(Value::as_str)
                .with_context(|| format!("managed result lacks {hash_field}"))?;
            if hash_file_content(Path::new(reference))? != expected {
                bail!("managed result output artifact was modified after completion");
            }
        }
    }
    let project_id = attempt
        .project_id
        .context("attempt lost project authority")?;
    let task_id = attempt.task_id.context("attempt lost task authority")?;
    let canonical = result
        .get("canonical_authority")
        .context("managed result lacks canonical authority")?;
    let reference: WriteReceiptRef = serde_json::from_value(
        canonical
            .get("receipt")
            .cloned()
            .context("managed result lacks canonical receipt")?,
    )?;
    let body_hash = canonical
        .get("body_hash")
        .and_then(Value::as_str)
        .context("managed result lacks canonical body hash")?;
    let base = managed_receipt_base(&result)?;
    if hash_json(&base)? != body_hash {
        bail!("managed result differs from its canonical body hash");
    }
    if reference.write_id != managed_result_write_id(&attempt.invocation_id) {
        bail!("managed result canonical receipt uses a non-deterministic write ID");
    }
    let (_, exact_reference) = exact_canonical_managed_result(
        store,
        project_id,
        task_id,
        &attempt.invocation_id,
        request_hash,
        Some(&base),
    )
    .await?
    .context("managed result canonical observation is missing")?;
    if exact_reference != reference {
        bail!("managed result canonical receipt identity differs from the exact write");
    }
    Ok(result)
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn load_managed_controller_candidate(
    runtime_root: &Path,
    store: &CanonicalStore,
    invocation_id: &str,
    expected_provider_output_hash: &str,
) -> Result<ManagedControllerCandidate> {
    let Some(digest) = invocation_id.strip_prefix("host-invocation:") else {
        bail!("managed finalization requires a deterministic host invocation id");
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("managed finalization invocation id is malformed");
    }
    let root = runtime_root
        .join("reports")
        .join("host-invocations")
        .join(invocation_id.replace(':', "_"));
    let preliminary: Value = serde_json::from_reader(File::open(root.join("result.json"))?)?;
    let request_hash = preliminary
        .get("request_hash")
        .and_then(Value::as_str)
        .context("managed result lacks request_hash")?;
    let result = validate_reusable_managed_result_with_store(store, &root, request_hash).await?;
    let attempt: ManagedHostAttemptJournal =
        serde_json::from_reader(File::open(root.join("attempt.json"))?)?;
    if attempt.invocation_id != invocation_id {
        bail!("managed attempt belongs to another invocation");
    }
    if crate::mcp_stdio::RegisteredTaskVerifier::from_reference(&attempt.planned_verifier_ref)
        .is_none()
    {
        bail!("managed attempt planned verifier reference is missing, unregistered, or stale");
    }
    let execution = result
        .get("execution_evidence")
        .context("managed result lacks execution_evidence")?;
    let stdout_ref = execution
        .get("stdout_ref")
        .and_then(Value::as_str)
        .context("managed result lacks captured provider output")?;
    let provider_output_hash = execution
        .get("stdout_hash")
        .and_then(Value::as_str)
        .context("managed result lacks provider output hash")?;
    let candidate_diff_hash = execution
        .get("candidate_diff_hash")
        .and_then(Value::as_str)
        .context("managed result lacks candidate diff hash")?;
    if provider_output_hash != expected_provider_output_hash {
        bail!("controller expected provider output hash does not match the managed result");
    }
    let candidate_diff = std::fs::read(stdout_ref)?;
    if candidate_unified_diff_hash(&candidate_diff, &attempt.write_set).as_deref()
        != Some(candidate_diff_hash)
    {
        bail!("managed provider output is not the exact validated in-scope CandidateDiff");
    }
    if !managed_result_is_controller_finalizable(&result, execution) {
        bail!("managed provider result is not eligible for controller finalization");
    }
    let canonical: WriteReceiptRef = serde_json::from_value(
        result
            .pointer("/canonical_authority/receipt")
            .cloned()
            .context("managed result lost canonical receipt")?,
    )?;
    Ok(ManagedControllerCandidate {
        invocation_id: invocation_id.to_owned(),
        idempotency_key: attempt.idempotency_key,
        project_id: attempt
            .project_id
            .context("attempt lost project authority")?,
        task_id: attempt.task_id.context("attempt lost task authority")?,
        work_item_id: attempt
            .work_item_id
            .context("attempt lost work item authority")?,
        agent_session_id: attempt
            .agent_session_id
            .context("attempt lost agent session authority")?,
        role_lease_id: attempt
            .role_lease_id
            .context("attempt lost TaskRoleLease authority")?,
        work_lease_id: attempt
            .work_lease_id
            .context("attempt lost WorkLease authority")?,
        worktree_lease_id: attempt
            .worktree_lease_id
            .context("attempt lost WorktreeLease authority")?,
        worktree_path: PathBuf::from(attempt.cwd_or_worktree),
        allowed_paths: attempt.write_set,
        provider_host_id: attempt.host,
        provider_host_session_id: attempt.broker_host_session_id,
        broker_job_id: attempt.broker_job_id,
        provider_result_id: attempt.broker_result_id,
        provider_output_hash: provider_output_hash.to_owned(),
        candidate_diff_hash: candidate_diff_hash.to_owned(),
        candidate_diff,
        planned_verifier_ref: attempt.planned_verifier_ref,
        managed_result_receipt: canonical,
        completed_at: OffsetDateTime::parse(
            result
                .get("completed_at")
                .and_then(Value::as_str)
                .context("managed result lacks RFC3339 completed_at")?,
            &time::format_description::well_known::Rfc3339,
        )?,
    })
}

pub(super) fn managed_result_is_controller_finalizable(result: &Value, execution: &Value) -> bool {
    result.get("status").and_then(Value::as_str) == Some("succeeded")
        && result.get("outcome_known").and_then(Value::as_bool) == Some(true)
        && result
            .pointer("/exit_evidence/success")
            .and_then(Value::as_bool)
            == Some(true)
        && result.get("candidate_only").and_then(Value::as_bool) == Some(true)
        && result.get("truth_promoted").and_then(Value::as_bool) == Some(false)
        && execution.get("worktree_immutable").and_then(Value::as_bool) == Some(true)
        && execution
            .get("launch_boundary_intact")
            .and_then(Value::as_bool)
            == Some(true)
        && execution
            .get("process_tree_terminated")
            .and_then(Value::as_bool)
            == Some(true)
}

pub(super) fn reconciled_unknown_outcome_base(
    attempt: &ManagedHostAttemptJournal,
    attempt_path: &Path,
    result_path: &Path,
    reason: &str,
) -> Value {
    let broker = broker_chain_from_attempt(attempt);
    json!({
        "schema_version": "eliot-managed-host-launch-result-v1",
        "invocation_id": attempt.invocation_id,
        "idempotency_key": attempt.idempotency_key,
        "request_hash": attempt.request_hash,
        "contract_hash": attempt.contract_hash,
        "attempt_hash": attempt.attempt_hash,
        "authority_hash": attempt.authority_hash,
        "host": attempt.host,
        "status": "unknown_outcome",
        "outcome_known": false,
        "reason": reason,
        "scope": {
            "project_id": attempt.project_id,
            "task_id": attempt.task_id,
            "work_item_id": attempt.work_item_id,
            "agent_session_id": attempt.agent_session_id,
            "role_lease_id": attempt.role_lease_id,
            "work_lease_id": attempt.work_lease_id,
            "worktree_lease_id": attempt.worktree_lease_id,
            "cwd_or_worktree": attempt.cwd_or_worktree,
            "write_set": attempt.write_set,
        },
        "tool_evidence": {
            "tool": attempt.tool,
            "official_cli": true,
            "executable": attempt.launch_boundary.executable_path,
            "executable_hash": attempt.launch_boundary.executable_hash,
            "version": attempt.tool_version,
            "capability_probe_receipt": attempt.launch_boundary.capability_probe_receipt,
            "prompt_hash": attempt.prompt_hash,
        },
        "model_evidence": {
            "selected_model": attempt.model,
            "exact_model_cli_flag": true,
        },
        "exit_evidence": { "code": Value::Null, "success": Value::Null },
        "attempt_ref": attempt_path,
        "result_ref": result_path,
        "execution_evidence": {
            "provider_dispatched": true,
            "stdout_ref": Value::Null,
            "stderr_ref": Value::Null,
            "stdout_hash": Value::Null,
            "stderr_hash": Value::Null,
            "candidate_diff_hash": Value::Null,
            "candidate_diff_ref": Value::Null,
            "worktree_before": attempt.worktree_before,
            "worktree_after": Value::Null,
            "worktree_immutable": Value::Null,
            "launch_boundary": attempt.launch_boundary,
            "launch_boundary_intact": Value::Null,
            "native_process_tree_guard": true,
            "process_tree_terminated": Value::Null,
        },
        "candidate_only": true,
        "truth_promoted": false,
        "disposition": "candidate_unreviewed",
        "cancellation_requested": false,
        "redispatch_allowed": false,
        "reconciliation_required": true,
        "broker_chain": {
            "job_id": broker.job_id,
            "result_id": broker.result_id,
            "job_result_ref": broker.result_id,
            "host_session_id": broker.host_session_id,
            "planned_verifier_ref": broker.planned_verifier_ref,
            "candidate_status": "candidate_only",
            "operation_job_recorded": true,
            "agent_result_recorded": true,
            "controller_disposition_required": true,
            "direct_truth_promotion": false,
        },
        "reconciled_at": OffsetDateTime::now_utc(),
    })
}

pub(super) async fn reconcile_existing_managed_invocation(
    config_path: &Path,
    root: &Path,
    request_hash: &str,
) -> Result<ExistingManagedInvocation> {
    let attempt_path = root.join("attempt.json");
    let result_path = root.join("result.json");
    let attempt_state = read_managed_attempt(&attempt_path)?;
    if result_path.is_file() {
        if !matches!(&attempt_state, ManagedAttemptJournalState::Valid(_)) {
            return Ok(ExistingManagedInvocation::UnknownOutcome);
        }
        let result = validate_reusable_managed_result(config_path, root, request_hash).await?;
        return match result.get("status").and_then(Value::as_str) {
            Some(
                "succeeded" | "failed" | "failed_before_dispatch" | "failed_immutable_boundary",
            ) => Ok(ExistingManagedInvocation::Reuse(result)),
            Some("unknown_outcome") => Ok(ExistingManagedInvocation::UnknownOutcome),
            Some(other) => bail!("unknown managed launch result status: {other}"),
            None => bail!("managed launch result has no status"),
        };
    }
    let attempt = match attempt_state {
        ManagedAttemptJournalState::Missing => {
            if provider_start_marker_path(root).exists() {
                return Ok(ExistingManagedInvocation::UnknownOutcome);
            }
            let lock = invocation_lock_record(root)?;
            if lock_owner_is_active(&lock)? {
                return Ok(ExistingManagedInvocation::InProgress);
            }
            clear_pre_provider_journals(root)?;
            return Ok(ExistingManagedInvocation::New);
        }
        ManagedAttemptJournalState::Malformed => {
            let lock = invocation_lock_record(root)?;
            if lock_owner_is_active(&lock)? {
                return Ok(ExistingManagedInvocation::InProgress);
            }
            if provider_start_marker_path(root).exists() {
                return Ok(ExistingManagedInvocation::UnknownOutcome);
            }
            clear_pre_provider_journals(root)?;
            return Ok(ExistingManagedInvocation::New);
        }
        ManagedAttemptJournalState::Valid(attempt) => attempt,
    };
    let lock = invocation_lock_record(root)?;
    if lock_owner_is_active(&lock)? {
        return Ok(ExistingManagedInvocation::InProgress);
    }
    if attempt.schema_version != MANAGED_ATTEMPT_SCHEMA_V4 {
        return Ok(ExistingManagedInvocation::UnknownOutcome);
    }
    validate_attempt_journal(&attempt)?;
    if attempt.request_hash != request_hash {
        bail!("Antigravity idempotency key was already used for a different request");
    }
    if !provider_may_have_started(root, Some(attempt.as_ref())) {
        clear_pre_provider_journals(root)?;
        return Ok(ExistingManagedInvocation::New);
    }
    if let Some(result) = recover_canonical_managed_receipt(config_path, &attempt).await? {
        record_managed_broker_result_from_receipt(config_path, root, &attempt, &result).await?;
        atomic_write_json(&result_path, &result)?;
        let result = validate_reusable_managed_result(config_path, root, request_hash).await?;
        return match broker_status_from_receipt(&result)? {
            AgentResultStatus::UnknownOutcome => Ok(ExistingManagedInvocation::UnknownOutcome),
            _ => Ok(ExistingManagedInvocation::Reuse(result)),
        };
    }
    let reason = "attempt journal exists without a terminal provider receipt";
    let base = reconciled_unknown_outcome_base(&attempt, &attempt_path, &result_path, reason);
    let result = canonicalize_managed_receipt(
        config_path,
        attempt
            .project_id
            .context("attempt lost project authority")?,
        attempt.task_id.context("attempt lost task authority")?,
        attempt
            .agent_session_id
            .context("attempt lost session authority")?,
        &attempt.invocation_id,
        base,
    )
    .await?;
    record_managed_broker_result_from_receipt(config_path, root, &attempt, &result).await?;
    atomic_write_json(&result_path, &result)?;
    Ok(ExistingManagedInvocation::UnknownOutcome)
}

pub(super) fn unknown_invocation_status(invocation_id: &str, idempotency_key: &str) -> Value {
    json!({
        "schema_version": "eliot-managed-host-invocation-status-v1",
        "invocation_id": invocation_id,
        "idempotency_key": idempotency_key,
        "status": "unknown_outcome",
        "outcome_known": false,
        "provider_call_budget_consumed": true,
        "redispatch_allowed": false,
        "reconciliation_required": true,
        "reason": "durable provider-start evidence exists but the attempt journal cannot be trusted",
    })
}

pub(super) fn not_attempted_invocation_status(invocation_id: &str, idempotency_key: &str) -> Value {
    json!({
        "schema_version": "eliot-managed-host-invocation-status-v1",
        "invocation_id": invocation_id,
        "idempotency_key": idempotency_key,
        "status": "not_attempted",
        "provider_call_budget_consumed": false,
        "redispatch_allowed": true,
    })
}

pub(super) async fn invocation_status(config_path: &Path, idempotency_key: &str) -> Result<Value> {
    let idempotency_key = idempotency_key.trim();
    if idempotency_key.is_empty() {
        bail!("--idempotency-key must not be empty");
    }
    let invocation_id = stable_invocation_id(idempotency_key);
    let root = invocation_root(config_path, &invocation_id);
    let attempt_path = root.join("attempt.json");
    let attempt_state = read_managed_attempt(&attempt_path)?;
    let attempt_was_valid = matches!(&attempt_state, ManagedAttemptJournalState::Valid(_));
    let request_hash = match &attempt_state {
        ManagedAttemptJournalState::Valid(attempt) => attempt.request_hash.as_str(),
        ManagedAttemptJournalState::Missing | ManagedAttemptJournalState::Malformed => "",
    };
    match reconcile_existing_managed_invocation(config_path, &root, request_hash).await? {
        ExistingManagedInvocation::Reuse(receipt) => Ok(receipt),
        ExistingManagedInvocation::UnknownOutcome => {
            let result_path = root.join("result.json");
            if attempt_was_valid && result_path.is_file() {
                match serde_json::from_reader(std::fs::File::open(result_path)?) {
                    Ok(result) => Ok(result),
                    Err(_) => Ok(unknown_invocation_status(&invocation_id, idempotency_key)),
                }
            } else {
                Ok(unknown_invocation_status(&invocation_id, idempotency_key))
            }
        }
        ExistingManagedInvocation::New => Ok(not_attempted_invocation_status(
            &invocation_id,
            idempotency_key,
        )),
        ExistingManagedInvocation::InProgress => Ok(json!({
            "schema_version": "eliot-managed-host-invocation-status-v1",
            "invocation_id": invocation_id,
            "idempotency_key": idempotency_key,
            "status": "in_progress",
            "provider_call_budget_consumed": true,
            "redispatch_allowed": false,
        })),
    }
}

pub(super) fn managed_result_id(invocation_id: &str) -> String {
    format!(
        "agent-result:{}",
        blake3::hash(invocation_id.as_bytes()).to_hex()
    )
}

pub(super) async fn begin_managed_broker_chain(
    config_path: &Path,
    contract: &eliot_types::HostLaunchContract,
    profile: &eliot_types::AgentHostRuntimeProfile,
    authority: &ManagedCanonicalAuthority,
) -> Result<ManagedBrokerChain> {
    let task_id = contract.task_id.context("managed broker task is missing")?;
    let project_id = contract
        .project_id
        .context("managed broker project is missing")?;
    let work_item_id = contract
        .work_item_id
        .context("managed broker work item is missing")?;
    let role_lease_id = contract
        .role_lease_id
        .clone()
        .context("managed broker role lease is missing")?;
    let planned_verifier_ref = contract
        .planned_verifier_ref
        .as_deref()
        .context("managed Antigravity broker chain requires a planned verifier reference")?;
    crate::mcp_stdio::RegisteredTaskVerifier::from_reference(planned_verifier_ref)
        .context("managed Antigravity planned verifier reference is unregistered or stale")?;
    let request = AgentInvocationRequest {
        invocation_id: contract.invocation_id.clone(),
        project_id,
        task_id,
        work_item_id,
        requested_capabilities: vec!["lease_scoped_candidate_implementation".to_owned()],
        role_lease_id,
        work_lease_id: contract.work_lease_id,
        packet_refs: vec![
            authority.task_receipt.receipt_id.to_string(),
            authority.session_receipt.receipt_id.to_string(),
            authority.role_receipt.receipt_id.to_string(),
            authority.host_binding_receipt.receipt_id.to_string(),
            authority.work_receipt.receipt_id.to_string(),
            authority.worktree_receipt.receipt_id.to_string(),
        ],
        expected_result_kind: "candidate_unified_diff".to_owned(),
        verifier_ref: planned_verifier_ref.to_owned(),
        idempotency_key: contract.idempotency_key.clone(),
    };
    let mut state = delegation_runtime::load_state(&runtime_root(config_path))?;
    let job = HostBrokerService.enqueue(
        &mut state,
        &request,
        profile,
        work_lease_is_active(&authority.work_lease),
    )?;
    write_canonical_managed_invocation_request(config_path, &state, &request).await?;
    write_canonical_managed_job(config_path, &state, &job).await?;
    delegation_runtime::save_host_broker_state(&runtime_root(config_path), &state)?;
    Ok(ManagedBrokerChain {
        job_id: job.job_id,
        result_id: managed_result_id(&contract.invocation_id),
        host_session_id: authority
            .host_binding
            .host_identity
            .client_instance_id
            .clone(),
        planned_verifier_ref: planned_verifier_ref.to_owned(),
    })
}

pub(super) async fn mark_managed_broker_running(
    config_path: &Path,
    chain: &ManagedBrokerChain,
) -> Result<()> {
    let mut state = delegation_runtime::load_state(&runtime_root(config_path))?;
    let job = state
        .operation_jobs
        .iter_mut()
        .find(|candidate| candidate.job_id == chain.job_id)
        .context("managed broker job disappeared before provider dispatch")?;
    if job.state == eliot_types::OperationJobState::Queued {
        HostBrokerService.transition(
            job,
            eliot_types::OperationJobState::Running,
            Some(chain.host_session_id.clone()),
        )?;
    } else if job.state != eliot_types::OperationJobState::Running {
        bail!("managed broker job is not dispatchable");
    }
    let job = state
        .operation_jobs
        .iter()
        .find(|candidate| candidate.job_id == chain.job_id)
        .cloned()
        .context("managed broker job disappeared after running transition")?;
    write_canonical_managed_job(config_path, &state, &job).await?;
    delegation_runtime::save_host_broker_state(&runtime_root(config_path), &state)
}

pub(super) async fn record_managed_broker_result(
    config_path: &Path,
    invocation_id: &str,
    chain: &ManagedBrokerChain,
    record: ManagedBrokerResultRecord<'_>,
) -> Result<()> {
    let mut state = delegation_runtime::load_state(&runtime_root(config_path))?;
    if let Some(job) = state
        .operation_jobs
        .iter_mut()
        .find(|candidate| candidate.job_id == chain.job_id)
        && job.state == eliot_types::OperationJobState::Queued
    {
        HostBrokerService.transition(
            job,
            eliot_types::OperationJobState::Running,
            Some(chain.host_session_id.clone()),
        )?;
    }
    let artifact_refs = record
        .candidate_diff_hash
        .map(|hash| vec![format!("candidate-unified-diff:{hash}")])
        .unwrap_or_default();
    let mut result = HostBrokerService.record_result(
        &mut state,
        AgentResultEnvelope {
            result_id: chain.result_id.clone(),
            invocation_id: invocation_id.to_owned(),
            host_id: AgentHostId::Antigravity,
            host_session_id: Some(chain.host_session_id.clone()),
            status: record.status,
            summary: record.summary.to_owned(),
            artifact_refs,
            evidence_refs: record.evidence_refs,
            verifier_refs: Vec::new(),
            candidate_only: true,
            exit_status: record.exit_status,
            token_or_cost_telemetry: None,
            unknown_outcome_evidence_refs: if record.status == AgentResultStatus::UnknownOutcome {
                vec!["managed-provider-outcome-reconciliation-required".to_owned()]
            } else {
                Vec::new()
            },
            supersedes_result_id: None,
            provider_output_hash: None,
            canonical_receipt: None,
        },
    )?;
    let (project_id, task_id, agent_session_id) =
        managed_broker_canonical_scope(&state, invocation_id)?;
    if result.canonical_receipt.is_none() {
        let (receipt, _) = write_canonical_host_observation(
            config_path,
            project_id,
            task_id,
            agent_session_id,
            &format!("managed-provider-result:{}", result.result_id),
            "agent_result",
            &serde_json::to_value(&result)?,
        )
        .await?;
        result.canonical_receipt = Some(receipt);
        let stored = state
            .agent_results
            .iter_mut()
            .find(|candidate| candidate.result_id == result.result_id)
            .context("managed provider result disappeared before receipt binding")?;
        *stored = result;
    }
    let job = state
        .operation_jobs
        .iter()
        .find(|candidate| candidate.job_id == chain.job_id)
        .cloned()
        .context("managed broker job disappeared after result")?;
    write_canonical_managed_job(config_path, &state, &job).await?;
    delegation_runtime::save_host_broker_state(&runtime_root(config_path), &state)
}

pub(super) fn managed_broker_canonical_scope(
    state: &DelegationState,
    invocation_id: &str,
) -> Result<(ProjectId, TaskId, AgentSessionId)> {
    let request = state
        .agent_invocations
        .iter()
        .find(|request| request.invocation_id == invocation_id)
        .context("managed broker request disappeared")?;
    let role = state
        .task_role_leases
        .iter()
        .find(|role| role.role_lease_id == request.role_lease_id)
        .context("managed broker request lost its task role lease")?;
    Ok((request.project_id, request.task_id, role.agent_session_id))
}

pub(super) async fn write_canonical_managed_job(
    config_path: &Path,
    state: &DelegationState,
    job: &eliot_types::OperationJob,
) -> Result<WriteReceiptRef> {
    let (project_id, task_id, agent_session_id) =
        managed_broker_canonical_scope(state, &job.invocation_id)?;
    let state_key = serde_json::to_string(&job.state)?;
    let (receipt, _) = write_canonical_host_observation(
        config_path,
        project_id,
        task_id,
        agent_session_id,
        &format!(
            "managed-operation-job:{}:{state_key}:{}",
            job.job_id,
            job.result_ref.as_deref().unwrap_or("none")
        ),
        "operation_job",
        &serde_json::to_value(job)?,
    )
    .await?;
    Ok(receipt)
}

pub(super) async fn write_canonical_managed_invocation_request(
    config_path: &Path,
    state: &DelegationState,
    request: &AgentInvocationRequest,
) -> Result<WriteReceiptRef> {
    let (project_id, task_id, agent_session_id) =
        managed_broker_canonical_scope(state, &request.invocation_id)?;
    let (receipt, _) = write_canonical_host_observation(
        config_path,
        project_id,
        task_id,
        agent_session_id,
        &format!("managed-agent-invocation:{}", request.invocation_id),
        "agent_invocation_request",
        &serde_json::to_value(request)?,
    )
    .await?;
    Ok(receipt)
}

pub(super) async fn wait_managed_root(child: &eliot_windows_ipc::SuspendedJobChild) -> Result<i32> {
    loop {
        if let Some(code) = child.try_wait()? {
            return Ok(code);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub(super) fn spawn_managed_pipe_reader(
    file: File,
) -> tokio::task::JoinHandle<std::io::Result<Vec<u8>>> {
    tokio::task::spawn_blocking(move || {
        let mut file = file;
        let mut retained = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            let count = file.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            let remaining = MAX_SECRET_BOUNDARY_BYTES
                .saturating_add(1)
                .saturating_sub(retained.len());
            retained.extend_from_slice(&chunk[..count.min(remaining)]);
        }
        Ok(retained)
    })
}

pub(super) async fn finish_managed_pipe_reads(
    stdout: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
    stderr: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
    timeout: Duration,
) -> Result<(Vec<u8>, Vec<u8>)> {
    tokio::time::timeout(timeout, async { Ok((stdout.await??, stderr.await??)) })
        .await
        .context("managed provider pipe drain exceeded its bounded deadline")?
}

pub(super) fn remaining_to_deadline(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn run_managed_antigravity(
    config_path: &Path,
    command: Command,
    contract: &eliot_types::HostLaunchContract,
    profile: &eliot_types::AgentHostRuntimeProfile,
    program: &str,
    args: &[String],
    invocation_root: &Path,
    request_hash: &str,
    prompt_hash: &str,
    daemon_readiness: &Value,
    authority: &ManagedCanonicalAuthority,
    launch_boundary: ManagedLaunchBoundaryAttestation,
    _invocation_lock: ManagedInvocationLock,
) -> Result<()> {
    std::fs::create_dir_all(invocation_root)?;
    let attempt_path = invocation_root.join("attempt.json");
    let stdout_path = invocation_root.join("stdout.txt");
    let stderr_path = invocation_root.join("stderr.log");
    let worktree_before = managed_worktree_snapshot(Path::new(&contract.cwd_or_worktree))?;
    if worktree_before.head != authority.worktree_lease.base_commit
        || worktree_before.status_hash != hash_bytes(&[])
        || worktree_before.diff_hash != hash_bytes(&[])
    {
        bail!("managed Antigravity requires the clean canonical WorktreeLease baseline");
    }
    let broker = begin_managed_broker_chain(config_path, contract, profile, authority).await?;
    let mut attempt = ManagedHostAttemptJournal {
        schema_version: MANAGED_ATTEMPT_SCHEMA_V4.to_owned(),
        invocation_id: contract.invocation_id.clone(),
        idempotency_key: contract.idempotency_key.clone(),
        request_hash: request_hash.to_owned(),
        contract_hash: contract.contract_hash.clone(),
        host: AgentHostId::Antigravity,
        project_id: contract.project_id,
        task_id: contract.task_id,
        work_item_id: contract.work_item_id,
        agent_session_id: contract.agent_session_id,
        role_lease_id: contract.role_lease_id.clone(),
        work_lease_id: contract.work_lease_id,
        worktree_lease_id: contract.worktree_lease_id,
        cwd_or_worktree: contract.cwd_or_worktree.clone(),
        write_set: contract.allowed_paths.clone(),
        tool: "agy".to_owned(),
        tool_version: profile.version.clone(),
        model: contract.model_route_if_selected.clone(),
        prompt_hash: prompt_hash.to_owned(),
        owner_pid: std::process::id(),
        authority_hash: authority.authority_hash.clone(),
        worktree_before: worktree_before.clone(),
        launch_boundary: launch_boundary.clone(),
        broker_job_id: broker.job_id.clone(),
        broker_result_id: broker.result_id.clone(),
        broker_host_session_id: broker.host_session_id.clone(),
        planned_verifier_ref: broker.planned_verifier_ref.clone(),
        attempt_hash: String::new(),
        attempt_recorded_before_provider_call: true,
        provider_call_budget_consumed: true,
        redispatch_allowed: false,
        started_at: OffsetDateTime::now_utc(),
    };
    attempt.attempt_hash = managed_attempt_hash(&attempt)?;
    if attempt_path.exists() {
        bail!("attempt-before-call CAS already exists");
    }
    atomic_write_json(&attempt_path, &attempt)?;
    mark_managed_broker_running(config_path, &broker).await?;
    write_provider_start_marker(invocation_root, &attempt.attempt_hash)?;

    let mut child = match eliot_windows_ipc::SuspendedJobChild::spawn(command.as_std()) {
        Ok(child) => child,
        Err(error) => {
            let reason = format!("failed to start official agy CLI: {error}");
            let launch_boundary_intact = managed_launch_boundary_is_current(&launch_boundary);
            let evidence = ManagedExecutionEvidence {
                stdout_hash: None,
                stderr_hash: None,
                candidate_diff_hash: None,
                secret_boundary_rule: None,
                worktree_before,
                worktree_after: managed_worktree_snapshot(Path::new(&contract.cwd_or_worktree))?,
                launch_boundary,
                launch_boundary_intact,
                process_tree_terminated: false,
                broker,
            };
            let receipt = finalize_managed_terminal(
                config_path,
                contract,
                ManagedTerminalRecord {
                    profile,
                    program,
                    args,
                    invocation_root,
                    request_hash,
                    prompt_hash,
                    daemon_readiness,
                    status: "failed_before_dispatch",
                    exit_code: None,
                    exit_success: Some(false),
                    outcome_known: true,
                    cancellation_requested: false,
                    reason: &reason,
                    evidence: &evidence,
                    broker_status: AgentResultStatus::Failed,
                },
            )
            .await?;
            write_json(&receipt)?;
            bail!("failed to start managed Antigravity launch");
        }
    };
    let stdout_task = spawn_managed_pipe_reader(
        child
            .take_stdout()
            .context("managed stdout pipe is missing")?,
    );
    let stderr_task = spawn_managed_pipe_reader(
        child
            .take_stderr()
            .context("managed stderr pipe is missing")?,
    );
    let wall_clock = Duration::from_secs(contract.wall_clock_budget_seconds);
    let deadline = Instant::now()
        .checked_add(wall_clock)
        .context("managed launch deadline overflowed")?;
    let root_wait =
        tokio::time::timeout(remaining_to_deadline(deadline), wait_managed_root(&child)).await;
    let root_exit_code = root_wait
        .as_ref()
        .ok()
        .and_then(|result| result.as_ref().ok())
        .copied();
    let root_wait_error = match &root_wait {
        Ok(Err(error)) => Some(format!("provider wait failed: {error}")),
        Err(_) => Some(
            "wall-clock timeout elapsed; the native Job Object terminated the provider process tree"
                .to_owned(),
        ),
        Ok(Ok(_)) => None,
    };
    let terminate_error = child.terminate(1).err();
    let process_wait_error = match child.wait_timeout(remaining_to_deadline(deadline)) {
        Ok(Some(_)) => None,
        Ok(None) => Some("provider process did not signal before the absolute deadline".to_owned()),
        Err(error) => Some(format!("provider termination wait failed: {error}")),
    };
    let drained =
        finish_managed_pipe_reads(stdout_task, stderr_task, remaining_to_deadline(deadline)).await;
    let (mut stdout_bytes, mut stderr_bytes, drain_error) = match drained {
        Ok((stdout, stderr)) => (Some(stdout), Some(stderr), None),
        Err(error) => (None, None, Some(error.to_string())),
    };
    let secret_boundary_rule = stdout_bytes
        .as_deref()
        .and_then(|bytes| inspect_secret_bytes(bytes).err())
        .or_else(|| {
            stderr_bytes
                .as_deref()
                .and_then(|bytes| inspect_secret_bytes(bytes).err())
        })
        .map(|violation| violation.rule);
    if let Some(rule) = secret_boundary_rule {
        if let Some(bytes) = stdout_bytes.as_mut() {
            bytes.fill(0);
        }
        if let Some(bytes) = stderr_bytes.as_mut() {
            bytes.fill(0);
        }
        stdout_bytes = None;
        stderr_bytes = None;
        atomic_write_json(
            &invocation_root.join("secret-boundary-rejection.json"),
            &json!({
                "schema_version": "eliot-secret-boundary-rejection-v1",
                "rule": rule,
                "raw_persisted": false,
                "content_digest_persisted": false,
            }),
        )?;
    }
    let outcome_known = root_wait_error.is_none()
        && terminate_error.is_none()
        && process_wait_error.is_none()
        && drain_error.is_none();
    let process_tree_terminated = terminate_error.is_none() && process_wait_error.is_none();
    let terminate_failure = terminate_error
        .as_ref()
        .map(|error| format!("Job termination failed: {error}"));
    let wait_reason = root_wait_error
        .or(terminate_failure)
        .or(process_wait_error)
        .or(drain_error);
    let cancellation_requested = !outcome_known;
    if let Some(bytes) = &stdout_bytes {
        std::fs::write(&stdout_path, bytes)?;
    }
    if let Some(bytes) = &stderr_bytes {
        std::fs::write(&stderr_path, bytes)?;
    }
    let worktree_after = managed_worktree_snapshot(Path::new(&contract.cwd_or_worktree))?;
    let launch_boundary_intact = managed_launch_boundary_is_current(&launch_boundary);
    let immutable = worktree_before == worktree_after && launch_boundary_intact;
    let exit_success = root_exit_code == Some(0);
    let candidate_diff_hash =
        (outcome_known && immutable && exit_success && secret_boundary_rule.is_none())
            .then(|| {
                stdout_bytes
                    .as_deref()
                    .and_then(|bytes| candidate_unified_diff_hash(bytes, &contract.allowed_paths))
            })
            .flatten();
    let evidence = ManagedExecutionEvidence {
        stdout_hash: stdout_bytes.as_deref().map(hash_bytes),
        stderr_hash: stderr_bytes.as_deref().map(hash_bytes),
        candidate_diff_hash: candidate_diff_hash.clone(),
        secret_boundary_rule,
        worktree_before,
        worktree_after,
        launch_boundary,
        launch_boundary_intact,
        process_tree_terminated,
        broker,
    };
    let (receipt_status, broker_status, reason) = if let Some(rule) = secret_boundary_rule {
        (
            "failed_secret_boundary",
            AgentResultStatus::Failed,
            format!("provider output rejected before persistence or hashing: {rule}"),
        )
    } else if !outcome_known {
        (
            "unknown_outcome",
            AgentResultStatus::UnknownOutcome,
            wait_reason.unwrap_or_else(|| "provider outcome is unknown".to_owned()),
        )
    } else if !immutable {
        (
            "failed_immutable_boundary",
            AgentResultStatus::Failed,
            "provider changed the leased worktree or managed launch boundary; candidate rejected"
                .to_owned(),
        )
    } else if exit_success && candidate_diff_hash.is_some() {
        (
            "succeeded",
            AgentResultStatus::Succeeded,
            "official agy plan exited successfully; immutable candidate diff remains controller-gated".to_owned(),
        )
    } else if exit_success {
        (
            "failed",
            AgentResultStatus::Failed,
            "official agy plan output was not an exact candidate unified diff".to_owned(),
        )
    } else {
        (
            "failed",
            AgentResultStatus::Failed,
            "official agy CLI returned a non-zero exit status".to_owned(),
        )
    };
    let receipt = finalize_managed_terminal(
        config_path,
        contract,
        ManagedTerminalRecord {
            profile,
            program,
            args,
            invocation_root,
            request_hash,
            prompt_hash,
            daemon_readiness,
            status: receipt_status,
            exit_code: root_exit_code,
            exit_success: outcome_known.then_some(exit_success),
            outcome_known,
            cancellation_requested,
            reason: &reason,
            evidence: &evidence,
            broker_status,
        },
    )
    .await?;
    write_json(&receipt)?;
    if receipt_status != "succeeded" {
        bail!("managed Antigravity launch finished as {receipt_status}: {reason}");
    }
    Ok(())
}

pub(super) async fn finalize_managed_terminal(
    config_path: &Path,
    contract: &eliot_types::HostLaunchContract,
    terminal: ManagedTerminalRecord<'_>,
) -> Result<Value> {
    let result_path = terminal.invocation_root.join("result.json");
    let attempt_path = terminal.invocation_root.join("attempt.json");
    let base = managed_result_receipt(contract, &terminal)?;
    let result = canonicalize_managed_receipt(
        config_path,
        contract.project_id.context("managed result lost project")?,
        contract.task_id.context("managed result lost task")?,
        contract
            .agent_session_id
            .context("managed result lost agent session")?,
        &contract.invocation_id,
        base,
    )
    .await?;
    record_managed_broker_result(
        config_path,
        &contract.invocation_id,
        &terminal.evidence.broker,
        ManagedBrokerResultRecord {
            status: terminal.broker_status,
            summary: terminal.reason,
            candidate_diff_hash: terminal.evidence.candidate_diff_hash.as_deref(),
            evidence_refs: vec![
                attempt_path.to_string_lossy().into_owned(),
                result_path.to_string_lossy().into_owned(),
            ],
            exit_status: terminal.exit_code,
        },
    )
    .await?;
    atomic_write_json(&result_path, &result)?;
    validate_reusable_managed_result(config_path, terminal.invocation_root, terminal.request_hash)
        .await
}

pub(super) fn managed_result_receipt(
    contract: &eliot_types::HostLaunchContract,
    terminal: &ManagedTerminalRecord<'_>,
) -> Result<Value> {
    let result_ref = terminal.invocation_root.join("result.json");
    let stdout_ref = terminal.invocation_root.join("stdout.txt");
    let stderr_ref = terminal.invocation_root.join("stderr.log");
    let attempt: ManagedHostAttemptJournal =
        serde_json::from_reader(File::open(terminal.invocation_root.join("attempt.json"))?)?;
    validate_attempt_journal(&attempt)?;
    let evidence = terminal.evidence;
    let provider_dispatched = terminal.status != "failed_before_dispatch";
    let output_captured = evidence.stdout_hash.is_some() && evidence.stderr_hash.is_some();
    let scope = json!({
        "project_id": contract.project_id,
        "task_id": contract.task_id,
        "work_item_id": contract.work_item_id,
        "agent_session_id": contract.agent_session_id,
        "role_lease_id": contract.role_lease_id,
        "work_lease_id": contract.work_lease_id,
        "worktree_lease_id": contract.worktree_lease_id,
        "cwd_or_worktree": contract.cwd_or_worktree,
        "baseline_commit": contract.baseline_commit,
        "write_set": contract.allowed_paths,
    });
    let execution_evidence = json!({
        "provider_dispatched": provider_dispatched,
        "stdout_ref": output_captured.then_some(stdout_ref),
        "stderr_ref": output_captured.then_some(stderr_ref),
        "stdout_hash": evidence.stdout_hash,
        "stderr_hash": evidence.stderr_hash,
        "candidate_diff_hash": evidence.candidate_diff_hash,
        "secret_boundary_rule": evidence.secret_boundary_rule,
        "candidate_diff_ref": evidence.candidate_diff_hash.as_ref().map(|hash| format!("candidate-unified-diff:{hash}")),
        "worktree_before": evidence.worktree_before,
        "worktree_after": evidence.worktree_after,
        "worktree_immutable": evidence.worktree_before == evidence.worktree_after,
        "launch_boundary": evidence.launch_boundary,
        "launch_boundary_intact": evidence.launch_boundary_intact,
        "native_process_tree_guard": true,
        "process_tree_terminated": evidence.process_tree_terminated,
    });
    let broker_chain = json!({
        "job_id": evidence.broker.job_id,
        "result_id": evidence.broker.result_id,
        "job_result_ref": evidence.broker.result_id,
        "host_session_id": evidence.broker.host_session_id,
        "planned_verifier_ref": evidence.broker.planned_verifier_ref,
        "candidate_status": "candidate_only",
        "operation_job_recorded": true,
        "agent_result_recorded": true,
        "controller_disposition_required": true,
        "direct_truth_promotion": false,
    });
    Ok(json!({
        "schema_version": "eliot-managed-host-launch-result-v1",
        "invocation_id": contract.invocation_id,
        "idempotency_key": contract.idempotency_key,
        "request_hash": terminal.request_hash,
        "contract_hash": contract.contract_hash,
        "attempt_hash": attempt.attempt_hash,
        "authority_hash": attempt.authority_hash,
        "host": AgentHostId::Antigravity,
        "status": terminal.status,
        "outcome_known": terminal.outcome_known,
        "reason": terminal.reason,
        "scope": scope,
        "tool_evidence": {
            "tool": "agy",
            "official_cli": true,
            "executable": terminal.program,
            "executable_hash": terminal.profile.executable_hash,
            "version": terminal.profile.version,
            "capability_probe_receipt": terminal.profile.capability_probe_receipt,
            "argv_without_prompt": &terminal.args[..terminal.args.len().saturating_sub(1)],
            "prompt_hash": terminal.prompt_hash,
        },
        "model_evidence": {
            "selected_model": contract.model_route_if_selected,
            "exact_model_cli_flag": true,
        },
        "exit_evidence": {
            "code": terminal.exit_code,
            "success": terminal.exit_success,
        },
        "attempt_ref": terminal.invocation_root.join("attempt.json"),
        "result_ref": &result_ref,
        "execution_evidence": execution_evidence,
        "governor_daemon": terminal.daemon_readiness,
        "candidate_only": true,
        "truth_promoted": false,
        "disposition": "candidate_unreviewed",
        "cancellation_requested": terminal.cancellation_requested,
        "redispatch_allowed": false,
        "reconciliation_required": !terminal.outcome_known,
        "broker_chain": broker_chain,
        "completed_at": OffsetDateTime::now_utc(),
    }))
}
