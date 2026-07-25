//! The task contract: acting under it, recording against it, and finishing it.
//!
//! Completing a task is not one write. It derives the agent result and the
//! completion memory from the same write id so a retry lands on the identical
//! records, submits them, and only then transitions the contract -- and every
//! step is fenced on the revision the caller expected. That fence and those
//! derivations are the completion semantics, so they stay next to the dispatch
//! that depends on them.

use super::*;

pub(super) async fn dispatch_task_action_request(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: TaskActionToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse write id")?;
    let mut task = require_task(state, project_id, task_id).await?;
    ensure_expected_revision_or_replay(state, &task, input.expected_revision, write_id).await?;

    let mut missing = Vec::new();
    if input.packet_id.trim().is_empty() {
        missing.push("packet_id");
    }
    if input.packet_revision_fence == 0 {
        missing.push("packet_revision_fence");
    }
    if input.task_contract_ref.trim().is_empty() {
        missing.push("task_contract_ref");
    }
    if input.current_truth_refs.is_empty() {
        missing.push("current_truth_refs");
    }
    if input.provenance_handles.is_empty() {
        missing.push("provenance_handles");
    }
    if !input.negative_memory_checked {
        missing.push("negative_memory_checked");
    }
    if input.negative_memory_check_ref.trim().is_empty() {
        missing.push("negative_memory_check_ref");
    }
    if input.planned_action.trim().is_empty() {
        missing.push("planned_action");
    }
    if input.planned_verifier_ref.trim().is_empty() {
        missing.push("planned_verifier_ref");
    }
    if !missing.is_empty() {
        return Ok(json!({
            "status": "denied_requires_probe",
            "decision": "deny",
            "missing": missing,
            "write_receipt": Value::Null
        }));
    }

    let (provenance, verifier) =
        match resolve_action_provenance(state, project_id, &task, write_id, &input).await {
            Ok(resolved) => resolved,
            Err(error) => {
                return Ok(json!({
                    "status": "denied_invalid_provenance",
                    "decision": "deny",
                    "reason": error.to_string(),
                    "write_receipt": Value::Null
                }));
            }
        };
    let proof_hash = canonical_struct_hash(&json!({
        "planned_action": input.planned_action,
        "provenance_set_hash": provenance.hash
    }))?;
    let lease_id = ActionLeaseId::from_uuid(write_id.as_uuid());
    task.status = TaskContractStatus::Active;
    task.action_lease_id = Some(lease_id);
    task.understanding_proof_hash = Some(proof_hash.clone());
    task.action_provenance = Some(provenance.clone());
    let contract = task_input(&task, Some(MemoryRevision::new(input.expected_revision)));
    let (receipt, task) = submit_task_transition(
        state,
        context,
        project_id,
        write_id,
        contract,
        "daemon-cognitive-gate",
        TaintClass::LocalTool,
        TaskTransitionEvidence::default(),
    )
    .await?;
    Ok(json!({
        "status": "allowed_bounded",
        "decision": "allow",
        "action_lease": {
            "lease_id": lease_id,
            "task_id": task_id,
            "at_revision": input.expected_revision,
            "scope": provenance.source_scope,
            "planned_action": input.planned_action,
            "planned_verifier_ref": provenance.planned_verifier_ref,
            "verifier_config_hash": verifier.config_hash(),
            "understanding_proof_hash": proof_hash,
            "provenance_set_hash": provenance.hash
        },
        "task_contract": task,
        "write_receipt": receipt
    }))
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_task_observation_record(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: TaskObservationToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse write id")?;
    let lease_id = ActionLeaseId::from_str(&input.action_lease_id).context("parse lease id")?;
    let mut task = require_task(state, project_id, task_id).await?;
    ensure_expected_revision_or_replay(state, &task, input.expected_revision, write_id).await?;
    if task.action_lease_id != Some(lease_id) {
        anyhow::bail!("observation requires the active task ActionLease");
    }
    if task.write_id != WriteId::from_uuid(lease_id.as_uuid()) {
        anyhow::bail!("ActionLease was invalidated by a later task transition");
    }
    let provenance = task
        .action_provenance
        .clone()
        .context("observation requires resolved canonical action provenance")?;
    if input.provenance_set_hash != provenance.hash {
        anyhow::bail!("observation provenance hash does not match the active ActionLease");
    }
    let expected_scope = format!("eliot/task/{task_id}/acceptance/{}", input.item_id);
    if input.scope != expected_scope || input.provenance_handles != [task.write_id.to_string()] {
        anyhow::bail!("observation scope or action receipt reference is not canonical");
    }
    let action_receipt = state
        .store
        .write_receipt_by_id(&task.write_id)
        .await?
        .context("active ActionLease WriteReceipt does not resolve")?;
    if action_receipt.project_id != project_id || action_receipt.task_id != Some(task_id) {
        anyhow::bail!("active ActionLease WriteReceipt scope mismatch");
    }
    let changed_paths = input.changed_paths.clone();
    let failing_verifiers = input.failing_verifiers.clone();
    let diagnostic_before = input.diagnostic_before.clone();
    let diagnostic_after = input.diagnostic_after.clone();
    let observation_id = write_id.to_string();
    let item = task
        .acceptance_items
        .iter_mut()
        .find(|item| item.item_id == input.item_id)
        .context("observation acceptance item not found")?;
    if item.required_evidence != TaskAcceptanceEvidenceKind::Observation {
        anyhow::bail!("acceptance item requires verification evidence");
    }
    item.satisfied = input.status == "passed";
    item.observation_id = Some(observation_id.clone());
    if !task.observation_ids.contains(&observation_id) {
        task.observation_ids.push(observation_id.clone());
    }
    let observation = ToolObservationInput {
        observation_id: observation_id.clone(),
        tool_name: input.tool_name,
        observation: input.observation,
        payload: json!({
            "status": input.status,
            "scope": input.scope,
            "action_receipt_ref": action_receipt.receipt_id,
            "action_lease_id": lease_id,
            "provenance_set_hash": provenance.hash,
            "planned_verifier_ref": provenance.planned_verifier_ref,
            "task_revision": input.expected_revision,
            "changed_paths": &changed_paths,
            "failing_verifiers": &failing_verifiers,
            "diagnostic_before": &diagnostic_before,
            "diagnostic_after": &diagnostic_after,
            "candidate_only": true
        }),
    };
    let contract = task_input(&task, Some(MemoryRevision::new(input.expected_revision)));
    let (receipt, task) = submit_task_transition(
        state,
        context,
        project_id,
        write_id,
        contract,
        "daemon-tool-observer",
        TaintClass::LocalTool,
        TaskTransitionEvidence {
            observation: Some(observation),
            verification: None,
        },
    )
    .await?;
    let observation_ref = format!("observation:{observation_id}");
    let prediction_resolution = resolve_observation_predictions(
        state,
        project_id,
        task_id,
        &diagnostic_before,
        &diagnostic_after,
        &changed_paths,
        &failing_verifiers,
        &observation_ref,
    )
    .await;
    Ok(json!({
        "status": "observed_candidate",
        "observation_id": observation_id,
        "task_contract": task,
        "write_receipt": receipt,
        "ul_prediction_resolution": prediction_resolution
    }))
}

#[allow(clippy::too_many_arguments)]
async fn resolve_observation_predictions(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    diagnostic_before: &[String],
    diagnostic_after: &[String],
    changed_paths: &[String],
    failing_verifiers: &[String],
    observation_ref: &str,
) -> Value {
    let event_time = time::OffsetDateTime::now_utc();
    let diagnostic = if diagnostic_before.is_empty() && diagnostic_after.is_empty() {
        json!({ "status": "not_observed" })
    } else {
        prediction_resolution_json(
            state
                .ul
                .prediction
                .resolve_diagnostic_delta(
                    project_id,
                    task_id,
                    diagnostic_before,
                    diagnostic_after,
                    observation_ref,
                    event_time,
                )
                .await,
        )
    };
    let blast = if changed_paths.is_empty() && failing_verifiers.is_empty() {
        json!({ "status": "not_observed" })
    } else {
        prediction_resolution_json(
            state
                .ul
                .prediction
                .resolve_blast(
                    project_id,
                    task_id,
                    changed_paths,
                    failing_verifiers,
                    observation_ref,
                    event_time,
                )
                .await,
        )
    };
    json!({
        "diagnostic_delta": diagnostic,
        "blast_radius": blast
    })
}

fn prediction_resolution_json(
    result: std::result::Result<Vec<eliot_types::PredictionRecord>, eliot_engine::EngineError>,
) -> Value {
    match result {
        Ok(records) => json!({
            "status": "resolved",
            "count": records.len(),
            "prediction_refs": records
                .iter()
                .map(|record| format!("prediction:{}", record.prediction_id))
                .collect::<Vec<_>>(),
        }),
        Err(error) => json!({
            "status": "measurement_error",
            "message": error.to_string(),
        }),
    }
}

pub(super) const MAX_COMPLETION_DECISION_BYTES: usize = 512;

pub(super) fn deterministic_completion_uuid(
    completion_write_id: WriteId,
    domain: &str,
) -> uuid::Uuid {
    let digest = blake3::hash(format!("{completion_write_id}:{domain}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

pub(super) fn completion_agent_result_write_id(completion_write_id: WriteId) -> WriteId {
    WriteId::from_uuid(deterministic_completion_uuid(
        completion_write_id,
        "agent-result",
    ))
}

pub(super) fn completion_memory_outcome(memory: Option<&CompletionMemoryRequest>) -> &'static str {
    match memory {
        Some(CompletionMemoryRequest::SaveDecision { .. }) => "saved_decision",
        Some(CompletionMemoryRequest::NothingToSave) => "nothing_to_save",
        None => "not_requested",
    }
}

pub(super) fn derive_completion_agent_result_command(
    request_context: AuthenticatedRequestContext,
    task: &TaskContract,
    completion_write_id: WriteId,
    verification_receipt_ids: Vec<ReceiptId>,
    requested_memory: Option<&CompletionMemoryRequest>,
) -> Result<AgentResultRecordCommand> {
    let provenance = task
        .action_provenance
        .as_ref()
        .context("completion memory requires canonical action provenance")?;
    let action_lease_id = task
        .action_lease_id
        .context("completion memory requires the accepted ActionLease")?;
    let base_commit = provenance
        .source_scope
        .baseline_commit
        .clone()
        .context("completion memory requires the leased base commit")?;
    let branch = provenance
        .source_scope
        .branch
        .clone()
        .context("completion memory requires the leased branch")?;
    let accepted_write_set = provenance.source_scope.artifact_paths.clone();
    let first_scope = task
        .verification_scopes
        .first()
        .context("completion memory requires canonical verifier scope")?;
    if task.verification_ids.len() != verification_receipt_ids.len()
        || task.verification_ids.len() != task.verification_scopes.len()
        || task.verification_ids.iter().any(|verification_id| {
            !task
                .verification_scopes
                .iter()
                .any(|scope| scope.verification_id == *verification_id)
        })
        || task.verification_scopes.iter().any(|scope| {
            scope.branch != branch
                || scope.commit != first_scope.commit
                || scope.project_id != task.project_id
                || scope.task_id != task.task_id
                || scope
                    .artifact_refs
                    .iter()
                    .any(|artifact| !accepted_write_set.contains(&artifact.resource_ref))
        })
    {
        anyhow::bail!("completion memory verifier lineage is not exact");
    }
    let agent_result_write_id = completion_agent_result_write_id(completion_write_id);
    let mut canonical_artifact_refs = task
        .verification_scopes
        .iter()
        .flat_map(|scope| scope.artifact_refs.clone())
        .collect::<Vec<_>>();
    canonical_artifact_refs.sort_by(|left, right| {
        (&left.resource_ref, &left.content_hash).cmp(&(&right.resource_ref, &right.content_hash))
    });
    canonical_artifact_refs.dedup_by(|left, right| {
        left.resource_ref == right.resource_ref && left.content_hash == right.content_hash
    });
    let lineage = ControllerCommitHandoff {
        child_session_id: request_context.session_id,
        task_id: task.task_id,
        action_lease_id,
        base_commit: base_commit.clone(),
        candidate_artifact_or_diff_ref: format!("git-diff:{base_commit}..{}", first_scope.commit),
        accepted_write_set: accepted_write_set.clone(),
        branch: branch.clone(),
        verification_ids: task.verification_ids.clone(),
        verification_receipt_ids,
        canonical_artifact_refs,
        resulting_controller_commit: first_scope.commit.clone(),
        controller_receipt_id: ReceiptId::from_uuid(agent_result_write_id.as_uuid()),
        provenance_set_hash: provenance.hash.clone(),
    };
    let memory = derive_completion_memory(
        task,
        completion_write_id,
        agent_result_write_id,
        first_scope,
        &lineage,
        requested_memory,
    )?;
    Ok(AgentResultRecordCommand {
        context: CommandContext {
            write_id: agent_result_write_id,
            agent_id: AgentId::from_uuid(request_context.session_id.as_uuid()),
            session_id: Some(request_context.session_id),
            project_id: task.project_id,
            task_id: Some(task.task_id),
            scope: format!("task:{}", task.task_id),
            authority: "daemon-finish-gate".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        lineage,
        memory,
    })
}

pub(super) fn derive_completion_memory(
    task: &TaskContract,
    completion_write_id: WriteId,
    agent_result_write_id: WriteId,
    first_scope: &VerifierArtifactScope,
    lineage: &ControllerCommitHandoff,
    requested_memory: Option<&CompletionMemoryRequest>,
) -> Result<CompletionMemoryAdmission> {
    Ok(match requested_memory {
        Some(CompletionMemoryRequest::SaveDecision { statement }) => {
            let statement = statement.trim();
            if statement.is_empty() || statement.len() > MAX_COMPLETION_DECISION_BYTES {
                anyhow::bail!(
                    "completion decision must contain 1..={MAX_COMPLETION_DECISION_BYTES} bytes"
                );
            }
            let where_applicable = std::iter::once(format!("project:{}", task.project_id))
                .chain(std::iter::once(format!("task:{}", task.task_id)))
                .chain(std::iter::once(format!("branch:{}", lineage.branch)))
                .chain(std::iter::once(format!("commit:{}", first_scope.commit)))
                .chain(
                    lineage
                        .accepted_write_set
                        .iter()
                        .map(|path| format!("accepted_artifact:{path}")),
                )
                .collect::<Vec<_>>();
            let where_not_applicable = vec![
                "other projects or tasks".to_owned(),
                "artifact paths outside the accepted ActionLease write set".to_owned(),
                format!("branches other than {}", lineage.branch),
                format!(
                    "commits other than {} unless canonically revalidated",
                    first_scope.commit
                ),
            ];
            let freshness_rule = format!(
                "revalidate when task revision, action provenance, accepted artifact content, branch, commit, verifier configuration, or original verification IDs [{}] change",
                task.verification_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let source_id = format!("completion:{}:{}", task.task_id, agent_result_write_id);
            let evidence_id = EvidenceId::from_uuid(deterministic_completion_uuid(
                completion_write_id,
                "completion-evidence",
            ));
            let claim_id = ClaimId::from_uuid(deterministic_completion_uuid(
                completion_write_id,
                "completion-claim",
            ));
            let source_material = json!({
                "statement": statement,
                "lineage": &lineage,
                "where_applicable": &where_applicable,
                "where_not_applicable": &where_not_applicable,
                "freshness_rule": &freshness_rule,
            });
            let content_hash = canonical_struct_hash(&source_material)?;
            let source = SourceSnapshotInput {
                source_id: source_id.clone(),
                uri: format!(
                    "git+{}?branch={}#{}",
                    first_scope.worktree_ref, lineage.branch, first_scope.commit
                ),
                authority: "daemon-finish-gate".to_owned(),
                content_hash,
                excerpt: statement.to_owned(),
            };
            let evidence = EvidenceAtomInput {
                evidence_id,
                source_id: source_id.clone(),
                summary: "exact completion decision and canonical controller handoff lineage"
                    .to_owned(),
                payload: source_material.clone(),
            };
            let claim = ClaimCardInput {
                claim_id,
                statement: statement.to_owned(),
                status: eliot_types::EpistemicStatus::Verified,
                payload: json!({
                    "source_id": source_id,
                    "evidence_id": evidence_id,
                    "lineage": &lineage,
                    "where_applicable": &where_applicable,
                    "where_not_applicable": &where_not_applicable,
                    "freshness_rule": &freshness_rule,
                }),
            };
            CompletionMemoryAdmission::SaveDecision {
                decision: Box::new(CompletionDecisionMemory {
                    source,
                    evidence,
                    claim,
                    where_applicable,
                    where_not_applicable,
                    freshness_rule,
                }),
            }
        }
        Some(CompletionMemoryRequest::NothingToSave) | None => {
            CompletionMemoryAdmission::NothingToSave
        }
    })
}

pub(super) async fn submit_completion_agent_result(
    state: &McpState,
    request_context: AuthenticatedRequestContext,
    task: &TaskContract,
    completion_write_id: WriteId,
    requested_memory: Option<&CompletionMemoryRequest>,
) -> Result<Option<eliot_types::WriteReceipt>> {
    let git_handoff = task
        .action_provenance
        .as_ref()
        .is_some_and(|provenance| provenance.source_scope.kind == "git_worktree");
    if !git_handoff {
        if matches!(
            requested_memory,
            Some(CompletionMemoryRequest::SaveDecision { .. })
        ) {
            anyhow::bail!("saved completion memory requires canonical Git handoff lineage");
        }
        return Ok(None);
    }
    let agent_result_write_id = completion_agent_result_write_id(completion_write_id);
    if let Some(receipt) = state
        .store
        .write_receipt_by_id(&agent_result_write_id)
        .await?
    {
        if receipt.project_id != task.project_id
            || receipt.task_id != Some(task.task_id)
            || receipt.command_kind != eliot_types::SemanticCommandKind::AgentResultRecord
            || !matches!(
                receipt.status,
                WriteStatus::Committed | WriteStatus::IdempotentReplay
            )
        {
            anyhow::bail!("completion AgentResult receipt has incompatible canonical scope");
        }
        let claim_id = ClaimId::from_uuid(deterministic_completion_uuid(
            completion_write_id,
            "completion-claim",
        ));
        let existing_saved_decision = receipt.created_records.contains(&claim_id.to_string());
        match requested_memory {
            Some(CompletionMemoryRequest::SaveDecision { .. }) if !existing_saved_decision => {
                anyhow::bail!("completion memory was already finalized as nothing_to_save");
            }
            Some(CompletionMemoryRequest::NothingToSave) if existing_saved_decision => {
                anyhow::bail!("completion memory was already finalized as save_decision");
            }
            _ => {}
        }
        // The first accepted AgentResult is immutable. A later authenticated IPC
        // session returns its canonical receipt instead of rebuilding an envelope
        // whose session-bound audit fields would change the idempotency hash.
        return Ok(Some(receipt));
    }
    let mut verification_receipt_ids = Vec::with_capacity(task.verification_ids.len());
    for verification_id in &task.verification_ids {
        let verification_write_id = WriteId::from_uuid(verification_id.as_uuid());
        let receipt = state
            .store
            .write_receipt_by_id(&verification_write_id)
            .await?
            .context("completion memory verification receipt does not resolve")?;
        if receipt.project_id != task.project_id || receipt.task_id != Some(task.task_id) {
            anyhow::bail!("completion memory verification receipt scope mismatch");
        }
        verification_receipt_ids.push(receipt.receipt_id);
    }
    let command = SemanticCommand::AgentResultRecord(derive_completion_agent_result_command(
        request_context,
        task,
        completion_write_id,
        verification_receipt_ids,
        requested_memory,
    )?);
    let envelope = WriteAdmissionService.admit(&command)?;
    state
        .writer
        .submit(envelope)
        .await
        .map(Some)
        .map_err(Into::into)
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_task_completion(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: TaskCompletionToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse write id")?;
    let mut task = require_task(state, project_id, task_id).await?;
    if let Some(receipt) = state.store.write_receipt_by_id(&write_id).await? {
        if task.status == TaskContractStatus::DoneVerified
            && task.completion_write_id == Some(write_id)
            && receipt.project_id == project_id
            && receipt.task_id == Some(task_id)
        {
            let agent_result_receipt = submit_completion_agent_result(
                state,
                context,
                &task,
                write_id,
                input.memory.as_ref(),
            )
            .await?;
            return Ok(json!({
                "status": "done_verified",
                "decision": "DONE_VERIFIED",
                "task_contract": task,
                "write_receipt": receipt,
                "agent_result_receipt": agent_result_receipt,
                "memory_outcome": completion_memory_outcome(input.memory.as_ref())
            }));
        }
        anyhow::bail!("completion write_id already belongs to another transition");
    }
    ensure_expected_revision_or_replay(state, &task, input.expected_revision, write_id).await?;

    let mut uncovered = Vec::new();
    if task.status != TaskContractStatus::Active {
        uncovered.push("task:not_active".to_owned());
    }
    match task.action_provenance.as_ref() {
        Some(provenance) => {
            let expected = provenance.hash.clone();
            let mut material = provenance.clone();
            material.hash.clear();
            if canonical_struct_hash(&material)? != expected {
                uncovered.push("action_provenance:invalid_hash".to_owned());
            }
        }
        None => uncovered.push("action_provenance:required".to_owned()),
    }

    let requested_acceptance = input
        .acceptance_item_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let stored_acceptance = task
        .acceptance_items
        .iter()
        .map(|item| item.item_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if requested_acceptance != stored_acceptance
        || requested_acceptance.len() != input.acceptance_item_ids.len()
    {
        uncovered.push("acceptance_mapping:not_exact".to_owned());
    }
    let requested_observations = input
        .observation_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let stored_observations = task
        .observation_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if requested_observations != stored_observations
        || requested_observations.len() != input.observation_ids.len()
    {
        uncovered.push("observation_mapping:not_exact".to_owned());
    }
    let requested_verifications = input
        .verification_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let stored_verifications = task
        .verification_ids
        .iter()
        .map(ToString::to_string)
        .collect::<std::collections::BTreeSet<_>>();
    if requested_verifications != stored_verifications
        || requested_verifications.len() != input.verification_ids.len()
    {
        uncovered.push("verification_mapping:not_exact".to_owned());
    }
    for item in &task.acceptance_items {
        let required_evidence_present = match item.required_evidence {
            TaskAcceptanceEvidenceKind::Observation => item
                .observation_id
                .as_ref()
                .is_some_and(|id| input.observation_ids.contains(id)),
            TaskAcceptanceEvidenceKind::Verification => item
                .verification_id
                .is_some_and(|id| input.verification_ids.contains(&id.to_string())),
        };
        if !item.satisfied
            || !required_evidence_present
            || !input.acceptance_item_ids.contains(&item.item_id)
        {
            uncovered.push(item.item_id.clone());
        }
    }
    if task.observation_ids.is_empty() {
        uncovered.push("observation:required".to_owned());
    }
    if task.verification_ids.is_empty() {
        uncovered.push("verification:required".to_owned());
    }
    for observation_id in &task.observation_ids {
        if input.observation_ids.contains(observation_id) {
            let observation_write_id = WriteId::from_str(observation_id)?;
            let receipt = state
                .store
                .write_receipt_by_id(&observation_write_id)
                .await?;
            if receipt.as_ref().is_none_or(|receipt| {
                receipt.project_id != project_id || receipt.task_id != Some(task_id)
            }) {
                uncovered.push(format!("observation_receipt:{observation_id}"));
            }
        } else {
            uncovered.push(format!("observation:{observation_id}"));
        }
    }
    for verification_id in &task.verification_ids {
        let id = verification_id.to_string();
        if input.verification_ids.contains(&id) {
            let verification_write_id = WriteId::from_uuid(verification_id.as_uuid());
            let receipt = state
                .store
                .write_receipt_by_id(&verification_write_id)
                .await?;
            if receipt.as_ref().is_none_or(|receipt| {
                receipt.project_id != project_id || receipt.task_id != Some(task_id)
            }) {
                uncovered.push(format!("verification_receipt:{id}"));
            }
            let Some(scope) = task
                .verification_scopes
                .iter()
                .find(|scope| scope.verification_id == *verification_id)
            else {
                uncovered.push(format!("verification_scope:{id}:missing"));
                continue;
            };
            let item_scope_matches = task.acceptance_items.iter().any(|item| {
                item.required_evidence == TaskAcceptanceEvidenceKind::Verification
                    && item.verification_id == Some(*verification_id)
                    && item.verification_scope_hash.as_deref()
                        == Some(scope.canonical_scope_hash.as_str())
                    && scope.acceptance_item_ids == [item.item_id.clone()]
            });
            if !item_scope_matches {
                uncovered.push(format!("verification_scope:{id}:acceptance_mismatch"));
            }
            match state.store.verification_run_by_id(*verification_id).await? {
                Some(run) if run.result == VerificationResult::Passed => {
                    let stored_scope =
                        run.payload
                            .get("artifact_scope")
                            .cloned()
                            .and_then(|value| {
                                serde_json::from_value::<VerifierArtifactScope>(value).ok()
                            });
                    if stored_scope.as_ref() != Some(scope) {
                        uncovered.push(format!("verification_scope:{id}:record_mismatch"));
                    }
                }
                _ => uncovered.push(format!("verification_run:{id}:not_passed")),
            }
            if let Err(error) = revalidate_verifier_scope(state, &task, scope).await {
                uncovered.push(format!("verification_scope:{id}:{error}"));
            }
        } else {
            uncovered.push(format!("verification:{id}"));
        }
    }
    if !uncovered.is_empty() {
        return Ok(json!({
            "status": "denied_incomplete",
            "decision": "deny",
            "uncovered_items": uncovered,
            "write_receipt": Value::Null
        }));
    }

    task.status = TaskContractStatus::DoneVerified;
    task.completion_write_id = Some(write_id);
    let contract = task_input(&task, Some(MemoryRevision::new(input.expected_revision)));
    let (receipt, task) = submit_task_transition(
        state,
        context,
        project_id,
        write_id,
        contract,
        "daemon-finish-gate",
        TaintClass::LocalVerified,
        TaskTransitionEvidence::default(),
    )
    .await?;
    // Bind durable handoff/memory to the canonical finish transition. If this second,
    // idempotent write is interrupted, replay enters the DONE_VERIFIED branch above
    // and repairs it without ever publishing completion memory ahead of task truth.
    let agent_result_receipt =
        submit_completion_agent_result(state, context, &task, write_id, input.memory.as_ref())
            .await?;
    Ok(json!({
        "status": "done_verified",
        "decision": "DONE_VERIFIED",
        "task_contract": task,
        "write_receipt": receipt,
        "agent_result_receipt": agent_result_receipt,
        "memory_outcome": completion_memory_outcome(input.memory.as_ref())
    }))
}

#[derive(Default)]
pub(super) struct TaskTransitionEvidence {
    pub(super) observation: Option<ToolObservationInput>,
    pub(super) verification: Option<VerificationRunInput>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn submit_task_transition(
    state: &McpState,
    request_context: AuthenticatedRequestContext,
    project_id: ProjectId,
    write_id: WriteId,
    contract: TaskContractInput,
    authority: &str,
    taint: TaintClass,
    evidence: TaskTransitionEvidence,
) -> Result<(eliot_types::WriteReceipt, TaskContract)> {
    let task_id = contract.task_id;
    let command = SemanticCommand::TaskContractWrite(TaskContractWriteCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(request_context.session_id.as_uuid()),
            session_id: Some(request_context.session_id),
            project_id,
            task_id: Some(task_id),
            scope: format!("task:{task_id}"),
            authority: authority.to_owned(),
            visibility: Visibility::Project,
            taint,
            lifecycle_status: LifecycleStatus::Active,
        },
        contract,
        observation: evidence.observation,
        verification: evidence.verification,
    });
    let envelope = WriteAdmissionService.admit(&command)?;
    let receipt = state.writer.submit(envelope).await?;
    let contract = require_task(state, project_id, task_id).await?;
    Ok((receipt, contract))
}

pub(super) async fn require_task(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<TaskContract> {
    let task = state
        .store
        .task_contract_by_id(task_id)
        .await?
        .context("TaskContract not found")?;
    if task.project_id != project_id {
        anyhow::bail!("TaskContract project scope mismatch");
    }
    Ok(task)
}

pub(super) async fn ensure_expected_revision_or_replay(
    state: &McpState,
    task: &TaskContract,
    expected_revision: u64,
    write_id: WriteId,
) -> Result<()> {
    if state.store.write_receipt_by_id(&write_id).await?.is_some() {
        return Ok(());
    }
    if task.memory_revision != MemoryRevision::new(expected_revision) {
        anyhow::bail!(
            "stale task revision: expected {expected_revision}, current {}",
            task.memory_revision.value()
        );
    }
    Ok(())
}

pub(super) fn task_input(
    task: &TaskContract,
    expected_revision: Option<MemoryRevision>,
) -> TaskContractInput {
    TaskContractInput {
        task_id: task.task_id,
        title: task.title.clone(),
        status: task.status,
        acceptance_items: task.acceptance_items.clone(),
        expected_revision,
        action_lease_id: task.action_lease_id,
        understanding_proof_hash: task.understanding_proof_hash.clone(),
        action_provenance: task.action_provenance.clone(),
        observation_ids: task.observation_ids.clone(),
        verification_ids: task.verification_ids.clone(),
        verification_scopes: task.verification_scopes.clone(),
        completion_write_id: task.completion_write_id,
    }
}
