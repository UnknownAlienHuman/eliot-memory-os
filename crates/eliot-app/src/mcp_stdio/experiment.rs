//! Meta-experiments: proposing a change to ELIOT's own policy and disposing of
//! the result.
//!
//! A disposition is only admissible against an authoritative trace, so most of
//! this module is revalidation: the trace authority, the execution behind it,
//! and the replay that proves the recorded action still reproduces. Separating
//! the dispatch from those checks would leave the dispatch looking simpler than
//! it is allowed to be.

use super::*;

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_meta_experiment_run(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    require_canonical_controller_authority(state)?;
    let input: MetaExperimentToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse meta experiment task_id")?;
    let task =
        require_canonical_task(state, project_id, task_id, input.expected_task_revision).await?;
    let fingerprint = canonical_struct_hash(&input)?;
    let experiment_key = canonical_idempotency_key(&input.idempotency_key, "meta-experiment")?;
    let expected_write = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::HarnessExperiment,
        &experiment_key,
    );
    let existing = state
        .store
        .canonical_record_by_write_id::<eliot_types::HarnessExperimentRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::HarnessExperiment.as_str()],
            expected_write,
        )
        .await?;
    if let Some(existing) = existing {
        if !existing
            .receipt_body
            .notes
            .contains(&canonical_fingerprint_marker(&fingerprint))
        {
            anyhow::bail!("meta experiment idempotency conflict");
        }
        revalidate_meta_experiment_trace_authority(state, &task, &existing.receipt_body).await?;
        return reconcile_authoritative_meta_experiment(state, context, &input, &existing, true)
            .await;
    }
    if !meta_change_class_supported(input.change_class) {
        anyhow::bail!(
            "unsupported meta change class: only replay-threshold verification_map is executable"
        );
    }
    let fixed_baseline = canonical_execution_by_id(
        state,
        project_id,
        task_id,
        &input.fixed_baseline_execution_id,
        "fixed baseline",
    )
    .await?;
    let fixed_candidate = canonical_execution_by_id(
        state,
        project_id,
        task_id,
        &input.fixed_candidate_execution_id,
        "fixed candidate",
    )
    .await?;
    let holdout_baseline = canonical_execution_by_id(
        state,
        project_id,
        task_id,
        &input.holdout_baseline_execution_id,
        "holdout baseline",
    )
    .await?;
    let holdout_candidate = canonical_execution_by_id(
        state,
        project_id,
        task_id,
        &input.holdout_candidate_execution_id,
        "holdout candidate",
    )
    .await?;
    for execution in [
        &fixed_baseline,
        &fixed_candidate,
        &holdout_baseline,
        &holdout_candidate,
    ] {
        revalidate_execution_trace_authority(state, &task, &execution.receipt_body).await?;
    }
    let fixed_set = canonical_set_for_execution(
        state,
        project_id,
        task_id,
        &fixed_candidate,
        ReplaySetRole::Fixed,
    )
    .await?;
    let holdout_set = canonical_set_for_execution(
        state,
        project_id,
        task_id,
        &holdout_candidate,
        ReplaySetRole::Holdout,
    )
    .await?;
    let baseline_payload = ExperimentalMetaPolicyPayload::ReplayThresholdV1 {
        policy: input.baseline_policy.clone(),
    };
    let candidate_payload = ExperimentalMetaPolicyPayload::ReplayThresholdV1 {
        policy: input.candidate_policy.clone(),
    };
    let baseline_policy_hash = canonical_struct_hash(&baseline_payload)?;
    let candidate_policy_hash = canonical_struct_hash(&candidate_payload)?;
    let assessment = MetaHarnessService::assess_canonical(CanonicalMetaExperimentInput {
        project_id,
        eval_run_id: EvalRunId::from_str(&input.eval_run_id).context("parse eval_run_id")?,
        verdict_id: None,
        profile_id: "canonical-meta-replay-threshold-v1".to_owned(),
        candidate_ref: candidate_policy_hash.clone(),
        change_class: input.change_class,
        changed_variables: input.changed_variables.clone(),
        coupled_change_rationale: input.coupled_change_rationale.clone(),
        baseline_policy_hash,
        candidate_policy_hash,
        fixed_set: fixed_set.receipt_body,
        holdout_set: holdout_set.receipt_body,
        fixed_baseline: fixed_baseline.receipt_body.clone(),
        fixed_candidate: fixed_candidate.receipt_body.clone(),
        holdout_baseline: holdout_baseline.receipt_body.clone(),
        holdout_candidate: holdout_candidate.receipt_body.clone(),
        threshold: input.candidate_policy.clone(),
        attempted_fence: input.attempted_fence.clone(),
    })?;
    let mut experiment = assessment.records.experiment.clone();
    experiment
        .notes
        .push(canonical_fingerprint_marker(&fingerprint));
    experiment.authoritative_metric_evidence = assessment.records.metric_evidence.clone();
    experiment.authoritative_isolation_rejection = assessment.records.isolation_rejection.clone();
    experiment.authoritative_policy_candidate = if assessment.eligible_for_promotion {
        Some(MetaPolicyExecutor::stage(
            project_id,
            experiment.harness_experiment_record_id.to_string(),
            baseline_payload,
            candidate_payload,
        )?)
    } else {
        None
    };
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::HarnessExperiment,
        &experiment_key,
        &experiment,
    )
    .await?;
    maybe_inject_m2_failure(
        "ELIOT_TEST_M2_META_FAIL_AFTER_EXPERIMENT_PRIMARY",
        &input.idempotency_key,
        "meta experiment primary",
    )?;
    let persisted = state
        .store
        .canonical_record_by_write_id::<eliot_types::HarnessExperimentRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::HarnessExperiment.as_str()],
            receipt.write_id,
        )
        .await?
        .context("canonical meta experiment was not rehydrated after write")?;
    reconcile_authoritative_meta_experiment(state, context, &input, &persisted, false).await
}

struct AuthoritativeMetaRecords<'a> {
    rejection: Option<&'a eliot_types::MetaIsolationRejectionRecord>,
    candidate: Option<&'a eliot_types::ExperimentalMetaPolicyCandidate>,
}

fn authoritative_meta_records<'a>(
    experiment: &'a eliot_types::HarnessExperimentRecord,
    fingerprint: &str,
) -> Result<AuthoritativeMetaRecords<'a>> {
    let experiment_ref = experiment.harness_experiment_record_id.to_string();
    let records = AuthoritativeMetaRecords {
        rejection: experiment.authoritative_isolation_rejection.as_ref(),
        candidate: experiment.authoritative_policy_candidate.as_ref(),
    };
    if !experiment
        .notes
        .contains(&canonical_fingerprint_marker(fingerprint))
        || experiment.authoritative_metric_evidence.is_empty()
        || records.rejection.is_some_and(|record| {
            record.source_experiment_ref != experiment_ref
                || record.decision != MetaExperimentDecision::Rejected
        })
        || records.candidate.is_some_and(|record| {
            record.source_experiment_ref != experiment_ref
                || record.state != ExperimentalMetaPolicyState::Experimental
        })
        || (records.rejection.is_some() && records.candidate.is_some())
        || (experiment.decision == MetaExperimentDecision::Rejected) != records.rejection.is_some()
    {
        anyhow::bail!("meta experiment authoritative primary is incomplete or conflicting");
    }
    Ok(records)
}

pub(super) async fn reconcile_authoritative_meta_experiment(
    state: &McpState,
    context: AuthenticatedRequestContext,
    input: &MetaExperimentToolInput,
    primary: &CanonicalRecord<eliot_types::HarnessExperimentRecord>,
    replayed: bool,
) -> Result<Value> {
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id)?;
    let fingerprint = canonical_struct_hash(input)?;
    let experiment = &primary.receipt_body;
    let records = authoritative_meta_records(experiment, &fingerprint)?;
    let rejection = records.rejection;
    let candidate = records.candidate;
    let scope = (project_id, task_id);
    let mut metric_receipts = Vec::new();
    for (index, metric) in experiment.authoritative_metric_evidence.iter().enumerate() {
        let key =
            canonical_idempotency_key(&input.idempotency_key, &format!("meta-metric-{index}"))?;
        metric_receipts.push(
            reconcile_canonical_record(
                state,
                context,
                scope,
                CanonicalReceiptKind::MetaMetricEvidence,
                &key,
                metric,
            )
            .await?,
        );
    }
    let isolation_receipt = if let Some(rejection) = rejection {
        let key = canonical_idempotency_key(&input.idempotency_key, "meta-isolation-rejection")?;
        Some(
            reconcile_canonical_record(
                state,
                context,
                scope,
                CanonicalReceiptKind::MetaIsolationRejection,
                &key,
                rejection,
            )
            .await?,
        )
    } else {
        None
    };
    require_receipted_meta_rejection(rejection.is_some(), isolation_receipt.is_some())?;
    let policy_candidate = if let Some(candidate) = candidate {
        let key = canonical_idempotency_key(&input.idempotency_key, "meta-policy-candidate")?;
        let candidate_receipt = reconcile_canonical_record(
            state,
            context,
            scope,
            CanonicalReceiptKind::ExperimentalPolicyCandidate,
            &key,
            candidate,
        )
        .await?;
        Some(json!({
            "candidate": candidate,
            "promotion_action_hash": MetaPolicyExecutor::exact_action_hash(
                candidate,
                MetaPolicyExecutionAction::Promote,
            )?,
            "canonical_receipt": candidate_receipt
        }))
    } else {
        None
    };
    let primary_status = state
        .store
        .write_receipt_by_id(&primary.canonical_receipt.write_id)
        .await?
        .context("meta experiment primary receipt no longer resolves")?
        .status;
    Ok(json!({
        "accepted": rejection.is_none(),
        "replayed": replayed,
        "assessment": {
            "records": {
                "experiment": experiment,
                "metric_evidence": experiment.authoritative_metric_evidence,
                "isolation_rejection": rejection
            },
            "eligible_for_promotion": candidate.is_some(),
            "gate_results": [],
            "blocking_reasons": experiment.notes
        },
        "experiment": experiment,
        "policy_candidate": policy_candidate,
        "experiment_revision": primary.memory_revision,
        "canonical_receipt": primary.canonical_receipt,
        "write_status": primary_status,
        "metric_receipts": metric_receipts,
        "isolation_rejection": rejection,
        "isolation_rejection_receipt": isolation_receipt
    }))
}

pub(super) fn require_receipted_meta_rejection(
    has_rejection: bool,
    has_receipt: bool,
) -> Result<()> {
    if has_rejection && !has_receipt {
        anyhow::bail!("meta isolation rejection cannot be returned without a canonical receipt");
    }
    Ok(())
}

pub(super) const fn meta_change_class_supported(change_class: MetaCandidateChangeClass) -> bool {
    matches!(change_class, MetaCandidateChangeClass::VerificationMap)
}

pub(super) async fn canonical_execution_by_id(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    execution_id: &str,
    label: &str,
) -> Result<CanonicalRecord<CanonicalReplayExecutionRecord>> {
    let records = state
        .store
        .canonical_records_by_subject_ref::<CanonicalReplayExecutionRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::SealedReplayRun.as_str()],
            execution_id,
            1,
        )
        .await?;
    let record = records
        .into_iter()
        .next()
        .with_context(|| format!("{label} sealed execution is not canonical for this task"))?;
    if record.receipt_body.execution_id != execution_id {
        anyhow::bail!("{label} sealed execution subject identity is inconsistent");
    }
    ReplayRunnerService::validate_canonical_execution_identity(&record.receipt_body)?;
    Ok(record)
}

static M2_META_COMMIT_SERIALIZER: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

pub(super) fn m2_meta_commit_serializer() -> &'static tokio::sync::Mutex<()> {
    M2_META_COMMIT_SERIALIZER.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(super) async fn revalidate_execution_trace_authority(
    state: &McpState,
    task: &TaskContract,
    execution: &CanonicalReplayExecutionRecord,
) -> Result<()> {
    ReplayRunnerService::validate_canonical_execution_identity(execution)?;
    let refs = execution
        .audit
        .trace_contract_refs
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    if refs.len() < 2 {
        anyhow::bail!("canonical replay execution no longer has two sealed trace members");
    }
    for contract_ref in refs {
        let mut contracts = state
            .store
            .canonical_records_by_subject_ref::<CanonicalTraceCompletenessContract>(
                task.project_id,
                Some(task.task_id),
                &[CanonicalReceiptKind::TraceCompletenessContract.as_str()],
                contract_ref,
                2,
            )
            .await?;
        if contracts.len() != 1 || contracts[0].receipt_body.contract_id != *contract_ref {
            anyhow::bail!(
                "canonical replay trace contract is missing or ambiguous: {contract_ref}"
            );
        }
        let contract = contracts
            .pop()
            .context("canonical replay trace contract disappeared")?;
        revalidate_canonical_trace(state, task, &contract.receipt_body).await?;
    }
    Ok(())
}

pub(super) async fn revalidate_meta_experiment_trace_authority(
    state: &McpState,
    task: &TaskContract,
    experiment: &eliot_types::HarnessExperimentRecord,
) -> Result<()> {
    let execution_refs = experiment
        .replay_run_refs
        .iter()
        .chain(&experiment.holdout_run_refs)
        .collect::<std::collections::BTreeSet<_>>();
    if execution_refs.len() < 2 {
        anyhow::bail!("canonical meta experiment lost fixed or holdout replay authority");
    }
    for execution_ref in execution_refs {
        let execution = canonical_execution_by_id(
            state,
            task.project_id,
            task.task_id,
            execution_ref,
            "canonical meta replay",
        )
        .await?;
        revalidate_execution_trace_authority(state, task, &execution.receipt_body).await?;
    }
    Ok(())
}

pub(super) async fn canonical_set_for_execution(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    execution: &CanonicalRecord<CanonicalReplayExecutionRecord>,
    role: ReplaySetRole,
) -> Result<CanonicalRecord<SealedReplaySetRecord>> {
    let records = state
        .store
        .canonical_records_by_subject_ref::<SealedReplaySetRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::ReplaySet.as_str()],
            &execution.receipt_body.sealed_set_hash,
            128,
        )
        .await?;
    records
        .into_iter()
        .find(|record| record.receipt_body.role == role)
        .with_context(|| format!("sealed {role:?} replay set is not canonical"))
}

pub(super) fn meta_policy_action_replay_result(
    action: MetaPolicyExecutionAction,
    execution: &CanonicalRecord<eliot_types::MetaPolicyExecutionReceipt>,
    resulting_candidate: &eliot_types::ExperimentalMetaPolicyCandidate,
    candidate_receipt: &(WriteReceiptRef, WriteStatus),
    action_receipt: &(WriteReceiptRef, WriteStatus),
) -> Result<Value> {
    let mut result = json!({
        "accepted": true,
        "replayed": true,
        "action": match action {
            MetaPolicyExecutionAction::Promote => "promote",
            MetaPolicyExecutionAction::Rollback => "rollback",
        },
        "policy_candidate": resulting_candidate,
        "canonical_receipts": {
            "candidate_state": candidate_receipt
        }
    });
    match action {
        MetaPolicyExecutionAction::Promote => {
            result["promotion"] = json!(execution.receipt_body);
            result["rollback_action_hash"] = json!(MetaPolicyExecutor::exact_action_hash(
                resulting_candidate,
                MetaPolicyExecutionAction::Rollback,
            )?);
            result["canonical_receipts"]["promotion"] = json!(action_receipt);
        }
        MetaPolicyExecutionAction::Rollback => {
            result["rollback"] = json!(execution.receipt_body);
            result["canonical_receipts"]["rollback"] = json!(action_receipt);
        }
    }
    Ok(result)
}

pub(super) async fn rehydrate_meta_policy_action_replay(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    input: &MetaDispositionToolInput,
) -> Result<Option<Value>> {
    let (action, kind, action_suffix, state_suffix) = if input.rollback_requested {
        (
            MetaPolicyExecutionAction::Rollback,
            CanonicalReceiptKind::MetaPolicyRollback,
            "meta-policy-rollback",
            "meta-policy-rolled-back",
        )
    } else if input.decision == MetaExperimentDecision::Promoted {
        (
            MetaPolicyExecutionAction::Promote,
            CanonicalReceiptKind::MetaPolicyPromotion,
            "meta-policy-promotion",
            "meta-policy-promoted",
        )
    } else {
        return Ok(None);
    };
    let action_key = canonical_idempotency_key(&input.idempotency_key, action_suffix)?;
    let expected_action_write =
        deterministic_canonical_write_id(project_id, Some(task_id), kind, &action_key);
    let Some(execution) = state
        .store
        .canonical_record_by_write_id::<eliot_types::MetaPolicyExecutionReceipt>(
            project_id,
            Some(task_id),
            &[kind.as_str()],
            expected_action_write,
        )
        .await?
    else {
        return Ok(None);
    };
    if execution.receipt_body.action != action
        || execution.receipt_body.exact_action_hash != input.expected_action_hash
        || execution.receipt_body.operator_command_ref != input.operator_command_ref
    {
        anyhow::bail!("meta policy idempotency key was reused for a different exact action");
    }
    let state_key = canonical_idempotency_key(&input.idempotency_key, state_suffix)?;
    let expected_state_write = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::ExperimentalPolicyCandidate,
        &state_key,
    );
    let expected_state = match action {
        MetaPolicyExecutionAction::Promote => ExperimentalMetaPolicyState::Promoted,
        MetaPolicyExecutionAction::Rollback => ExperimentalMetaPolicyState::RolledBack,
    };
    let resulting_candidate = execution
        .receipt_body
        .resulting_candidate
        .as_ref()
        .context("meta policy action has no authoritative resulting candidate state")?;
    if resulting_candidate.state != expected_state
        || resulting_candidate.candidate_id != execution.receipt_body.candidate_id
    {
        anyhow::bail!("meta policy action and candidate state are not an exact pair");
    }
    let candidate_receipt = reconcile_canonical_record(
        state,
        context,
        (project_id, task_id),
        CanonicalReceiptKind::ExperimentalPolicyCandidate,
        &state_key,
        resulting_candidate,
    )
    .await?;
    if candidate_receipt.0.write_id != expected_state_write {
        anyhow::bail!("meta policy candidate reconciliation used a non-authoritative write id");
    }
    let action_status = state
        .store
        .write_receipt_by_id(&execution.canonical_receipt.write_id)
        .await?
        .context("meta policy action write receipt no longer resolves")?
        .status;
    let action_receipt = (execution.canonical_receipt.clone(), action_status);
    Ok(Some(meta_policy_action_replay_result(
        action,
        &execution,
        resulting_candidate,
        &candidate_receipt,
        &action_receipt,
    )?))
}

pub(super) async fn canonical_meta_experiment(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    experiment_id: &str,
) -> Result<CanonicalRecord<eliot_types::HarnessExperimentRecord>> {
    let records = state
        .store
        .canonical_records_by_subject_ref::<eliot_types::HarnessExperimentRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::HarnessExperiment.as_str()],
            experiment_id,
            2,
        )
        .await?;
    records
        .into_iter()
        .find(|record| {
            record.receipt_body.harness_experiment_record_id.to_string() == experiment_id
        })
        .context("canonical meta experiment authority is missing")
}

pub(super) async fn canonical_meta_metrics(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    experiment: &eliot_types::HarnessExperimentRecord,
) -> Result<Vec<eliot_types::CanonicalMetaMetricEvidence>> {
    let mut metrics = Vec::with_capacity(experiment.authoritative_metric_evidence.len());
    for authoritative in &experiment.authoritative_metric_evidence {
        let mut records = state
            .store
            .canonical_records_by_subject_ref::<eliot_types::CanonicalMetaMetricEvidence>(
                project_id,
                Some(task_id),
                &[CanonicalReceiptKind::MetaMetricEvidence.as_str()],
                &authoritative.evidence_hash,
                2,
            )
            .await?;
        let record = records
            .drain(..)
            .find(|record| record.receipt_body == *authoritative)
            .context("canonical meta metric evidence is missing")?;
        metrics.push(record.receipt_body);
    }
    Ok(metrics)
}

pub(super) async fn canonical_meta_rejections(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    experiment_id: &str,
) -> Result<Vec<CanonicalRecord<eliot_types::MetaIsolationRejectionRecord>>> {
    Ok(state
        .store
        .canonical_records_by_subject_ref::<eliot_types::MetaIsolationRejectionRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::MetaIsolationRejection.as_str()],
            experiment_id,
            2,
        )
        .await?
        .into_iter()
        .filter(|record| record.receipt_body.source_experiment_ref == experiment_id)
        .collect())
}

pub(super) async fn canonical_meta_dispositions(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    experiment_id: &str,
) -> Result<Vec<CanonicalRecord<eliot_types::HarnessExperimentRecord>>> {
    state
        .store
        .canonical_records_by_subject_ref::<eliot_types::HarnessExperimentRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::HarnessDisposition.as_str()],
            experiment_id,
            2,
        )
        .await
        .map_err(Into::into)
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_meta_experiment_disposition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    require_canonical_controller_authority(state)?;
    let _commit_guard = m2_meta_commit_serializer().lock().await;
    let input: MetaDispositionToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse meta disposition task_id")?;
    let task =
        require_canonical_task(state, project_id, task_id, input.expected_task_revision).await?;
    let experiment =
        canonical_meta_experiment(state, project_id, task_id, &input.experiment_id).await?;
    revalidate_meta_experiment_trace_authority(state, &task, &experiment.receipt_body).await?;
    let actual_revision = experiment
        .memory_revision
        .context("canonical meta experiment has no revision")?;
    if actual_revision.value() != input.expected_experiment_revision {
        anyhow::bail!(
            "stale experiment revision: expected {}, current {}",
            input.expected_experiment_revision,
            actual_revision.value()
        );
    }
    if let Some(replayed) =
        rehydrate_meta_policy_action_replay(state, context, project_id, task_id, &input).await?
    {
        return Ok(replayed);
    }
    let policy_candidate =
        current_meta_policy_candidate(state, project_id, task_id, &experiment.receipt_body).await?;
    if input.rollback_requested {
        let policy_candidate = policy_candidate
            .context("canonical experimental replay-threshold policy candidate not found")?;
        reject_distinct_meta_terminal_action(
            state,
            project_id,
            task_id,
            &policy_candidate.receipt_body.candidate_id,
            MetaPolicyExecutionAction::Rollback,
        )
        .await?;
        if policy_candidate.receipt_body.state != ExperimentalMetaPolicyState::Promoted {
            anyhow::bail!("meta policy rollback requires the current Promoted state exactly");
        }
        let promotions = state
            .store
            .meta_policy_actions_by_candidate(
                project_id,
                task_id,
                &policy_candidate.receipt_body.candidate_id,
                MetaPolicyExecutionAction::Promote,
            )
            .await?;
        if promotions.len() != 1 {
            anyhow::bail!("canonical policy promotion receipt is missing or ambiguous");
        }
        let promotion = &promotions[0];
        let expected_hash = MetaPolicyExecutor::exact_action_hash(
            &policy_candidate.receipt_body,
            MetaPolicyExecutionAction::Rollback,
        )?;
        let authorization = exact_meta_authorization(&input, &expected_hash)?;
        let (rolled_back, rollback) = MetaPolicyExecutor::rollback(
            &policy_candidate.receipt_body,
            &promotion.receipt_body,
            &authorization,
        )?;
        let rollback_key =
            canonical_idempotency_key(&input.idempotency_key, "meta-policy-rollback")?;
        let rollback_receipt = persist_canonical_record(
            state,
            context,
            project_id,
            task_id,
            CanonicalReceiptKind::MetaPolicyRollback,
            &rollback_key,
            &rollback,
        )
        .await?;
        maybe_inject_m2_failure(
            "ELIOT_TEST_M2_META_FAIL_AFTER_ACTION",
            &input.idempotency_key,
            "meta rollback action",
        )?;
        let state_key =
            canonical_idempotency_key(&input.idempotency_key, "meta-policy-rolled-back")?;
        let state_receipt = persist_canonical_record(
            state,
            context,
            project_id,
            task_id,
            CanonicalReceiptKind::ExperimentalPolicyCandidate,
            &state_key,
            &rolled_back,
        )
        .await?;
        return Ok(json!({
            "accepted": true,
            "action": "rollback",
            "policy_candidate": rolled_back,
            "rollback": rollback,
            "canonical_receipts": {
                "rollback": rollback_receipt,
                "candidate_state": state_receipt
            }
        }));
    }
    if input.decision == MetaExperimentDecision::Promoted {
        let policy_candidate = policy_candidate
            .context("canonical experimental replay-threshold policy candidate not found")?;
        reject_distinct_meta_terminal_action(
            state,
            project_id,
            task_id,
            &policy_candidate.receipt_body.candidate_id,
            MetaPolicyExecutionAction::Promote,
        )
        .await?;
        if policy_candidate.receipt_body.state != ExperimentalMetaPolicyState::Experimental {
            anyhow::bail!("meta policy promotion requires the current Experimental state exactly");
        }
        let experiment_id = experiment
            .receipt_body
            .harness_experiment_record_id
            .to_string();
        let rejections =
            canonical_meta_rejections(state, project_id, task_id, &experiment_id).await?;
        if experiment.receipt_body.decision != MetaExperimentDecision::KeptExperimental
            || !rejections.is_empty()
        {
            anyhow::bail!("rejected or isolated meta experiment cannot promote policy");
        }
        let assessment = CanonicalMetaExperimentAssessment {
            records: eliot_types::CanonicalMetaExperimentRecordSet {
                experiment: experiment.receipt_body.clone(),
                metric_evidence: canonical_meta_metrics(
                    state,
                    project_id,
                    task_id,
                    &experiment.receipt_body,
                )
                .await?,
                isolation_rejection: None,
            },
            eligible_for_promotion: true,
            gate_results: Vec::new(),
            blocking_reasons: Vec::new(),
        };
        let expected_hash = MetaPolicyExecutor::exact_action_hash(
            &policy_candidate.receipt_body,
            MetaPolicyExecutionAction::Promote,
        )?;
        let authorization = exact_meta_authorization(&input, &expected_hash)?;
        let (promoted, promotion) = MetaPolicyExecutor::promote(
            &policy_candidate.receipt_body,
            &assessment,
            &authorization,
        )?;
        let promotion_key =
            canonical_idempotency_key(&input.idempotency_key, "meta-policy-promotion")?;
        let promotion_receipt = persist_canonical_record(
            state,
            context,
            project_id,
            task_id,
            CanonicalReceiptKind::MetaPolicyPromotion,
            &promotion_key,
            &promotion,
        )
        .await?;
        maybe_inject_m2_failure(
            "ELIOT_TEST_M2_META_FAIL_AFTER_ACTION",
            &input.idempotency_key,
            "meta promotion action",
        )?;
        let state_key = canonical_idempotency_key(&input.idempotency_key, "meta-policy-promoted")?;
        let state_receipt = persist_canonical_record(
            state,
            context,
            project_id,
            task_id,
            CanonicalReceiptKind::ExperimentalPolicyCandidate,
            &state_key,
            &promoted,
        )
        .await?;
        let rollback_action_hash =
            MetaPolicyExecutor::exact_action_hash(&promoted, MetaPolicyExecutionAction::Rollback)?;
        return Ok(json!({
            "accepted": true,
            "action": "promote",
            "policy_candidate": promoted,
            "promotion": promotion,
            "rollback_action_hash": rollback_action_hash,
            "canonical_receipts": {
                "promotion": promotion_receipt,
                "candidate_state": state_receipt
            }
        }));
    }
    if !matches!(
        input.decision,
        MetaExperimentDecision::Rejected | MetaExperimentDecision::KeptExperimental
    ) {
        anyhow::bail!("terminal MCP disposition must be REJECTED or KEPT_EXPERIMENTAL");
    }
    let experiment_id = experiment
        .receipt_body
        .harness_experiment_record_id
        .to_string();
    let dispositions =
        canonical_meta_dispositions(state, project_id, task_id, &experiment_id).await?;
    if dispositions.len() > 1 {
        anyhow::bail!("meta experiment has multiple terminal disposition records");
    }
    if let Some(existing) = dispositions.into_iter().next() {
        if existing.receipt_body.decision != input.decision {
            anyhow::bail!("experiment already has a conflicting terminal disposition");
        }
        return Ok(json!({
            "accepted": true,
            "replayed": true,
            "disposition": existing.receipt_body,
            "canonical_receipt": existing.canonical_receipt,
            "disposition_revision": existing.memory_revision
        }));
    }
    let fingerprint = canonical_struct_hash(&input)?;
    let disposition_key = canonical_idempotency_key(&input.idempotency_key, "meta-disposition")?;
    let assessment = MetaExperimentAssessment {
        record: experiment.receipt_body.clone(),
        eligible_for_promotion: false,
        gate_results: Vec::new(),
        blocking_reasons: experiment.receipt_body.notes.clone(),
    };
    let mut disposition = MetaDispositionService::apply(
        &assessment,
        MetaDispositionRequest {
            decision: input.decision,
            authorized_command_ref: format!(
                "governor-command:meta-disposition:{}",
                &fingerprint[..16]
            ),
            rollback_target_ref: String::new(),
            rollback_command_ref: String::new(),
        },
    )?;
    disposition
        .notes
        .push(canonical_fingerprint_marker(&fingerprint));
    let (receipt, write_status) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::HarnessDisposition,
        &disposition_key,
        &disposition,
    )
    .await?;
    Ok(json!({
        "accepted": true,
        "replayed": false,
        "disposition": disposition,
        "canonical_receipt": receipt,
        "write_status": write_status,
        "rollback_receipt": Value::Null
    }))
}

pub(super) async fn reject_distinct_meta_terminal_action(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    candidate_id: &str,
    action: MetaPolicyExecutionAction,
) -> Result<()> {
    if !state
        .store
        .meta_policy_actions_by_candidate(project_id, task_id, candidate_id, action)
        .await?
        .is_empty()
    {
        anyhow::bail!(
            "meta policy terminal action already exists; retry its original idempotency key"
        );
    }
    Ok(())
}

pub(super) async fn dispatch_canonical_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: CanonicalStatusToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse canonical status task_id")?;
    let task = require_task(state, project_id, task_id).await?;
    let traces = canonical_trace_records(state, project_id, task_id).await?;
    let sleep = state
        .store
        .sleep_view(project_id, Some(task_id), 128)
        .await?;
    let replay = state
        .store
        .replay_view(project_id, Some(task_id), 128)
        .await?;
    let profile = ReplayRunnerService::deterministic_no_mutation_profile();
    let profile_hash = canonical_struct_hash(&profile)?;
    let mut trace_status = Vec::with_capacity(traces.len());
    for canonical in traces {
        let authority = revalidate_canonical_trace(state, &task, &canonical.receipt_body).await;
        trace_status.push(json!({
            "trace": canonical.receipt_body,
            "canonical_receipt": canonical.canonical_receipt,
            "memory_revision": canonical.memory_revision,
            "authority_valid": authority.is_ok(),
            "authority_error": authority.err().map(|error| error.to_string())
        }));
    }
    let sleep_runs = sleep
        .bundles
        .iter()
        .map(|record| {
            json!({
                "run": record.receipt_body.run,
                "bundle_id": record.receipt_body.bundle_id,
                "canonical_receipt": record.canonical_receipt,
                "memory_revision": record.memory_revision
            })
        })
        .collect::<Vec<_>>();
    let candidate_artifacts = sleep
        .bundles
        .iter()
        .flat_map(|record| {
            record.receipt_body.artifacts.iter().map(|artifact| {
                json!({
                    "artifact": artifact,
                    "receipt_kind": artifact.artifact_kind.receipt_kind(),
                    "aggregate_receipt": record.canonical_receipt,
                    "memory_revision": record.memory_revision
                })
            })
        })
        .collect::<Vec<_>>();
    let complete_replay_executions = complete_authoritative_replay_executions(&replay);
    Ok(json!({
        "component": "canonical_status",
        "project_id": project_id,
        "task_id": task_id,
        "task_revision": task.memory_revision,
        "replay_profile": {
            "version": profile.profile_id,
            "hash": profile_hash,
            "profile": profile
        },
        "registered_traces": trace_status,
        "sleep_runs": sleep_runs,
        "candidate_artifacts": candidate_artifacts,
        "sealed_replay_sets": replay.sealed_sets,
        "sealed_replay_cases": replay.sealed_cases,
        "sealed_replay_snapshots": replay.sealed_snapshots,
        "sealed_replay_executions": complete_replay_executions,
        "experiments_and_dispositions": replay.harness_experiments,
        "meta_metric_evidence": replay.meta_metrics,
        "meta_isolation_rejections": replay.isolation_rejections,
        "experimental_policy_candidates": replay.policy_candidates,
        "policy_execution_receipts": replay.policy_executions,
        "promotion_boundary": "only replay_threshold_v1 with exact action hash and exact rollback is executable"
    }))
}

pub(super) fn complete_authoritative_replay_executions(
    replay: &eliot_store::CanonicalReplayView,
) -> Vec<CanonicalRecord<CanonicalReplayExecutionRecord>> {
    let mut complete = Vec::new();
    let mut included = std::collections::BTreeSet::new();
    for baseline in &replay.sealed_executions {
        let Some(authority) = baseline.receipt_body.authoritative_replay.as_deref() else {
            continue;
        };
        let candidate = replay.sealed_executions.iter().find(|record| {
            record.canonical_receipt.write_id == authority.expected_candidate_write_id
                && record.receipt_body == authority.candidate_execution
        });
        let set_complete = replay.sealed_sets.iter().any(|record| {
            record.canonical_receipt.write_id == authority.expected_set_write_id
                && record.receipt_body == authority.sealed_set
        });
        let cases_complete = authority
            .expected_case_write_ids
            .iter()
            .zip(&authority.cases)
            .all(|(write_id, body)| {
                replay.sealed_cases.iter().any(|record| {
                    record.canonical_receipt.write_id == *write_id && record.receipt_body == *body
                })
            });
        let snapshots_complete = authority
            .expected_snapshot_write_ids
            .iter()
            .zip(&authority.snapshots)
            .all(|(write_id, body)| {
                replay.sealed_snapshots.iter().any(|record| {
                    record.canonical_receipt.write_id == *write_id && record.receipt_body == *body
                })
            });
        if set_complete
            && cases_complete
            && snapshots_complete
            && authority.expected_case_write_ids.len() == authority.cases.len()
            && authority.expected_snapshot_write_ids.len() == authority.snapshots.len()
            && let Some(candidate) = candidate
        {
            for record in [baseline, candidate] {
                if included.insert(record.canonical_receipt.write_id) {
                    complete.push(record.clone());
                }
            }
        }
    }
    complete
}
