//! Replaying what happened, and consolidating it while idle.
//!
//! A replay run re-executes recorded work against the canonical record and has
//! to reconcile whatever the last attempt left half-written; a sleep run
//! consolidates the result into bundles that are validated the same way. Both
//! answer the same question -- does the record still say what it said -- so the
//! reconciliation lives beside the runs rather than behind them.

use super::*;

pub(super) async fn dispatch_trace_completeness(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    require_canonical_controller_authority(state)?;
    let input: TraceCompletenessToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse canonical trace task_id")?;
    let task =
        require_canonical_task(state, project_id, task_id, input.expected_task_revision).await?;
    let write_key = canonical_idempotency_key(&input.idempotency_key, "trace-registration")?;
    let write_id = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::TraceCompletenessContract,
        &write_key,
    );
    if input.trace_ref.trim().is_empty() {
        anyhow::bail!("trace_ref must not be empty");
    }
    let evidence = resolve_canonical_trace_evidence(state, &input, &task).await?;
    let contract = TraceCompletenessService::build_canonical(CanonicalTraceCompletenessInput {
        project_id,
        task_id,
        source_task_revision: task.memory_revision,
        trace_ref: input.trace_ref.clone(),
        evidence,
    })?;
    let by_write = state
        .store
        .canonical_record_by_write_id::<CanonicalTraceCompletenessContract>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::TraceCompletenessContract.as_str()],
            write_id,
        )
        .await?;
    let by_trace = state
        .store
        .canonical_trace_by_trace_ref(project_id, task_id, &contract.trace_ref)
        .await?;
    let existing = match (by_write, by_trace) {
        (Some(by_write), Some(by_trace)) => {
            if by_write.canonical_receipt.write_id != by_trace.canonical_receipt.write_id {
                anyhow::bail!(
                    "trace registration idempotency key and trace_ref resolve to different canonical records"
                );
            }
            Some(by_write)
        }
        (Some(by_write), None) => Some(by_write),
        (None, Some(by_trace)) => Some(by_trace),
        (None, None) => None,
    };
    if let Some(existing) = existing {
        revalidate_canonical_trace(state, &task, &existing.receipt_body).await?;
        if existing.receipt_body != contract {
            anyhow::bail!("trace registration idempotency or trace_ref conflict");
        }
        return Ok(json!({
            "accepted": true,
            "replayed": true,
            "trace": existing.receipt_body,
            "canonical_receipt": existing.canonical_receipt,
            "memory_revision": existing.memory_revision
        }));
    }
    let (receipt, write_status) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::TraceCompletenessContract,
        &write_key,
        &contract,
    )
    .await?;
    let persisted = state
        .store
        .canonical_record_by_write_id::<CanonicalTraceCompletenessContract>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::TraceCompletenessContract.as_str()],
            receipt.write_id,
        )
        .await?
        .context("canonical trace contract was not rehydrated after write")?;
    write_json_report(
        &latest_report_path(&state.root, "trace-completeness"),
        &contract,
    )?;
    Ok(json!({
        "accepted": true,
        "replayed": false,
        "trace": contract,
        "canonical_receipt": receipt,
        "memory_revision": persisted.memory_revision,
        "write_status": write_status
    }))
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_replay_run(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    require_canonical_controller_authority(state)?;
    let input: ReplayRunToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse canonical replay task_id")?;
    let task =
        require_canonical_task(state, project_id, task_id, input.expected_task_revision).await?;
    let input_fingerprint = canonical_struct_hash(&input)?;
    let (trace_refs, role) = validate_canonical_replay_request(&input)?;
    let baseline_ref = canonical_struct_hash(&ExperimentalMetaPolicyPayload::ReplayThresholdV1 {
        policy: input.baseline_policy.clone(),
    })?;
    let candidate_ref = canonical_struct_hash(&ExperimentalMetaPolicyPayload::ReplayThresholdV1 {
        policy: input.candidate_policy.clone(),
    })?;
    let set_key = canonical_idempotency_key(&input.idempotency_key, "replay-set")?;
    let baseline_key = canonical_idempotency_key(&input.idempotency_key, "replay-baseline")?;
    let candidate_key = canonical_idempotency_key(&input.idempotency_key, "replay-candidate")?;
    let expected_baseline_write = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::SealedReplayRun,
        &baseline_key,
    );
    let expected_candidate_write = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::SealedReplayRun,
        &candidate_key,
    );
    if let Some(existing) = state
        .store
        .canonical_record_by_write_id::<CanonicalReplayExecutionRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::SealedReplayRun.as_str()],
            expected_baseline_write,
        )
        .await?
    {
        let request = AuthoritativeReplayRequest {
            task: &task,
            input: &input,
            input_fingerprint: &input_fingerprint,
            expected_candidate_write,
            baseline: &existing,
            replayed: true,
        };
        return reconcile_authoritative_replay(state, context, &request).await;
    }
    let mut contracts = Vec::with_capacity(trace_refs.len());
    for trace_ref in &trace_refs {
        contracts.push(
            require_registered_trace(state, &task, trace_ref)
                .await?
                .receipt_body,
        );
    }
    let mut cases = Vec::with_capacity(contracts.len());
    let mut snapshots = Vec::with_capacity(contracts.len());
    for contract in &contracts {
        let context_ref =
            canonical_trace_reference(contract, CanonicalTraceEvidenceKind::ContextPacket)?;
        let memory_ref =
            canonical_trace_reference(contract, CanonicalTraceEvidenceKind::MemoryExposureSet)?;
        let policy_ref =
            canonical_trace_reference(contract, CanonicalTraceEvidenceKind::PolicySnapshot)?;
        let artifact_ref =
            canonical_trace_reference(contract, CanonicalTraceEvidenceKind::ArtifactRef)?;
        let case = ReplayCaseService::create(ReplayCaseInput {
            project_id,
            source_task_id: Some(task_id),
            case_kind: input.case_kind.clone(),
            trace_contract_ref: contract.contract_id.clone(),
            input_snapshot_refs: vec![
                context_ref.clone(),
                memory_ref.clone(),
                policy_ref.clone(),
                artifact_ref.clone(),
            ],
        })?;
        snapshots.push(ReplayInputSnapshot {
            snapshot_id: format!("replay-snapshot:{}", contract.evidence_manifest_hash),
            replay_case_id: case.replay_case_id,
            context_packet_ref: Some(context_ref),
            memory_refs: vec![memory_ref],
            skill_refs: Vec::new(),
            policy_refs: vec![policy_ref],
            artifact_refs: vec![artifact_ref],
            created_at: time::OffsetDateTime::now_utc(),
        });
        cases.push(case);
    }
    let set = ReplaySetService::create(ReplaySetInput {
        project_id,
        name: input.set_name.clone(),
        purpose: format!("{} sealed canonical replay", input.set_role),
        cases: cases.iter().map(|case| case.replay_case_id).collect(),
        fixed: true,
        holdout: role == ReplaySetRole::Holdout,
        created_from_refs: contracts
            .iter()
            .map(|contract| contract.contract_id.clone())
            .collect(),
    });
    let sealed = ReplaySealService::seal(ReplaySealInput {
        set,
        role,
        version: input.set_version,
        evaluator_version: input.evaluator_version.clone(),
        context_version: input.sealed_context_version.clone(),
        cases,
        snapshots,
    })?;
    let observations = sealed
        .cases
        .iter()
        .zip(&sealed.snapshots)
        .zip(&contracts)
        .map(
            |((case, snapshot), contract)| CanonicalReplayObservationEvidence {
                replay_case_id: case.case.replay_case_id,
                snapshot_hash: snapshot.content_hash.clone(),
                evidence: contract.evidence.clone(),
            },
        )
        .collect::<Vec<_>>();
    let mut baseline_execution =
        ReplayRunnerService::run_canonical(CanonicalReplayExecutionInput {
            sealed_set: sealed.set.clone(),
            cases: sealed.cases.clone(),
            snapshots: sealed.snapshots.clone(),
            trace_contracts: contracts.clone(),
            observations: observations.clone(),
            baseline_ref: baseline_ref.clone(),
            candidate_ref: baseline_ref.clone(),
            candidate_version: input.baseline_version.clone(),
            mutation_attempt: input.mutation_attempt.clone(),
        })?;
    let candidate_execution = ReplayRunnerService::run_canonical(CanonicalReplayExecutionInput {
        sealed_set: sealed.set.clone(),
        cases: sealed.cases.clone(),
        snapshots: sealed.snapshots.clone(),
        trace_contracts: contracts,
        observations,
        baseline_ref,
        candidate_ref,
        candidate_version: input.candidate_version.clone(),
        mutation_attempt: input.mutation_attempt.clone(),
    })?;
    let expected_set_write_id = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::ReplaySet,
        &set_key,
    );
    let expected_case_write_ids = (0..sealed.cases.len())
        .map(|index| {
            let key =
                canonical_idempotency_key(&input.idempotency_key, &format!("replay-case-{index}"))?;
            Ok(deterministic_canonical_write_id(
                project_id,
                Some(task_id),
                CanonicalReceiptKind::ReplayCase,
                &key,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_snapshot_write_ids = (0..sealed.snapshots.len())
        .map(|index| {
            let key = canonical_idempotency_key(
                &input.idempotency_key,
                &format!("replay-snapshot-{index}"),
            )?;
            Ok(deterministic_canonical_write_id(
                project_id,
                Some(task_id),
                CanonicalReceiptKind::ReplayInputSnapshot,
                &key,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    baseline_execution.authoritative_replay = Some(Box::new(CanonicalReplayAuthority {
        input_fingerprint: input_fingerprint.clone(),
        sealed_set: sealed.set.clone(),
        cases: sealed.cases.clone(),
        snapshots: sealed.snapshots.clone(),
        candidate_execution: candidate_execution.clone(),
        expected_baseline_write_id: expected_baseline_write,
        expected_candidate_write_id: expected_candidate_write,
        expected_set_write_id,
        expected_case_write_ids,
        expected_snapshot_write_ids,
    }));
    let baseline_receipt = persist_canonical_record(
        state,
        context,
        project_id,
        task_id,
        CanonicalReceiptKind::SealedReplayRun,
        &baseline_key,
        &baseline_execution,
    )
    .await?;
    maybe_inject_m2_failure(
        "ELIOT_TEST_M2_REPLAY_FAIL_AFTER_BASELINE",
        &input.idempotency_key,
        "replay baseline primary",
    )?;
    let persisted_baseline = state
        .store
        .canonical_record_by_write_id::<CanonicalReplayExecutionRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::SealedReplayRun.as_str()],
            baseline_receipt.0.write_id,
        )
        .await?
        .context("canonical replay baseline primary was not rehydrated after write")?;
    let request = AuthoritativeReplayRequest {
        task: &task,
        input: &input,
        input_fingerprint: &input_fingerprint,
        expected_candidate_write,
        baseline: &persisted_baseline,
        replayed: false,
    };
    let report = reconcile_authoritative_replay(state, context, &request).await?;
    write_json_report(&latest_report_path(&state.root, "replay-runs"), &report)?;
    let verdict = ReplayVerdictService::verdict(&candidate_execution.run);
    write_json_report(
        &latest_report_path(&state.root, "replay-verdicts"),
        &verdict,
    )?;
    Ok(report)
}

struct AuthoritativeReplayRequest<'a> {
    task: &'a TaskContract,
    input: &'a ReplayRunToolInput,
    input_fingerprint: &'a str,
    expected_candidate_write: WriteId,
    baseline: &'a CanonicalRecord<CanonicalReplayExecutionRecord>,
    replayed: bool,
}

fn validate_authoritative_replay<'a>(
    request: &'a AuthoritativeReplayRequest<'a>,
) -> Result<&'a CanonicalReplayAuthority> {
    let project_id = request.task.project_id;
    let task_id = request.task.task_id;
    let authority = request
        .baseline
        .receipt_body
        .authoritative_replay
        .as_deref()
        .context("canonical replay baseline has no authoritative aggregate")?;
    let baseline_key =
        canonical_idempotency_key(&request.input.idempotency_key, "replay-baseline")?;
    let set_key = canonical_idempotency_key(&request.input.idempotency_key, "replay-set")?;
    let expected_baseline_write = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::SealedReplayRun,
        &baseline_key,
    );
    let expected_set_write = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::ReplaySet,
        &set_key,
    );
    let expected_case_writes = (0..authority.cases.len())
        .map(|index| {
            let key = canonical_idempotency_key(
                &request.input.idempotency_key,
                &format!("replay-case-{index}"),
            )?;
            Ok(deterministic_canonical_write_id(
                project_id,
                Some(task_id),
                CanonicalReceiptKind::ReplayCase,
                &key,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_snapshot_writes = (0..authority.snapshots.len())
        .map(|index| {
            let key = canonical_idempotency_key(
                &request.input.idempotency_key,
                &format!("replay-snapshot-{index}"),
            )?;
            Ok(deterministic_canonical_write_id(
                project_id,
                Some(task_id),
                CanonicalReceiptKind::ReplayInputSnapshot,
                &key,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    if authority.input_fingerprint != request.input_fingerprint
        || request.baseline.canonical_receipt.write_id != expected_baseline_write
        || authority.expected_baseline_write_id != expected_baseline_write
        || authority.expected_candidate_write_id != request.expected_candidate_write
        || authority.expected_set_write_id != expected_set_write
        || authority.expected_case_write_ids != expected_case_writes
        || authority.expected_snapshot_write_ids != expected_snapshot_writes
        || authority.candidate_execution.authoritative_replay.is_some()
    {
        anyhow::bail!("replay idempotency key conflicts with the authoritative complete input");
    }
    let resealed = ReplaySealService::seal(ReplaySealInput {
        set: authority.sealed_set.set.clone(),
        role: authority.sealed_set.role,
        version: authority.sealed_set.version,
        evaluator_version: authority.sealed_set.evaluator_version.clone(),
        context_version: authority.sealed_set.context_version.clone(),
        cases: authority
            .cases
            .iter()
            .map(|record| record.case.clone())
            .collect(),
        snapshots: authority
            .snapshots
            .iter()
            .map(|record| record.snapshot.clone())
            .collect(),
    })?;
    if resealed.set != authority.sealed_set
        || resealed.cases != authority.cases
        || resealed.snapshots != authority.snapshots
        || request.baseline.receipt_body.sealed_set_hash != authority.sealed_set.sealed_hash
        || authority.candidate_execution.sealed_set_hash != authority.sealed_set.sealed_hash
    {
        anyhow::bail!("authoritative replay aggregate membership is tampered");
    }
    Ok(authority)
}

async fn reconcile_authoritative_replay(
    state: &McpState,
    context: AuthenticatedRequestContext,
    request: &AuthoritativeReplayRequest<'_>,
) -> Result<Value> {
    let scope = (request.task.project_id, request.task.task_id);
    let authority = validate_authoritative_replay(request)?;
    let candidate_key =
        canonical_idempotency_key(&request.input.idempotency_key, "replay-candidate")?;
    let set_key = canonical_idempotency_key(&request.input.idempotency_key, "replay-set")?;
    revalidate_execution_trace_authority(state, request.task, &request.baseline.receipt_body)
        .await?;
    revalidate_execution_trace_authority(state, request.task, &authority.candidate_execution)
        .await?;

    let mut record_receipts = Vec::new();
    record_receipts.push(
        reconcile_canonical_record(
            state,
            context,
            scope,
            CanonicalReceiptKind::ReplaySet,
            &set_key,
            &authority.sealed_set,
        )
        .await?,
    );
    for (index, case) in authority.cases.iter().enumerate() {
        let key = canonical_idempotency_key(
            &request.input.idempotency_key,
            &format!("replay-case-{index}"),
        )?;
        record_receipts.push(
            reconcile_canonical_record(
                state,
                context,
                scope,
                CanonicalReceiptKind::ReplayCase,
                &key,
                case,
            )
            .await?,
        );
    }
    for (index, snapshot) in authority.snapshots.iter().enumerate() {
        let key = canonical_idempotency_key(
            &request.input.idempotency_key,
            &format!("replay-snapshot-{index}"),
        )?;
        record_receipts.push(
            reconcile_canonical_record(
                state,
                context,
                scope,
                CanonicalReceiptKind::ReplayInputSnapshot,
                &key,
                snapshot,
            )
            .await?,
        );
    }
    let candidate_receipt = reconcile_canonical_record(
        state,
        context,
        scope,
        CanonicalReceiptKind::SealedReplayRun,
        &candidate_key,
        &authority.candidate_execution,
    )
    .await?;
    let baseline_status = state
        .store
        .write_receipt_by_id(&request.baseline.canonical_receipt.write_id)
        .await?
        .context("authoritative replay baseline receipt no longer resolves")?
        .status;
    Ok(json!({
        "accepted": true,
        "replayed": request.replayed,
        "sealed_set": authority.sealed_set,
        "cases": authority.cases,
        "snapshots": authority.snapshots,
        "baseline_execution": request.baseline.receipt_body,
        "candidate_execution": authority.candidate_execution,
        "canonical_receipts": {
            "records": record_receipts,
            "baseline_execution": (request.baseline.canonical_receipt.clone(), baseline_status),
            "candidate_execution": candidate_receipt
        }
    }))
}

pub(super) fn maybe_inject_m2_failure(variable: &str, key: &str, checkpoint: &str) -> Result<()> {
    if cfg!(debug_assertions)
        && std::env::var(variable)
            .ok()
            .is_some_and(|configured| configured == key)
    {
        anyhow::bail!("injected M2 failure after {checkpoint}");
    }
    Ok(())
}

pub(super) fn canonical_trace_reference(
    contract: &CanonicalTraceCompletenessContract,
    kind: CanonicalTraceEvidenceKind,
) -> Result<String> {
    contract
        .evidence
        .iter()
        .find(|evidence| evidence.kind == kind)
        .map(|evidence| evidence.reference.clone())
        .with_context(|| format!("canonical trace is missing {kind:?}"))
}

pub(super) fn validate_canonical_replay_request(
    input: &ReplayRunToolInput,
) -> Result<(Vec<String>, ReplaySetRole)> {
    let mut trace_refs = input.trace_refs.clone();
    trace_refs.sort();
    trace_refs.dedup();
    if trace_refs.len() < 2 || trace_refs.len() > 20 {
        anyhow::bail!("sealed replay set requires 2 to 20 distinct canonical traces");
    }
    if input.set_name.trim().is_empty() || input.set_version == 0 {
        anyhow::bail!("sealed replay set requires a name and positive version");
    }
    let role = match input.set_role.as_str() {
        "fixed" => ReplaySetRole::Fixed,
        "holdout" => ReplaySetRole::Holdout,
        _ => anyhow::bail!("set_role must be fixed or holdout"),
    };
    if input.baseline_policy.schema_version != "1"
        || input.candidate_policy.schema_version != "1"
        || input.baseline_policy.evaluator_version != input.evaluator_version
        || input.candidate_policy.evaluator_version != input.evaluator_version
        || input.baseline_policy.minimum_pass_basis_points > 10_000
        || input.candidate_policy.minimum_pass_basis_points > 10_000
        || canonical_struct_hash(&input.baseline_policy)?
            == canonical_struct_hash(&input.candidate_policy)?
        || input.baseline_version.trim().is_empty()
        || input.candidate_version.trim().is_empty()
        || input.sealed_context_version.trim().is_empty()
        || input.evaluator_version.trim().is_empty()
    {
        anyhow::bail!("sealed replay versions, baseline, and candidate must be explicit");
    }
    Ok((trace_refs, role))
}

pub(super) async fn persist_canonical_record<T: serde::Serialize>(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    kind: CanonicalReceiptKind,
    key: &str,
    record: &T,
) -> Result<(WriteReceiptRef, WriteStatus)> {
    write_canonical_observation(state, context, project_id, Some(task_id), kind, key, record).await
}

pub(super) async fn reconcile_canonical_record<T>(
    state: &McpState,
    context: AuthenticatedRequestContext,
    scope: (ProjectId, TaskId),
    kind: CanonicalReceiptKind,
    key: &str,
    body: &T,
) -> Result<(WriteReceiptRef, WriteStatus)>
where
    T: PartialEq + serde::de::DeserializeOwned + serde::Serialize,
{
    let (project_id, task_id) = scope;
    let expected_write = deterministic_canonical_write_id(project_id, Some(task_id), kind, key);
    if let Some(existing) = state
        .store
        .canonical_record_by_write_id::<T>(
            project_id,
            Some(task_id),
            &[kind.as_str()],
            expected_write,
        )
        .await?
    {
        if existing.receipt_kind != kind.as_str() || existing.receipt_body != *body {
            anyhow::bail!("canonical secondary record conflicts with its authoritative primary");
        }
        let status = state
            .store
            .write_receipt_by_id(&expected_write)
            .await?
            .context("canonical secondary write receipt no longer resolves")?
            .status;
        return Ok((existing.canonical_receipt, status));
    }
    persist_canonical_record(state, context, project_id, task_id, kind, key, body).await
}

pub(super) fn dispatch_replay_report(state: &McpState) -> Value {
    json!({
        "component": "replay_report",
        "run": read_latest_report_value(&state.root, "replay-runs").ok(),
        "verdict": read_latest_report_value(&state.root, "replay-verdicts").ok()
    })
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_sleep_run(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    require_canonical_controller_authority(state)?;
    let input: SleepRunToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse governed sleep task_id")?;
    let task =
        require_canonical_task(state, project_id, task_id, input.expected_task_revision).await?;
    if !input.dry_run {
        anyhow::bail!("governed sleep MCP is candidate-only and requires dry_run=true");
    }
    if input.trace_refs.is_empty() || input.trace_refs.len() > 20 {
        anyhow::bail!("sleep requires between 1 and 20 requested trace refs");
    }
    let mut contracts = Vec::with_capacity(input.trace_refs.len());
    for trace_ref in &input.trace_refs {
        contracts.push(
            require_registered_trace(state, &task, trace_ref)
                .await?
                .receipt_body,
        );
    }
    if contracts.len() != input.trace_refs.len() {
        anyhow::bail!("sleep input contains an unregistered or duplicate canonical trace");
    }
    let fingerprint = canonical_struct_hash(&input)?;
    let bundle_key = canonical_idempotency_key(&input.idempotency_key, "sleep-bundle")?;
    let expected_write = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::SleepConsolidationBundle,
        &bundle_key,
    );
    let existing = state
        .store
        .canonical_record_by_write_id::<SleepConsolidationBundle>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::SleepConsolidationBundle.as_str()],
            expected_write,
        )
        .await?;
    let (bundle, receipt, write_status, replayed) = if let Some(existing) = existing {
        if !existing
            .receipt_body
            .run
            .reasoning_route_ref
            .contains(&canonical_fingerprint_marker(&fingerprint))
        {
            anyhow::bail!("sleep idempotency conflict");
        }
        validate_sleep_bundle(&existing.receipt_body)?;
        (
            existing.receipt_body.clone(),
            existing.canonical_receipt.clone(),
            WriteStatus::IdempotentReplay,
            true,
        )
    } else {
        let mut bundle = SleepConsolidationService::run_with_artifacts(
            SleepRunInput {
                project_id,
                trigger: input.trigger,
                dry_run: input.dry_run,
                input_traces: input.trace_refs.clone(),
                max_input_bytes: 8_192,
                reasoning_retry_limit: 1,
            },
            &contracts,
            IncidentService::new(&state.root).lockdown_active()?,
        )?;
        bundle.run.input_scope.task_ids = vec![task_id];
        bundle.run.reasoning_route_ref = format!(
            "deterministic:sleep-consolidation-v3; {}",
            canonical_fingerprint_marker(&fingerprint)
        );
        finalize_sleep_bundle_identity(&mut bundle)?;
        validate_sleep_bundle(&bundle)?;
        let (receipt, write_status) = write_canonical_observation(
            state,
            context,
            project_id,
            Some(task_id),
            CanonicalReceiptKind::SleepConsolidationBundle,
            &bundle_key,
            &bundle,
        )
        .await?;
        (bundle, receipt, write_status, false)
    };
    let artifact_receipts = reconcile_sleep_artifacts(
        state,
        context,
        project_id,
        task_id,
        &input.idempotency_key,
        &bundle,
    )
    .await?;
    write_json_report(&latest_report_path(&state.root, "sleep"), &bundle)?;
    Ok(json!({
        "accepted": true,
        "replayed": replayed,
        "bundle": bundle,
        "run": bundle.run,
        "artifacts": bundle.artifacts,
        "artifact_receipts": artifact_receipts,
        "canonical_receipt": receipt,
        "write_status": write_status
    }))
}

pub(super) fn finalize_sleep_bundle_identity(bundle: &mut SleepConsolidationBundle) -> Result<()> {
    let bundle_hash = canonical_struct_hash(&json!({
        "run": bundle.run,
        "artifacts": bundle.artifacts,
    }))?;
    bundle.bundle_id = format!("sleep-bundle:{bundle_hash}");
    bundle.bundle_hash = bundle_hash;
    Ok(())
}

pub(super) fn validate_sleep_bundle(bundle: &SleepConsolidationBundle) -> Result<()> {
    let expected_hash = canonical_struct_hash(&json!({
        "run": bundle.run,
        "artifacts": bundle.artifacts,
    }))?;
    let kinds = bundle
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_kind)
        .collect::<std::collections::BTreeSet<_>>();
    if bundle.bundle_hash != expected_hash
        || bundle.bundle_id != format!("sleep-bundle:{expected_hash}")
        || bundle.artifacts.len() != 5
        || kinds.len() != 5
        || bundle.artifacts.iter().any(|artifact| {
            artifact.body["sleep_run_ref"] != bundle.run.sleep_run_id
                || validate_sleep_artifact(artifact).is_err()
        })
    {
        anyhow::bail!("sleep aggregate is incomplete, tampered, or non-authoritative");
    }
    Ok(())
}

pub(super) async fn reconcile_sleep_artifacts(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    idempotency_key: &str,
    bundle: &SleepConsolidationBundle,
) -> Result<Vec<Value>> {
    let mut receipts = Vec::new();
    for (index, artifact) in bundle.artifacts.iter().enumerate() {
        let key = canonical_idempotency_key(
            idempotency_key,
            &format!(
                "sleep-artifact-{}-{index}",
                artifact.artifact_kind.receipt_kind()
            ),
        )?;
        let kind = sleep_artifact_receipt_kind(artifact.artifact_kind);
        let expected_write =
            deterministic_canonical_write_id(project_id, Some(task_id), kind, &key);
        let existing = state
            .store
            .canonical_record_by_write_id::<eliot_types::SleepCandidateArtifact>(
                project_id,
                Some(task_id),
                &[kind.as_str()],
                expected_write,
            )
            .await?;
        let (receipt, write_status) = match existing {
            None => {
                write_canonical_observation(
                    state,
                    context,
                    project_id,
                    Some(task_id),
                    kind,
                    &key,
                    artifact,
                )
                .await?
            }
            Some(record)
                if record.receipt_kind == kind.as_str() && record.receipt_body == *artifact =>
            {
                (record.canonical_receipt, WriteStatus::IdempotentReplay)
            }
            _ => anyhow::bail!(
                "sleep secondary reconciliation found a conflicting canonical artifact"
            ),
        };
        receipts.push(json!({
            "artifact": artifact,
            "canonical_receipt": receipt,
            "write_status": write_status
        }));
        maybe_inject_sleep_reconciliation_failure(index + 1)?;
    }
    for (index, artifact) in bundle.artifacts.iter().enumerate() {
        let key = canonical_idempotency_key(
            idempotency_key,
            &format!(
                "sleep-artifact-{}-{index}",
                artifact.artifact_kind.receipt_kind()
            ),
        )?;
        let kind = sleep_artifact_receipt_kind(artifact.artifact_kind);
        let expected_write =
            deterministic_canonical_write_id(project_id, Some(task_id), kind, &key);
        let persisted = state
            .store
            .canonical_record_by_write_id::<eliot_types::SleepCandidateArtifact>(
                project_id,
                Some(task_id),
                &[kind.as_str()],
                expected_write,
            )
            .await?;
        if persisted.is_none_or(|record| record.receipt_body != *artifact) {
            anyhow::bail!("sleep secondary reconciliation is incomplete or conflicting");
        }
    }
    Ok(receipts)
}

pub(super) fn maybe_inject_sleep_reconciliation_failure(completed: usize) -> Result<()> {
    if cfg!(debug_assertions)
        && std::env::var("ELIOT_TEST_M2_SLEEP_FAIL_AFTER_SECONDARIES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            == Some(completed)
    {
        anyhow::bail!("injected sleep secondary reconciliation failure");
    }
    Ok(())
}

pub(super) const fn sleep_artifact_receipt_kind(
    kind: SleepCandidateArtifactKind,
) -> CanonicalReceiptKind {
    match kind {
        SleepCandidateArtifactKind::Procedure => CanonicalReceiptKind::ProcedureCandidate,
        SleepCandidateArtifactKind::ForgettingAction => CanonicalReceiptKind::ForgettingCandidate,
        SleepCandidateArtifactKind::Test => CanonicalReceiptKind::TestCandidate,
        SleepCandidateArtifactKind::ReplayCase => CanonicalReceiptKind::ReplayCaseCandidate,
        SleepCandidateArtifactKind::Dream => CanonicalReceiptKind::DreamCandidate,
    }
}

pub(super) fn validate_sleep_artifact(
    artifact: &eliot_types::SleepCandidateArtifact,
) -> Result<()> {
    let expected_prefix = match artifact.artifact_kind {
        SleepCandidateArtifactKind::Procedure => "procedure-candidate:",
        SleepCandidateArtifactKind::ForgettingAction => "forgetting-candidate:",
        SleepCandidateArtifactKind::Test => "test-candidate:",
        SleepCandidateArtifactKind::ReplayCase => "replay-case-candidate:",
        SleepCandidateArtifactKind::Dream => "dream-candidate:",
    };
    if !artifact.candidate_only
        || artifact.required_replay.replay_marker.is_some()
        || !artifact.required_replay.required
        || artifact.prohibited_direct_effects.is_empty()
        || artifact.source_trace_ref.trim().is_empty()
        || artifact.source_trace_contract_ref.trim().is_empty()
        || !artifact.artifact_id.starts_with(expected_prefix)
    {
        anyhow::bail!("sleep emitted an unsafe, dangling, or non-candidate artifact");
    }
    Ok(())
}
