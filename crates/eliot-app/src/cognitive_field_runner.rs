use anyhow::{Context, Result, bail, ensure};
use eliot_engine::CognitiveFieldGradingService;
use eliot_types::{
    AgentHostId, COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION,
    COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION, COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION,
    COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION, COGNITIVE_FIELD_PLAN_SCHEMA_VERSION,
    COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION, COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION,
    COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION, COGNITIVE_FIELD_WORKER_SCHEMA_VERSION,
    CognitiveDeterministicEvidenceReceipt, CognitiveDeterministicReport, CognitiveFieldCase,
    CognitiveFieldExecutionKey, CognitiveFieldPlan, CognitiveFieldPlanItem,
    CognitiveFieldProviderCallPlan, CognitiveFieldProviderEvidenceReceipt,
    CognitiveFieldProviderOutputProjection, CognitiveFieldProviderPlan,
    CognitiveFieldProviderProjection, CognitiveFieldRole, CognitiveFieldRunContract,
    CognitiveFieldSuite, CognitiveFieldValidationReport, CognitiveHardGateEvidence,
    CognitiveHardGateKind, CognitiveJudgeResult, CognitiveMemoryCondition,
    CognitiveUnderstandingAnswer, CognitiveWorkerResult, ProjectId, TaskId, TaskIntentOracle,
    cognitive_judge_result_schema, cognitive_understanding_answer_schema,
    cognitive_worker_result_schema, inspect_secret_bytes,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;
use uuid::Uuid;

pub fn validate(suite_path: &Path) -> Result<()> {
    let (_, report, _) = load_and_validate_suite(suite_path)?;
    print_json(&report)?;
    ensure!(
        report.valid,
        "cognitive field suite failed validation: {}",
        report.errors.join("; ")
    );
    Ok(())
}

pub fn schema(kind: &str) -> Result<()> {
    let schema = match kind.trim().to_ascii_lowercase().as_str() {
        "worker" => cognitive_worker_result_schema()?,
        "reader" => cognitive_understanding_answer_schema()?,
        "judge" => cognitive_judge_result_schema()?,
        other => {
            bail!("unsupported cognitive field schema {other}; expected worker, reader, or judge")
        }
    };
    print_json(&schema)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn prepare(
    suite_path: &Path,
    run_id: &str,
    primary_repository: &Path,
    second_repository: &Path,
    report_root: &Path,
    private_root: &Path,
) -> Result<()> {
    ensure!(!run_id.trim().is_empty(), "run_id must not be empty");
    let (suite, report, suite_bytes) = load_and_validate_suite(suite_path)?;
    ensure!(
        report.valid,
        "cognitive field suite failed validation: {}",
        report.errors.join("; ")
    );
    let primary = canonical_directory(primary_repository, "primary repository")?;
    let second = canonical_directory(second_repository, "second repository")?;
    ensure!(
        primary != second,
        "second repository must differ from primary"
    );
    ensure!(
        second.join("Cargo.toml").is_file(),
        "second repository must be a real Rust repository with Cargo.toml"
    );
    ensure!(
        permissive_license_declared(&second)?,
        "second repository must declare MIT, Apache-2.0, BSD-2-Clause, or BSD-3-Clause"
    );
    let primary_commit = git_commit(&primary)?;
    let second_commit = git_commit(&second)?;

    let report_root = absolute_path(report_root)?;
    let private_root = absolute_path(private_root)?;
    ensure!(
        !private_root.starts_with(&primary) && !private_root.starts_with(&second),
        "private certification root must remain outside both Git repositories"
    );
    fs::create_dir_all(&report_root)?;
    fs::create_dir_all(private_root.join("oracles"))?;
    let canonical_private_root = fs::canonicalize(&private_root)?;

    let suite_sha256 = sha256_bytes(&suite_bytes);
    let private_root_sha256 = sha256_bytes(canonical_path(&canonical_private_root).as_bytes());
    let contract_path = report_root.join("contract.json");
    let existing_contract = contract_path
        .is_file()
        .then(|| read_json::<CognitiveFieldRunContract>(&contract_path))
        .transpose()?;
    let mut contract = CognitiveFieldRunContract {
        schema_version: COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        suite_sha256,
        source_commit: primary_commit,
        primary_repository: canonical_path(&primary),
        second_repository: canonical_path(&second),
        second_repository_commit: second_commit,
        output_root: canonical_path(&report_root),
        private_root_sha256,
        hard_provider_call_cap: suite.hard_provider_call_cap,
        contract_hash: String::new(),
        sealed_at: existing_contract
            .as_ref()
            .map_or_else(OffsetDateTime::now_utc, |existing| existing.sealed_at),
    };
    contract.contract_hash =
        CognitiveFieldGradingService::hash_json(&contract_without_hash(&contract))?;
    if let Some(existing) = existing_contract {
        ensure!(
            existing == contract,
            "existing sealed contract differs from the resumed prepare request"
        );
        contract = existing;
    }
    let mut plan = CognitiveFieldPlan {
        schema_version: COGNITIVE_FIELD_PLAN_SCHEMA_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        contract_hash: contract.contract_hash.clone(),
        items: suite
            .cases
            .iter()
            .map(|case| CognitiveFieldPlanItem {
                case_id: case.case_id.clone(),
                tier: case.tier,
                model_backed: case.model_backed,
                roles: case.required_roles.clone(),
                memory_conditions: case.memory_conditions.clone(),
                oracle_ref: case.oracle_ref.clone(),
                deterministic_verifier_refs: case.deterministic_verifier_refs.clone(),
            })
            .collect(),
        planned_provider_calls: suite.hard_provider_call_cap,
        hard_provider_call_cap: suite.hard_provider_call_cap,
        plan_hash: String::new(),
    };
    plan.plan_hash = CognitiveFieldGradingService::hash_json(&plan_without_hash(&plan))?;

    let suite_root = suite_path
        .parent()
        .context("field suite path has no parent")?;
    let worker_prompt = fs::read(suite_root.join("templates/worker-prompt.txt"))?;
    let reader_prompt = fs::read(suite_root.join("templates/reader-prompt.txt"))?;
    let reader_schema = fs::read(suite_root.join(&suite.reader_output_schema_ref))?;
    let mut leak_reports = Vec::new();
    for (index, case) in suite.cases.iter().enumerate() {
        let mut oracle = generated_oracle(case, index, &contract, &suite_bytes);
        CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
        let scan = CognitiveFieldGradingService::scan_reader_surfaces(
            &oracle,
            &[
                ("worker-prompt".to_owned(), worker_prompt.clone()),
                ("reader-prompt".to_owned(), reader_prompt.clone()),
                ("reader-output-schema".to_owned(), reader_schema.clone()),
                ("suite-manifest".to_owned(), suite_bytes.clone()),
            ],
        );
        ensure!(
            scan.clean,
            "reader pre-dispatch surface leaked hidden oracle values for {}",
            case.case_id
        );
        leak_reports.push(json!({
            "case_id": case.case_id,
            "clean": scan.clean,
            "scanned_surfaces": scan.scanned_surfaces,
            "finding_count": scan.findings.len(),
        }));
        write_new_or_same_json(
            &private_root
                .join("oracles")
                .join(format!("{}.json", case.case_id)),
            &oracle,
        )?;
    }

    write_new_or_same(&report_root.join("suite.json"), &suite_bytes)?;
    write_new_or_same_json(&contract_path, &contract)?;
    write_new_or_same_json(&report_root.join("plan.json"), &plan)?;
    write_new_or_same_json(
        &report_root.join("preflight.json"),
        &json!({
            "schema_version": "eliot-cognitive-field-preflight-v1",
            "run_id": run_id,
            "suite_valid": true,
            "case_count": suite.cases.len(),
            "oracle_count": leak_reports.len(),
            "reader_surface_scans": leak_reports,
            "private_root_sha256": contract.private_root_sha256,
            "provider_calls": 0,
        }),
    )?;
    print_json(&json!({
        "status": "prepared",
        "run_id": run_id,
        "contract_hash": contract.contract_hash,
        "plan_hash": plan.plan_hash,
        "source_commit": contract.source_commit,
        "second_repository_commit": contract.second_repository_commit,
        "case_count": suite.cases.len(),
        "provider_calls": 0,
        "report_root": report_root,
        "private_root_sha256": contract.private_root_sha256,
    }))
}

#[allow(clippy::too_many_lines)]
pub fn record_deterministic(
    report_root: &Path,
    private_root: &Path,
    case_id: &str,
    memory_condition: &str,
    receipt_path: &Path,
) -> Result<()> {
    let report_root = canonical_directory(report_root, "cognitive report root")?;
    let private_root = canonical_directory(private_root, "private certification root")?;
    let receipt_path = fs::canonicalize(receipt_path)
        .with_context(|| format!("resolve deterministic receipt {}", receipt_path.display()))?;
    ensure!(
        receipt_path.starts_with(&private_root),
        "deterministic receipt must remain inside the private certification root"
    );
    let suite: CognitiveFieldSuite = read_json(&report_root.join("suite.json"))?;
    let contract: CognitiveFieldRunContract = read_json(&report_root.join("contract.json"))?;
    ensure!(
        contract_path_matches(&report_root, &contract.output_root),
        "report root differs from the sealed contract"
    );
    ensure!(
        contract_private_root_matches(&private_root, &contract.private_root_sha256),
        "private certification root does not match the sealed contract"
    );
    ensure!(
        git_commit(Path::new(&contract.primary_repository))? == contract.source_commit,
        "primary repository HEAD moved after the field contract was sealed"
    );
    let case = suite
        .cases
        .iter()
        .find(|case| case.case_id == case_id)
        .with_context(|| format!("unknown cognitive field case {case_id}"))?;
    let condition = parse_condition(memory_condition)?;
    ensure!(
        execution_conditions(case).contains(&condition),
        "memory condition {memory_condition} is not planned for {case_id}"
    );
    let receipt: CognitiveDeterministicEvidenceReceipt = read_json(&receipt_path)?;
    validate_deterministic_receipt(&contract, case, condition, &private_root, &receipt)?;
    let receipt_hash = CognitiveFieldGradingService::hash_json(&receipt)?;
    let binding = format!(
        "{}:{}:{}:{}",
        contract.run_id,
        case.case_id,
        condition_name(condition),
        contract.source_commit
    );
    let (project_id, task_id) = stable_binding_ids(&binding);
    let gate_evidence = CognitiveHardGateKind::ALL
        .into_iter()
        .map(|gate| CognitiveHardGateEvidence {
            gate,
            passed: true,
            evidence_refs: vec![
                format!("deterministic-receipt:{receipt_hash}"),
                format!("contract:{}", contract.contract_hash),
            ],
            explanation: format!(
                "The sealed verifier receipt and field contract satisfy the {gate:?} hard gate"
            ),
        })
        .collect();
    let mut report = CognitiveDeterministicReport {
        schema_version: COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION.to_owned(),
        case_id: case.case_id.clone(),
        project_id,
        task_id,
        source_commit: contract.source_commit.clone(),
        verifier_refs: receipt.verifier_refs.clone(),
        hard_gate_evidence: gate_evidence,
        controller_provider_calls: receipt.controller_provider_calls,
        truth_revision_before: receipt.truth_revision_before.clone(),
        truth_revision_after_observability: receipt.truth_revision_after_observability.clone(),
        report_hash: String::new(),
        passed: true,
    };
    CognitiveFieldGradingService::seal_deterministic_report(&mut report)?;
    let evidence_root = report_root
        .join("evidence")
        .join(&case.case_id)
        .join(condition_name(condition));
    write_new_or_same_json(&evidence_root.join("deterministic.json"), &report)?;
    write_new_or_same_json(
        &evidence_root.join("verifier-receipt.json"),
        &json!({
            "schema_version": "eliot-cognitive-sanitized-verifier-receipt-v1",
            "run_id": receipt.run_id,
            "case_id": receipt.case_id,
            "memory_condition": receipt.memory_condition,
            "source_commit": receipt.source_commit,
            "verifier_refs": receipt.verifier_refs,
            "commands": receipt.commands.iter().map(|command| json!({
                "command_ref": command.command_ref,
                "arguments_sha256": command.arguments_sha256,
                "exit_code": command.exit_code,
                "elapsed_ms": command.elapsed_ms,
                "stdout_sha256": command.stdout_sha256,
                "stderr_sha256": command.stderr_sha256,
            })).collect::<Vec<_>>(),
            "controller_provider_calls": receipt.controller_provider_calls,
            "truth_revision_before": receipt.truth_revision_before,
            "truth_revision_after_observability": receipt.truth_revision_after_observability,
            "private_receipt_hash": receipt_hash,
        }),
    )?;
    print_json(&json!({
        "status": "deterministic_evidence_recorded",
        "run_id": contract.run_id,
        "case_id": case.case_id,
        "memory_condition": condition_name(condition),
        "deterministic_report_hash": report.report_hash,
        "private_receipt_hash": receipt_hash,
        "provider_calls": 0,
    }))
}

pub fn seal_provider_plan(
    report_root: &Path,
    private_root: &Path,
    calls_path: &Path,
) -> Result<()> {
    let report_root = canonical_directory(report_root, "cognitive report root")?;
    let private_root = canonical_directory(private_root, "private certification root")?;
    let calls_path = fs::canonicalize(calls_path)
        .with_context(|| format!("resolve provider calls {}", calls_path.display()))?;
    ensure!(
        calls_path.starts_with(&private_root) && calls_path.is_file(),
        "provider calls must be a file inside the private certification root"
    );
    let suite: CognitiveFieldSuite = read_json(&report_root.join("suite.json"))?;
    let contract: CognitiveFieldRunContract = read_json(&report_root.join("contract.json"))?;
    validate_report_roots(&contract, &report_root, &private_root)?;
    ensure!(
        git_commit(Path::new(&contract.primary_repository))? == contract.source_commit,
        "primary repository HEAD moved after the field contract was sealed"
    );
    ensure_deterministic_evidence_complete(&suite, &report_root)?;

    let calls: Vec<CognitiveFieldProviderCallPlan> = read_json(&calls_path)?;
    let (planned_provider_calls, planned_smoke_calls) =
        validate_provider_calls(&suite, &calls, &private_root)?;
    let plan_path = report_root.join("provider-plan.json");
    let existing = plan_path
        .is_file()
        .then(|| read_json::<CognitiveFieldProviderPlan>(&plan_path))
        .transpose()?;
    let mut plan = CognitiveFieldProviderPlan {
        schema_version: COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION.to_owned(),
        run_id: contract.run_id.clone(),
        contract_hash: contract.contract_hash.clone(),
        calls,
        planned_provider_calls,
        planned_smoke_calls,
        plan_hash: String::new(),
        sealed_at: existing
            .as_ref()
            .map_or_else(OffsetDateTime::now_utc, |plan| plan.sealed_at),
    };
    plan.plan_hash = CognitiveFieldGradingService::hash_json(&provider_plan_without_hash(&plan))?;
    if let Some(existing) = existing {
        ensure!(
            existing == plan,
            "existing sealed provider plan differs from the requested call plan"
        );
        plan = existing;
    }
    write_new_or_same_json(&plan_path, &plan)?;
    print_json(&json!({
        "status": "provider_plan_sealed",
        "run_id": contract.run_id,
        "provider_plan_hash": plan.plan_hash,
        "planned_provider_calls": plan.planned_provider_calls,
        "planned_smoke_calls": plan.planned_smoke_calls,
        "total_calls": plan.calls.len(),
    }))
}

#[allow(clippy::too_many_lines)]
pub fn record_provider(report_root: &Path, private_root: &Path, receipt_path: &Path) -> Result<()> {
    let report_root = canonical_directory(report_root, "cognitive report root")?;
    let private_root = canonical_directory(private_root, "private certification root")?;
    let receipt_path = fs::canonicalize(receipt_path)
        .with_context(|| format!("resolve provider receipt {}", receipt_path.display()))?;
    ensure!(
        receipt_path.starts_with(&private_root) && receipt_path.is_file(),
        "provider receipt must be a file inside the private certification root"
    );
    let suite: CognitiveFieldSuite = read_json(&report_root.join("suite.json"))?;
    let contract: CognitiveFieldRunContract = read_json(&report_root.join("contract.json"))?;
    let plan: CognitiveFieldProviderPlan = read_json(&report_root.join("provider-plan.json"))?;
    validate_report_roots(&contract, &report_root, &private_root)?;
    ensure!(
        git_commit(Path::new(&contract.primary_repository))? == contract.source_commit,
        "primary repository HEAD moved after the field contract was sealed"
    );
    validate_provider_plan_hash(&plan)?;
    let receipt_bytes = fs::read(&receipt_path)?;
    enforce_provider_secret_boundary("provider receipt", &receipt_bytes)?;
    let receipt: CognitiveFieldProviderEvidenceReceipt = serde_json::from_slice(&receipt_bytes)?;
    ensure!(
        receipt.schema_version == COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION,
        "provider evidence schema version is invalid"
    );
    ensure!(
        receipt.run_id == contract.run_id
            && receipt.contract_hash == contract.contract_hash
            && receipt.provider_plan_hash == plan.plan_hash
            && receipt.source_commit == contract.source_commit,
        "provider evidence differs from the sealed run authority"
    );
    let call = plan
        .calls
        .iter()
        .find(|call| call.call_id == receipt.call_id)
        .with_context(|| {
            format!(
                "provider call {} is not in the sealed plan",
                receipt.call_id
            )
        })?;
    validate_provider_receipt_envelope(call, &receipt, &private_root)?;

    let mut output_receipts = receipt
        .outputs
        .iter()
        .map(|output| (output.execution.clone(), output))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        output_receipts.len() == receipt.outputs.len()
            && output_receipts.keys().eq(call.executions.iter()),
        "provider outputs do not exactly match the sealed call executions"
    );

    let prompt_bytes = fs::read(private_file(
        &private_root,
        &receipt.prompt_path,
        &receipt.prompt_sha256,
        "provider prompt",
    )?)?;
    let raw_stdout = fs::read(private_file(
        &private_root,
        &receipt.raw_stdout_path,
        &receipt.raw_stdout_sha256,
        "provider stdout",
    )?)?;
    let raw_stderr = fs::read(private_file(
        &private_root,
        &receipt.raw_stderr_path,
        &receipt.raw_stderr_sha256,
        "provider stderr",
    )?)?;
    enforce_provider_secret_boundary("provider prompt", &prompt_bytes)?;
    enforce_provider_secret_boundary("provider stdout", &raw_stdout)?;
    enforce_provider_secret_boundary("provider stderr", &raw_stderr)?;
    let stdout_text = String::from_utf8_lossy(&raw_stdout);
    for required in [
        receipt.resolved_model.as_str(),
        receipt.provider_session_id.as_str(),
        receipt.provider_receipt_ref.as_str(),
    ] {
        ensure!(
            stdout_text.contains(required),
            "provider stdout does not attest the exact model/session/receipt identity"
        );
    }

    let mut admitted = Vec::with_capacity(call.executions.len());
    for execution in &call.executions {
        let output = output_receipts
            .remove(execution)
            .context("sealed provider output is missing")?;
        let output_path = private_file(
            &private_root,
            &output.output_path,
            &output.output_sha256,
            "provider structured output",
        )?;
        let bytes = fs::read(&output_path)?;
        enforce_provider_secret_boundary("provider structured output", &bytes)?;
        let evidence_root = report_root
            .join("evidence")
            .join(&execution.case_id)
            .join(condition_name(execution.memory_condition));
        let deterministic: CognitiveDeterministicReport =
            read_json(&evidence_root.join("deterministic.json"))?;
        ensure!(
            deterministic_report_is_valid(&deterministic)?,
            "provider output is bound to invalid deterministic evidence"
        );
        let case = suite
            .cases
            .iter()
            .find(|case| case.case_id == execution.case_id)
            .context("provider output case is absent from the suite")?;
        let oracle: TaskIntentOracle = read_json(
            &private_root
                .join("oracles")
                .join(format!("{}.json", case.case_id)),
        )?;
        if receipt.role != CognitiveFieldRole::CodexJudge {
            let leak = CognitiveFieldGradingService::scan_reader_surfaces(
                &oracle,
                &[
                    ("provider-prompt".to_owned(), prompt_bytes.clone()),
                    ("provider-stdout".to_owned(), raw_stdout.clone()),
                    ("provider-output".to_owned(), bytes.clone()),
                ],
            );
            ensure!(
                leak.clean,
                "Worker/Reader provider surface contains private oracle values"
            );
        }
        let (target_name, reader_binding) = match receipt.role {
            CognitiveFieldRole::CodexWorker => {
                let worker: CognitiveWorkerResult = serde_json::from_slice(&bytes)?;
                validate_worker_output(&worker, execution, case, &deterministic)?;
                ("worker.json", None)
            }
            CognitiveFieldRole::UnderstandingReader => {
                let reader: CognitiveUnderstandingAnswer = serde_json::from_slice(&bytes)?;
                validate_reader_output(&reader, execution, &deterministic)?;
                (
                    "reader.json",
                    Some(json!({
                        "schema_version": "eliot-cognitive-reader-binding-v1",
                        "run_id": contract.run_id,
                        "source_commit": contract.source_commit,
                        "case_id": execution.case_id,
                        "memory_condition": condition_name(execution.memory_condition),
                        "reader_output_hash":
                            CognitiveFieldGradingService::hash_json(&reader)?,
                        "reader_output_sha256": output.output_sha256,
                    })),
                )
            }
            CognitiveFieldRole::CodexJudge => {
                let judge: CognitiveJudgeResult = serde_json::from_slice(&bytes)?;
                validate_judge_output(&judge, execution, &oracle, &deterministic)?;
                ("judge.json", None)
            }
        };
        admitted.push((
            evidence_root,
            target_name,
            bytes,
            output.output_sha256.clone(),
            reader_binding,
        ));
    }

    let invocation_path = report_root
        .join("provider-invocations")
        .join(format!("{}.json", call.call_id));
    let existing = invocation_path
        .is_file()
        .then(|| read_json::<CognitiveFieldProviderProjection>(&invocation_path))
        .transpose()?;
    let projection = CognitiveFieldProviderProjection {
        schema_version: COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION.to_owned(),
        run_id: contract.run_id.clone(),
        contract_hash: contract.contract_hash.clone(),
        provider_plan_hash: plan.plan_hash.clone(),
        source_commit: contract.source_commit.clone(),
        call_id: call.call_id.clone(),
        role: call.role,
        host: call.host,
        requested_model: call.requested_model.clone(),
        resolved_model: receipt.resolved_model.clone(),
        provider_session_id: receipt.provider_session_id.clone(),
        provider_receipt_ref: receipt.provider_receipt_ref.clone(),
        provider_executable_sha256: receipt.provider_executable_sha256.clone(),
        prompt_sha256: receipt.prompt_sha256.clone(),
        raw_stdout_sha256: receipt.raw_stdout_sha256.clone(),
        raw_stderr_sha256: receipt.raw_stderr_sha256.clone(),
        outputs: call
            .executions
            .iter()
            .map(|execution| {
                let output_sha256 = receipt
                    .outputs
                    .iter()
                    .find(|output| output.execution == *execution)
                    .map(|output| output.output_sha256.clone())
                    .unwrap_or_default();
                CognitiveFieldProviderOutputProjection {
                    execution: execution.clone(),
                    output_sha256,
                }
            })
            .collect(),
        provider_smoke: call.provider_smoke,
        counts_against_cap: call.counts_against_cap,
        elapsed_ms: receipt.elapsed_ms,
        recorded_at: existing
            .as_ref()
            .map_or_else(OffsetDateTime::now_utc, |projection| projection.recorded_at),
    };
    if let Some(existing) = existing {
        ensure!(
            existing == projection,
            "provider invocation already exists with different evidence"
        );
    }
    write_new_or_same_json(&invocation_path, &projection)?;
    for (evidence_root, target_name, bytes, _, reader_binding) in &admitted {
        write_new_or_same(&evidence_root.join(target_name), bytes)?;
        if let Some(reader_binding) = reader_binding {
            write_new_or_same_json(&evidence_root.join("reader-binding.json"), reader_binding)?;
        }
        write_new_or_same_json(
            &evidence_root.join(format!("provider-{}.json", role_name(call.role))),
            &projection,
        )?;
    }
    print_json(&json!({
        "status": "provider_evidence_recorded",
        "run_id": contract.run_id,
        "call_id": call.call_id,
        "role": role_name(call.role),
        "host": call.host.as_str(),
        "resolved_model": receipt.resolved_model,
        "execution_count": admitted.len(),
        "counts_against_cap": call.counts_against_cap,
        "provider_smoke": call.provider_smoke,
    }))
}

#[allow(clippy::too_many_lines)]
pub fn grade(report_root: &Path, private_root: &Path) -> Result<()> {
    let report_root = canonical_directory(report_root, "cognitive report root")?;
    let private_root = canonical_directory(private_root, "private certification root")?;
    let suite: CognitiveFieldSuite = read_json(&report_root.join("suite.json"))?;
    let contract: CognitiveFieldRunContract = read_json(&report_root.join("contract.json"))?;
    let validation = CognitiveFieldGradingService::validate_suite(&suite);
    ensure!(
        validation.valid,
        "stored suite is invalid: {}",
        validation.errors.join("; ")
    );
    validate_report_roots(&contract, &report_root, &private_root)?;
    let provider_plan = report_root
        .join("provider-plan.json")
        .is_file()
        .then(|| read_json::<CognitiveFieldProviderPlan>(&report_root.join("provider-plan.json")))
        .transpose()?;
    if let Some(plan) = &provider_plan {
        validate_provider_plan_hash(plan)?;
        ensure!(
            plan.run_id == contract.run_id && plan.contract_hash == contract.contract_hash,
            "provider plan differs from the sealed run contract"
        );
        let (capped, smokes) = validate_provider_calls(&suite, &plan.calls, &private_root)?;
        ensure!(
            capped == plan.planned_provider_calls && smokes == plan.planned_smoke_calls,
            "provider plan summary counts are invalid"
        );
    }
    let provider_invocations = load_provider_projections(&report_root)?;
    let actual_provider_calls = provider_invocations
        .values()
        .filter(|projection| projection.counts_against_cap)
        .count();
    let actual_smoke_calls = provider_invocations
        .values()
        .filter(|projection| projection.provider_smoke)
        .count();
    let provider_plan_complete = provider_plan.as_ref().is_some_and(|plan| {
        let planned = plan
            .calls
            .iter()
            .map(|call| call.call_id.as_str())
            .collect::<BTreeSet<_>>();
        let recorded = provider_invocations
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        planned == recorded
            && actual_provider_calls == usize::from(plan.planned_provider_calls)
            && actual_smoke_calls == usize::from(plan.planned_smoke_calls)
            && actual_provider_calls <= usize::from(contract.hard_provider_call_cap)
    });

    let mut deterministic_results = Vec::new();
    let mut judge_results = Vec::new();
    let mut expected_executions = 0usize;
    let mut passed_executions = 0usize;
    let mut missing_executions = 0usize;
    let mut semantic_scores = Vec::new();
    for case in &suite.cases {
        let conditions = execution_conditions(case);
        for condition in conditions {
            expected_executions = expected_executions.saturating_add(1);
            let condition_name = condition_name(condition);
            let evidence_root = report_root
                .join("evidence")
                .join(&case.case_id)
                .join(condition_name);
            let deterministic_path = evidence_root.join("deterministic.json");
            if !deterministic_path.is_file() {
                missing_executions = missing_executions.saturating_add(1);
                deterministic_results.push(json!({
                    "case_id": case.case_id,
                    "memory_condition": condition_name,
                    "status": "not_run",
                }));
                continue;
            }
            let deterministic: CognitiveDeterministicReport = read_json(&deterministic_path)?;
            let deterministic_valid = deterministic_report_is_valid(&deterministic)?;
            deterministic_results.push(json!({
                "case_id": case.case_id,
                "memory_condition": condition_name,
                "status": if deterministic_valid { "passed" } else { "failed" },
                "report_hash": deterministic.report_hash,
                "verifier_refs": deterministic.verifier_refs,
            }));
            if !case.model_backed {
                if deterministic_valid {
                    passed_executions = passed_executions.saturating_add(1);
                }
                continue;
            }
            let worker_path = evidence_root.join("worker.json");
            let reader_path = evidence_root.join("reader.json");
            let judge_path = evidence_root.join("judge.json");
            if provider_plan.is_none()
                || !worker_path.is_file()
                || !reader_path.is_file()
                || !judge_path.is_file()
            {
                missing_executions = missing_executions.saturating_add(1);
                judge_results.push(json!({
                    "case_id": case.case_id,
                    "memory_condition": condition_name,
                    "status": "not_run",
                    "reason": "sealed Worker/Reader/Judge provider evidence is incomplete",
                }));
                continue;
            }
            let execution = CognitiveFieldExecutionKey {
                case_id: case.case_id.clone(),
                memory_condition: condition,
            };
            let provider_errors = provider_role_errors(
                provider_plan
                    .as_ref()
                    .context("provider plan disappeared")?,
                &provider_invocations,
                &evidence_root,
                &execution,
            )?;
            if !provider_errors.is_empty() {
                judge_results.push(json!({
                    "case_id": case.case_id,
                    "memory_condition": condition_name,
                    "status": "failed",
                    "provider_role_errors": provider_errors,
                }));
                continue;
            }
            let worker: CognitiveWorkerResult = read_json(&worker_path)?;
            let reader: CognitiveUnderstandingAnswer = read_json(&reader_path)?;
            let judge: CognitiveJudgeResult = read_json(&judge_path)?;
            let oracle: TaskIntentOracle = read_json(
                &private_root
                    .join("oracles")
                    .join(format!("{}.json", case.case_id)),
            )?;
            validate_worker_output(&worker, &execution, case, &deterministic)?;
            validate_reader_output(&reader, &execution, &deterministic)?;
            validate_judge_output(&judge, &execution, &oracle, &deterministic)?;
            let grade = CognitiveFieldGradingService::grade_case(
                &suite,
                case,
                &oracle,
                &reader,
                &deterministic,
                &judge,
            );
            if grade.passed {
                passed_executions = passed_executions.saturating_add(1);
            }
            semantic_scores.push(grade.semantic_average_milli);
            judge_results.push(json!({
                "case_id": case.case_id,
                "memory_condition": condition_name,
                "status": if grade.passed { "passed" } else { "failed" },
                "grade": grade,
            }));
        }
    }

    let all_passed = missing_executions == 0
        && passed_executions == expected_executions
        && expected_executions > 0
        && provider_plan_complete;
    let median_semantic_milli = median(&mut semantic_scores);
    let status = if all_passed {
        "COGNITIVE_FIELD_CERTIFIED_INTERNAL_RC"
    } else {
        "MECHANISMS_COMPLETE_FIELD_CERTIFICATION_BLOCKED"
    };
    let metrics = json!({
        "schema_version": "eliot-cognitive-field-metrics-v1",
        "run_id": contract.run_id,
        "expected_executions": expected_executions,
        "passed_executions": passed_executions,
        "missing_executions": missing_executions,
        "median_semantic_milli": median_semantic_milli,
        "provider_call_cap": contract.hard_provider_call_cap,
        "provider_plan_sealed": provider_plan.is_some(),
        "provider_plan_complete": provider_plan_complete,
        "actual_provider_calls": actual_provider_calls,
        "actual_smoke_calls": actual_smoke_calls,
        "status": status,
    });
    crate::runtime_instance::atomic_write_json(
        &report_root.join("deterministic-results.json"),
        &deterministic_results,
    )?;
    crate::runtime_instance::atomic_write_json(
        &report_root.join("judge-results.json"),
        &judge_results,
    )?;
    crate::runtime_instance::atomic_write_json(&report_root.join("metrics.json"), &metrics)?;
    let markdown = render_report(
        &contract,
        status,
        expected_executions,
        passed_executions,
        missing_executions,
        median_semantic_milli,
        actual_provider_calls,
        actual_smoke_calls,
        provider_plan_complete,
    );
    crate::runtime_instance::atomic_write_bytes(
        &report_root.join("report.md"),
        markdown.as_bytes(),
    )?;
    print_json(&metrics)?;
    ensure!(all_passed, "cognitive field certification is incomplete");
    Ok(())
}

fn load_provider_projections(
    report_root: &Path,
) -> Result<BTreeMap<String, CognitiveFieldProviderProjection>> {
    let root = report_root.join("provider-invocations");
    if !root.is_dir() {
        return Ok(BTreeMap::new());
    }
    let mut projections = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        ensure!(
            path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("json"),
            "provider invocation registry contains a non-JSON entry"
        );
        let projection: CognitiveFieldProviderProjection = read_json(&path)?;
        ensure!(
            projection.schema_version == COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION
                && safe_segment(&projection.call_id)
                && projections
                    .insert(projection.call_id.clone(), projection)
                    .is_none(),
            "provider invocation registry contains invalid or duplicate evidence"
        );
    }
    Ok(projections)
}

fn provider_role_errors(
    plan: &CognitiveFieldProviderPlan,
    invocations: &BTreeMap<String, CognitiveFieldProviderProjection>,
    evidence_root: &Path,
    execution: &CognitiveFieldExecutionKey,
) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    let mut sessions = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    for role in [
        CognitiveFieldRole::CodexWorker,
        CognitiveFieldRole::UnderstandingReader,
        CognitiveFieldRole::CodexJudge,
    ] {
        let projection_path = evidence_root.join(format!("provider-{}.json", role_name(role)));
        if !projection_path.is_file() {
            errors.push(format!(
                "{} provider projection is missing",
                role_name(role)
            ));
            continue;
        }
        let projection: CognitiveFieldProviderProjection = read_json(&projection_path)?;
        let Some(call) = plan
            .calls
            .iter()
            .find(|call| call.call_id == projection.call_id)
        else {
            errors.push(format!(
                "{} projection references an unplanned call",
                role_name(role)
            ));
            continue;
        };
        let registered = invocations.get(&projection.call_id);
        let output = projection
            .outputs
            .iter()
            .find(|output| output.execution == *execution);
        let target = evidence_root.join(match role {
            CognitiveFieldRole::CodexWorker => "worker.json",
            CognitiveFieldRole::UnderstandingReader => "reader.json",
            CognitiveFieldRole::CodexJudge => "judge.json",
        });
        let output_hash_matches = output.is_some_and(|output| {
            target
                .is_file()
                .then(|| fs::read(&target).ok())
                .flatten()
                .is_some_and(|bytes| sha256_bytes(&bytes) == output.output_sha256)
        });
        if projection.schema_version != COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION
            || projection.provider_plan_hash != plan.plan_hash
            || projection.role != role
            || call.role != role
            || call.host != projection.host
            || call.requested_model != projection.requested_model
            || projection.requested_model != projection.resolved_model
            || !call.executions.contains(execution)
            || registered != Some(&projection)
            || !output_hash_matches
        {
            errors.push(format!(
                "{} provider projection failed its plan/session/output binding",
                role_name(role)
            ));
        }
        sessions.insert(projection.provider_session_id.clone());
        receipts.insert(projection.provider_receipt_ref.clone());
    }
    if sessions.len() != 3 {
        errors
            .push("Worker, Reader, and Judge must use three distinct provider sessions".to_owned());
    }
    if receipts.len() != 3 {
        errors.push(
            "Worker, Reader, and Judge must have three distinct provider receipts".to_owned(),
        );
    }
    Ok(errors)
}

fn load_and_validate_suite(
    suite_path: &Path,
) -> Result<(CognitiveFieldSuite, CognitiveFieldValidationReport, Vec<u8>)> {
    let suite_bytes =
        fs::read(suite_path).with_context(|| format!("read {}", suite_path.display()))?;
    let suite: CognitiveFieldSuite = serde_json::from_slice(&suite_bytes)?;
    let mut report = CognitiveFieldGradingService::validate_suite(&suite);
    let suite_root = suite_path
        .parent()
        .context("field suite path has no parent")?;
    let reader_schema = cognitive_understanding_answer_schema()?;
    validate_schema_asset(
        &mut report,
        &suite_root.join(&suite.reader_output_schema_ref),
        &reader_schema,
        "reader",
    );
    let judge_schema = cognitive_judge_result_schema()?;
    validate_schema_asset(
        &mut report,
        &suite_root.join(&suite.judge_output_schema_ref),
        &judge_schema,
        "judge",
    );
    if !suite_root.join("contamination-rules.json").is_file() {
        report
            .errors
            .push("contamination-rules.json is missing".to_owned());
    }
    if !suite_root.join("templates/worker-prompt.txt").is_file() {
        report.errors.push("worker prompt is missing".to_owned());
    }
    for case in &suite.cases {
        if !suite_root.join(&case.reader_prompt_ref).is_file() {
            report.errors.push(format!(
                "reader prompt for {} does not exist: {}",
                case.case_id, case.reader_prompt_ref
            ));
        }
    }
    report.valid = report.errors.is_empty();
    Ok((suite, report, suite_bytes))
}

fn validate_schema_asset(
    report: &mut CognitiveFieldValidationReport,
    path: &Path,
    generated: &Value,
    kind: &str,
) {
    let checked_in = fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let Some(checked_in) = checked_in else {
        report
            .errors
            .push(format!("{kind} output schema is missing or invalid"));
        return;
    };
    if required_set(&checked_in) != required_set(generated) {
        report.errors.push(format!(
            "{kind} output schema required fields differ from the Rust contract"
        ));
    }
}

fn required_set(value: &Value) -> BTreeSet<String> {
    value
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn generated_oracle(
    case: &CognitiveFieldCase,
    case_index: usize,
    contract: &CognitiveFieldRunContract,
    suite_bytes: &[u8],
) -> TaskIntentOracle {
    let private_ref = |kind: &str| {
        format!(
            "private-{kind}:{}",
            sha256_bytes(
                format!(
                    "{}:{}:{kind}:{}",
                    contract.run_id,
                    case.case_id,
                    sha256_bytes(suite_bytes)
                )
                .as_bytes()
            )
        )
    };
    let private_marker = format!(
        "PRIVATE-ORACLE-{}",
        sha256_bytes(format!("{}:{}", contract.run_id, case.case_id).as_bytes())
    );
    TaskIntentOracle {
        schema_version: COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION.to_owned(),
        oracle_id: format!("oracle:{}:{}", contract.run_id, case.case_id),
        exact_user_prompt_hash: sha256_bytes(case.title.as_bytes()),
        exact_user_prompt_ref: format!("suite.json#/cases/{case_index}/title"),
        source_commit: contract.source_commit.clone(),
        normalized_goal: case.title.clone(),
        desired_state: vec![format!("{} is satisfied with current evidence", case.title)],
        acceptance_items: vec![private_ref("acceptance")],
        non_goals: vec![
            "Do not substitute controller output for a provider role".to_owned(),
            "Do not promote candidate-only evidence to current truth".to_owned(),
        ],
        architecture_constraints: vec![
            "Current source and deterministic verifier evidence outrank memory".to_owned(),
            "Worker, Reader, and Judge sessions remain isolated".to_owned(),
        ],
        expected_subsystem_set: vec![private_ref("subsystem")],
        acceptable_owner_file_symbol_alternatives: vec![private_ref("owner-alternative")],
        required_invariant_refs: vec![private_ref("invariant")],
        required_verifier_refs: vec![private_ref("verifier")],
        forbidden_conclusions: vec![private_marker],
        authoritative_source_refs: vec![
            format!("git:{}", contract.source_commit),
            format!("suite:{}", case.case_id),
        ],
        oracle_hash: String::new(),
    }
}

fn execution_conditions(case: &CognitiveFieldCase) -> Vec<CognitiveMemoryCondition> {
    if case.model_backed {
        return case.memory_conditions.clone();
    }
    case.memory_conditions
        .first()
        .copied()
        .into_iter()
        .collect()
}

fn condition_name(condition: CognitiveMemoryCondition) -> &'static str {
    match condition {
        CognitiveMemoryCondition::Treatment => "treatment",
        CognitiveMemoryCondition::MemoryFreeControl => "memory_free_control",
        CognitiveMemoryCondition::RawCorpus => "raw_corpus",
        CognitiveMemoryCondition::DistilledCorpus => "distilled_corpus",
    }
}

fn parse_condition(value: &str) -> Result<CognitiveMemoryCondition> {
    match value.trim().to_ascii_lowercase().as_str() {
        "treatment" => Ok(CognitiveMemoryCondition::Treatment),
        "memory_free_control" => Ok(CognitiveMemoryCondition::MemoryFreeControl),
        "raw_corpus" => Ok(CognitiveMemoryCondition::RawCorpus),
        "distilled_corpus" => Ok(CognitiveMemoryCondition::DistilledCorpus),
        other => bail!("unsupported cognitive memory condition {other}"),
    }
}

fn role_name(role: CognitiveFieldRole) -> &'static str {
    match role {
        CognitiveFieldRole::CodexWorker => "worker",
        CognitiveFieldRole::UnderstandingReader => "reader",
        CognitiveFieldRole::CodexJudge => "judge",
    }
}

fn enforce_provider_secret_boundary(label: &str, bytes: &[u8]) -> Result<()> {
    inspect_secret_bytes(bytes)
        .map_err(|violation| anyhow::anyhow!("{label} failed secret boundary: {violation}"))
}

fn validate_report_roots(
    contract: &CognitiveFieldRunContract,
    report_root: &Path,
    private_root: &Path,
) -> Result<()> {
    ensure!(
        contract_path_matches(report_root, &contract.output_root),
        "report root differs from the sealed contract"
    );
    ensure!(
        contract_private_root_matches(private_root, &contract.private_root_sha256),
        "private certification root does not match the sealed contract"
    );
    Ok(())
}

fn ensure_deterministic_evidence_complete(
    suite: &CognitiveFieldSuite,
    report_root: &Path,
) -> Result<()> {
    for case in &suite.cases {
        for condition in execution_conditions(case) {
            let path = report_root
                .join("evidence")
                .join(&case.case_id)
                .join(condition_name(condition))
                .join("deterministic.json");
            ensure!(
                path.is_file(),
                "deterministic evidence is incomplete; missing {}",
                path.display()
            );
            let report: CognitiveDeterministicReport = read_json(&path)?;
            ensure!(
                deterministic_report_is_valid(&report)?,
                "deterministic evidence is invalid for {}",
                case.case_id
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_provider_calls(
    suite: &CognitiveFieldSuite,
    calls: &[CognitiveFieldProviderCallPlan],
    private_root: &Path,
) -> Result<(u8, u8)> {
    ensure!(!calls.is_empty(), "provider call plan must not be empty");
    let mut call_ids = BTreeSet::new();
    let mut observed =
        BTreeMap::<(String, CognitiveMemoryCondition, CognitiveFieldRole), u8>::new();
    let mut smoke_cases = BTreeSet::new();
    let mut capped = 0_u8;
    let mut smokes = 0_u8;
    for (index, call) in calls.iter().enumerate() {
        ensure!(
            usize::from(call.call_number) == index + 1,
            "provider call numbers must be contiguous and ordered from 1"
        );
        ensure!(
            safe_segment(&call.call_id) && call_ids.insert(call.call_id.clone()),
            "provider call_id is duplicate or unsafe"
        );
        ensure!(
            explicit_model_id(&call.requested_model),
            "provider model must be an explicit versioned ID, not a floating alias"
        );
        ensure!(
            is_sha256(&call.expected_provider_executable_sha256) && is_sha256(&call.prompt_sha256),
            "provider executable and prompt hashes must be SHA-256 values"
        );
        let prompt_path = private_relative_file(private_root, &call.prompt_ref, "provider prompt")?;
        ensure!(
            sha256_bytes(&fs::read(prompt_path)?) == call.prompt_sha256,
            "provider prompt hash differs from the sealed call plan"
        );
        ensure!(
            !call.executions.is_empty() && call.executions.windows(2).all(|pair| pair[0] < pair[1]),
            "provider call executions must be non-empty, unique, and sorted"
        );
        let memory_condition = call.executions[0].memory_condition;
        ensure!(
            call.executions
                .iter()
                .all(|execution| execution.memory_condition == memory_condition),
            "one provider call must not mix memory conditions"
        );
        match call.role {
            CognitiveFieldRole::CodexWorker | CognitiveFieldRole::CodexJudge => ensure!(
                call.host == AgentHostId::Codex,
                "Worker and Judge calls must use Codex-owned sessions"
            ),
            CognitiveFieldRole::UnderstandingReader => ensure!(
                matches!(
                    call.host,
                    AgentHostId::Claude | AgentHostId::Antigravity | AgentHostId::OpenCode
                ),
                "Reader calls must use Claude, Antigravity, or OpenCode"
            ),
        }
        ensure!(
            call.provider_smoke != call.counts_against_cap,
            "exactly one of provider_smoke or counts_against_cap must be true"
        );
        if call.counts_against_cap {
            capped = capped
                .checked_add(1)
                .context("provider call count overflow")?;
        } else {
            smokes = smokes
                .checked_add(1)
                .context("provider smoke count overflow")?;
            ensure!(
                call.executions.len() == 1,
                "a provider smoke must contain exactly one execution"
            );
            let execution = &call.executions[0];
            let expected_host = match execution.case_id.as_str() {
                "H01" => AgentHostId::Codex,
                "H02" => AgentHostId::Claude,
                "H03" => AgentHostId::Antigravity,
                "H04" => AgentHostId::OpenCode,
                _ => bail!("provider smoke must target H01, H02, H03, or H04"),
            };
            ensure!(
                call.host == expected_host && smoke_cases.insert(execution.case_id.clone()),
                "provider smoke host/case binding is invalid or duplicated"
            );
        }
        for execution in &call.executions {
            let case = suite
                .cases
                .iter()
                .find(|case| case.case_id == execution.case_id)
                .context("provider plan contains an unknown case")?;
            ensure!(
                case.model_backed
                    && execution_conditions(case).contains(&execution.memory_condition)
                    && case.required_roles.contains(&call.role),
                "provider plan execution is not admitted by the suite"
            );
            let count = observed
                .entry((
                    execution.case_id.clone(),
                    execution.memory_condition,
                    call.role,
                ))
                .or_default();
            *count = count.saturating_add(1);
        }
    }
    ensure!(
        capped <= suite.hard_provider_call_cap,
        "sealed provider plan exceeds the hard provider-call cap"
    );
    let expected_smokes = ["H01", "H02", "H03", "H04"]
        .into_iter()
        .filter(|case_id| suite.cases.iter().any(|case| case.case_id == *case_id))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    ensure!(
        smoke_cases == expected_smokes,
        "provider plan must contain one exact smoke for every configured live host case"
    );
    let mut expected = BTreeMap::new();
    for case in suite.cases.iter().filter(|case| case.model_backed) {
        for condition in execution_conditions(case) {
            for role in &case.required_roles {
                expected.insert((case.case_id.clone(), condition, *role), 1_u8);
            }
        }
    }
    ensure!(
        observed == expected,
        "provider plan must cover every model-backed execution role exactly once"
    );
    Ok((capped, smokes))
}

fn validate_provider_plan_hash(plan: &CognitiveFieldProviderPlan) -> Result<()> {
    ensure!(
        plan.schema_version == COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION,
        "provider plan schema version is invalid"
    );
    ensure!(
        CognitiveFieldGradingService::hash_json(&provider_plan_without_hash(plan))?
            == plan.plan_hash,
        "provider plan hash is invalid"
    );
    Ok(())
}

fn validate_provider_receipt_envelope(
    call: &CognitiveFieldProviderCallPlan,
    receipt: &CognitiveFieldProviderEvidenceReceipt,
    private_root: &Path,
) -> Result<()> {
    ensure!(
        receipt.role == call.role
            && receipt.host == call.host
            && receipt.requested_model == call.requested_model
            && receipt.resolved_model == call.requested_model,
        "provider role, host, or exact resolved model differs from the sealed call"
    );
    ensure!(
        !receipt.provider_session_id.trim().is_empty()
            && !receipt.provider_receipt_ref.trim().is_empty(),
        "provider-owned session and receipt identities are required"
    );
    ensure!(
        receipt.provider_calls == 1
            && receipt.exit_code == 0
            && receipt.elapsed_ms > 0
            && !receipt.timed_out
            && !receipt.unknown_outcome
            && !receipt.controller_substitution,
        "provider call did not end as one known successful provider-owned invocation"
    );
    ensure!(
        receipt.oracle_exposed == (receipt.role == CognitiveFieldRole::CodexJudge)
            && !receipt.worker_transcript_exposed,
        "provider role isolation flags are invalid"
    );
    if matches!(
        receipt.role,
        CognitiveFieldRole::UnderstandingReader | CognitiveFieldRole::CodexJudge
    ) {
        ensure!(
            receipt.read_only,
            "Reader and Judge sessions must be read-only"
        );
    }
    ensure!(
        receipt.provider_executable_sha256 == call.expected_provider_executable_sha256
            && is_sha256(&receipt.provider_executable_sha256),
        "provider executable hash differs from the sealed plan"
    );
    let executable = fs::canonicalize(&receipt.provider_executable)
        .context("resolve provider executable from evidence")?;
    ensure!(
        executable.is_file()
            && sha256_bytes(&fs::read(executable)?) == receipt.provider_executable_sha256,
        "provider executable no longer matches the sealed hash"
    );
    let prompt = private_file(
        private_root,
        &receipt.prompt_path,
        &receipt.prompt_sha256,
        "provider prompt",
    )?;
    let expected_prompt = private_relative_file(private_root, &call.prompt_ref, "provider prompt")?;
    ensure!(
        prompt == expected_prompt
            && receipt.prompt_sha256 == call.prompt_sha256
            && is_sha256(&receipt.prompt_sha256),
        "provider prompt differs from the sealed call"
    );
    ensure!(
        is_sha256(&receipt.raw_stdout_sha256)
            && is_sha256(&receipt.raw_stderr_sha256)
            && receipt.outputs.iter().all(|output| {
                is_sha256(&output.output_sha256) && call.executions.contains(&output.execution)
            }),
        "provider evidence contains an invalid output hash or execution"
    );
    Ok(())
}

fn validate_worker_output(
    worker: &CognitiveWorkerResult,
    execution: &CognitiveFieldExecutionKey,
    case: &CognitiveFieldCase,
    deterministic: &CognitiveDeterministicReport,
) -> Result<()> {
    ensure!(
        worker.schema_version == COGNITIVE_FIELD_WORKER_SCHEMA_VERSION
            && worker.case_id == execution.case_id
            && worker.memory_condition == execution.memory_condition
            && worker.project_id == deterministic.project_id
            && worker.task_id == deterministic.task_id,
        "Worker output binding is invalid"
    );
    ensure!(
        !worker.work_summary.trim().is_empty()
            && !worker.current_truth_refs.is_empty()
            && !worker.observation_refs.is_empty()
            && !worker.verifier_refs.is_empty()
            && !worker.next_state_ref.trim().is_empty(),
        "Worker output omits required governed task state"
    );
    ensure!(
        worker
            .verifier_refs
            .iter()
            .any(|reference| case.deterministic_verifier_refs.contains(reference)),
        "Worker output omits every registered case verifier"
    );
    if execution.memory_condition == CognitiveMemoryCondition::MemoryFreeControl {
        ensure!(
            worker.memory_handles_used.is_empty() && worker.influence_receipt_refs.is_empty(),
            "memory-free Worker output contains memory exposure or influence"
        );
    }
    if execution.case_id == "M08"
        && execution.memory_condition == CognitiveMemoryCondition::Treatment
    {
        ensure!(
            !worker.influence_receipt_refs.is_empty(),
            "M08 treatment requires a real influence receipt"
        );
    }
    Ok(())
}

fn validate_reader_output(
    reader: &CognitiveUnderstandingAnswer,
    execution: &CognitiveFieldExecutionKey,
    deterministic: &CognitiveDeterministicReport,
) -> Result<()> {
    ensure!(
        reader.schema_version == eliot_types::COGNITIVE_UNDERSTANDING_SCHEMA_VERSION
            && reader.case_id == execution.case_id
            && reader.memory_condition == execution.memory_condition
            && reader.project_id == deterministic.project_id
            && reader.task_id == deterministic.task_id,
        "Reader output binding is invalid"
    );
    if execution.memory_condition == CognitiveMemoryCondition::MemoryFreeControl {
        ensure!(
            reader.memory_handles_received.is_empty()
                && reader.memory_handles_expanded.is_empty()
                && reader.memory_handles_used.is_empty()
                && reader.influence_receipt_refs.is_empty(),
            "memory-free Reader output contains memory exposure or influence"
        );
    }
    Ok(())
}

fn validate_judge_output(
    judge: &CognitiveJudgeResult,
    execution: &CognitiveFieldExecutionKey,
    oracle: &TaskIntentOracle,
    deterministic: &CognitiveDeterministicReport,
) -> Result<()> {
    ensure!(
        judge.schema_version == eliot_types::COGNITIVE_JUDGE_SCHEMA_VERSION
            && judge.case_id == execution.case_id
            && judge.oracle_hash == oracle.oracle_hash
            && judge.deterministic_report_hash == deterministic.report_hash,
        "Judge output binding is invalid"
    );
    Ok(())
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn explicit_model_id(value: &str) -> bool {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    !value.is_empty()
        && value.bytes().any(|byte| byte.is_ascii_digit())
        && (value.contains('-') || value.contains('/'))
        && !matches!(
            lower.as_str(),
            "opus" | "sonnet" | "haiku" | "flash" | "pro" | "default" | "auto" | "latest"
        )
}

fn private_relative_file(private_root: &Path, relative: &str, label: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    ensure!(
        !relative.is_absolute()
            && relative
                .components()
                .all(|component| { matches!(component, std::path::Component::Normal(_)) }),
        "{label} ref must be a safe path relative to the private root"
    );
    let path = fs::canonicalize(private_root.join(relative))
        .with_context(|| format!("resolve {label} ref {}", relative.display()))?;
    ensure!(
        path.starts_with(private_root) && path.is_file(),
        "{label} ref escaped the private root or is not a file"
    );
    Ok(path)
}

fn private_file(
    private_root: &Path,
    value: &str,
    expected_sha256: &str,
    label: &str,
) -> Result<PathBuf> {
    let path = Path::new(value);
    let path = if path.is_absolute() {
        fs::canonicalize(path)
    } else {
        fs::canonicalize(private_root.join(path))
    }
    .with_context(|| format!("resolve {label} {value}"))?;
    ensure!(
        path.starts_with(private_root)
            && path.is_file()
            && sha256_bytes(&fs::read(&path)?) == expected_sha256,
        "{label} escaped the private root or failed its SHA-256 binding"
    );
    Ok(path)
}

fn validate_deterministic_receipt(
    contract: &CognitiveFieldRunContract,
    case: &CognitiveFieldCase,
    condition: CognitiveMemoryCondition,
    private_root: &Path,
    receipt: &CognitiveDeterministicEvidenceReceipt,
) -> Result<()> {
    ensure!(
        receipt.schema_version == COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION,
        "deterministic evidence schema version is invalid"
    );
    ensure!(
        receipt.run_id == contract.run_id
            && receipt.case_id == case.case_id
            && receipt.memory_condition == condition
            && receipt.source_commit == contract.source_commit,
        "deterministic evidence binding differs from the sealed plan"
    );
    ensure!(
        receipt.controller_provider_calls == 0,
        "controller substitution is forbidden in deterministic evidence"
    );
    ensure!(
        !receipt.truth_revision_before.trim().is_empty()
            && receipt.truth_revision_before == receipt.truth_revision_after_observability,
        "observability changed or omitted the truth revision"
    );
    let expected = case
        .deterministic_verifier_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed = receipt
        .verifier_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        expected == observed && expected.len() == receipt.verifier_refs.len(),
        "deterministic evidence does not exactly cover the registered verifier refs"
    );
    ensure!(
        !receipt.commands.is_empty(),
        "deterministic evidence has no command receipts"
    );
    for command in &receipt.commands {
        ensure!(
            !command.command_ref.trim().is_empty()
                && is_sha256(&command.arguments_sha256)
                && command.exit_code == 0
                && is_sha256(&command.stdout_sha256)
                && is_sha256(&command.stderr_sha256),
            "deterministic command receipt is incomplete or failed"
        );
        verify_private_log(private_root, &command.stdout_path, &command.stdout_sha256)?;
        verify_private_log(private_root, &command.stderr_path, &command.stderr_sha256)?;
    }
    Ok(())
}

fn verify_private_log(private_root: &Path, path: &str, expected_sha256: &str) -> Result<()> {
    let path = fs::canonicalize(path).with_context(|| format!("resolve private log {path}"))?;
    ensure!(
        path.starts_with(private_root) && path.is_file(),
        "verifier log must be a file inside the private certification root"
    );
    ensure!(
        sha256_bytes(&fs::read(&path)?) == expected_sha256,
        "verifier log hash mismatch for {}",
        path.display()
    );
    Ok(())
}

fn stable_binding_ids(binding: &str) -> (ProjectId, TaskId) {
    (
        ProjectId::from_uuid(stable_uuid(&format!("project:{binding}"))),
        TaskId::from_uuid(stable_uuid(&format!("task:{binding}"))),
    )
}

fn stable_uuid(value: &str) -> Uuid {
    let digest = Sha256::digest(value.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn deterministic_report_is_valid(report: &CognitiveDeterministicReport) -> Result<bool> {
    let original_hash = report.report_hash.clone();
    let original_passed = report.passed;
    let mut expected = report.clone();
    CognitiveFieldGradingService::seal_deterministic_report(&mut expected)?;
    Ok(original_passed && expected.passed && expected.report_hash == original_hash)
}

fn contract_without_hash(contract: &CognitiveFieldRunContract) -> CognitiveFieldRunContract {
    let mut material = contract.clone();
    material.contract_hash.clear();
    material
}

fn plan_without_hash(plan: &CognitiveFieldPlan) -> CognitiveFieldPlan {
    let mut material = plan.clone();
    material.plan_hash.clear();
    material
}

fn provider_plan_without_hash(plan: &CognitiveFieldProviderPlan) -> CognitiveFieldProviderPlan {
    let mut material = plan.clone();
    material.plan_hash.clear();
    material
}

fn git_commit(repository: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["-C"])
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .output()?;
    ensure!(
        output.status.success(),
        "git rev-parse failed for {}: {}",
        repository.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let commit = String::from_utf8(output.stdout)?.trim().to_owned();
    ensure!(
        commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "git returned a non-SHA commit for {}",
        repository.display()
    );
    Ok(commit)
}

fn permissive_license_declared(repository: &Path) -> Result<bool> {
    let manifest = fs::read_to_string(repository.join("Cargo.toml"))?.to_ascii_lowercase();
    if ["mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause"]
        .iter()
        .any(|license| manifest.contains(license))
    {
        return Ok(true);
    }
    for entry in fs::read_dir(repository)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if (name.starts_with("license") || name.starts_with("copying")) && entry.path().is_file() {
            let text = fs::read_to_string(entry.path())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if text.contains("mit license")
                || text.contains("apache license")
                || text.contains("bsd 2-clause")
                || text.contains("bsd 3-clause")
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_new_or_same_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new_or_same(path, &bytes)
}

fn write_new_or_same(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.is_file() {
        ensure!(
            fs::read(path)? == bytes,
            "sealed output already exists with different content: {}",
            path.display()
        );
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("{label} does not exist: {}", path.display()))?;
    ensure!(canonical.is_dir(), "{label} is not a directory");
    Ok(canonical)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

fn canonical_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        return format!("//{}", rest.replace('\\', "/"));
    }
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(&value)
        .replace('\\', "/")
}

fn legacy_canonical_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn contract_path_matches(path: &Path, expected: &str) -> bool {
    canonical_path(path) == expected || legacy_canonical_path(path) == expected
}

fn contract_private_root_matches(path: &Path, expected_sha256: &str) -> bool {
    [canonical_path(path), legacy_canonical_path(path)]
        .into_iter()
        .any(|value| sha256_bytes(value.as_bytes()) == expected_sha256)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn median(values: &mut [u16]) -> Option<u16> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        Some(
            values[middle - 1]
                .saturating_add(values[middle])
                .saturating_div(2),
        )
    } else {
        Some(values[middle])
    }
}

#[allow(clippy::too_many_arguments)]
fn render_report(
    contract: &CognitiveFieldRunContract,
    status: &str,
    expected: usize,
    passed: usize,
    missing: usize,
    semantic_median: Option<u16>,
    actual_provider_calls: usize,
    actual_smoke_calls: usize,
    provider_plan_complete: bool,
) -> String {
    format!(
        "# Cognitive field certification\n\n\
         - Status: `{status}`\n\
         - Run: `{run_id}`\n\
         - Source commit: `{source_commit}`\n\
         - Second repository commit: `{second_commit}`\n\
         - Expected executions: {expected}\n\
         - Passed executions: {passed}\n\
         - Missing executions: {missing}\n\
         - Median semantic score (milli-points): {semantic_median:?}\n\
         - Provider call cap: {provider_cap}\n\n\
         - Actual capped provider calls: {actual_provider_calls}\n\
         - Actual provider smokes: {actual_smoke_calls}\n\
         - Sealed provider plan complete: {provider_plan_complete}\n\n\
         Raw provider transcripts and private oracle material are not included in this report.\n",
        run_id = contract.run_id,
        source_commit = contract.source_commit,
        second_commit = contract.second_repository_commit,
        provider_cap = contract.hard_provider_call_cap,
    )
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    writeln!(stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        execution_conditions, generated_oracle, provider_plan_without_hash, record_provider,
        sha256_bytes, validate_deterministic_receipt, validate_provider_calls,
        validate_provider_receipt_envelope, write_new_or_same_json,
    };
    use eliot_engine::CognitiveFieldGradingService;
    use eliot_types::{
        AgentHostId, COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION,
        COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION, COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION,
        COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION,
        COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION, CognitiveDeterministicEvidenceReceipt,
        CognitiveDeterministicReport, CognitiveFieldExecutionKey, CognitiveFieldProviderCallPlan,
        CognitiveFieldProviderEvidenceReceipt, CognitiveFieldProviderOutputReceipt,
        CognitiveFieldProviderPlan, CognitiveFieldRole, CognitiveFieldRunContract,
        CognitiveFieldSuite, CognitiveHardGateEvidence, CognitiveMemoryCondition,
        CognitiveVerifierCommandReceipt, minimal_cognitive_understanding_answer,
    };
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[test]
    fn generated_private_oracle_values_are_absent_from_the_versioned_suite()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let suite_bytes = std::fs::read(root.join("tests/cognitive/field-v2/suite.json"))?;
        let suite: CognitiveFieldSuite = serde_json::from_slice(&suite_bytes)?;
        let contract = CognitiveFieldRunContract {
            schema_version: COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION.to_owned(),
            run_id: "preflight-test".to_owned(),
            suite_sha256: sha256_bytes(&suite_bytes),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            primary_repository: "C:/primary".to_owned(),
            second_repository: "C:/second".to_owned(),
            second_repository_commit: "fedcba9876543210fedcba9876543210fedcba98".to_owned(),
            output_root: "C:/reports".to_owned(),
            private_root_sha256: "private-root".to_owned(),
            hard_provider_call_cap: suite.hard_provider_call_cap,
            contract_hash: "contract".to_owned(),
            sealed_at: OffsetDateTime::UNIX_EPOCH,
        };
        for (index, case) in suite.cases.iter().enumerate() {
            let mut oracle = generated_oracle(case, index, &contract, &suite_bytes);
            CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
            let scan = CognitiveFieldGradingService::scan_reader_surfaces(
                &oracle,
                &[("suite-manifest".to_owned(), suite_bytes.clone())],
            );
            assert!(scan.clean, "{}: {:?}", case.case_id, scan.findings);
        }
        Ok(())
    }

    #[test]
    fn windows_verbatim_prefix_does_not_change_field_path_identity() {
        let ordinary = Path::new(r"C:\field\run");
        let verbatim = Path::new(r"\\?\C:\field\run");
        assert_eq!(
            super::canonical_path(ordinary),
            super::canonical_path(verbatim)
        );
        assert!(super::contract_path_matches(
            verbatim,
            &super::canonical_path(ordinary)
        ));
    }

    #[test]
    fn deterministic_receipt_requires_real_private_logs_and_exact_hashes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-cognitive-deterministic-receipt-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root)?;
        let stdout = root.join("stdout.log");
        let stderr = root.join("stderr.log");
        fs::write(&stdout, b"focused verifier passed\n")?;
        fs::write(&stderr, b"")?;
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let suite: CognitiveFieldSuite = serde_json::from_slice(&fs::read(
            suite_root.join("tests/cognitive/field-v2/suite.json"),
        )?)?;
        let case = suite
            .cases
            .iter()
            .find(|case| case.case_id == "U01")
            .ok_or("find U01")?;
        let contract = CognitiveFieldRunContract {
            schema_version: COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION.to_owned(),
            run_id: "receipt-test".to_owned(),
            suite_sha256: "0".repeat(64),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            primary_repository: "C:/primary".to_owned(),
            second_repository: "C:/second".to_owned(),
            second_repository_commit: "fedcba9876543210fedcba9876543210fedcba98".to_owned(),
            output_root: "C:/reports".to_owned(),
            private_root_sha256: sha256_bytes(root.to_string_lossy().as_bytes()),
            hard_provider_call_cap: suite.hard_provider_call_cap,
            contract_hash: "contract".to_owned(),
            sealed_at: OffsetDateTime::UNIX_EPOCH,
        };
        let mut receipt = CognitiveDeterministicEvidenceReceipt {
            schema_version: COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION.to_owned(),
            run_id: contract.run_id.clone(),
            case_id: case.case_id.clone(),
            memory_condition: CognitiveMemoryCondition::Treatment,
            source_commit: contract.source_commit.clone(),
            verifier_refs: case.deterministic_verifier_refs.clone(),
            commands: vec![CognitiveVerifierCommandReceipt {
                command_ref: "cargo:test/cognitive_field_grading".to_owned(),
                arguments_sha256: "1".repeat(64),
                exit_code: 0,
                elapsed_ms: 12,
                stdout_path: stdout.to_string_lossy().into_owned(),
                stdout_sha256: sha256_bytes(&fs::read(&stdout)?),
                stderr_path: stderr.to_string_lossy().into_owned(),
                stderr_sha256: sha256_bytes(&fs::read(&stderr)?),
            }],
            controller_provider_calls: 0,
            truth_revision_before: "revision:1".to_owned(),
            truth_revision_after_observability: "revision:1".to_owned(),
        };
        validate_deterministic_receipt(
            &contract,
            case,
            CognitiveMemoryCondition::Treatment,
            &fs::canonicalize(&root)?,
            &receipt,
        )?;
        receipt.commands[0].stdout_sha256 = "2".repeat(64);
        assert!(
            validate_deterministic_receipt(
                &contract,
                case,
                CognitiveMemoryCondition::Treatment,
                &fs::canonicalize(&root)?,
                &receipt,
            )
            .is_err()
        );
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn provider_plan_covers_three_isolated_roles_with_bounded_calls()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let suite: CognitiveFieldSuite = serde_json::from_slice(&fs::read(
            suite_root.join("tests/cognitive/field-v2/suite.json"),
        )?)?;
        let private_root =
            std::env::temp_dir().join(format!("eliot-cognitive-provider-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(private_root.join("prompts"))?;
        let private_root = fs::canonicalize(private_root)?;
        let mut calls = Vec::new();
        let mut by_role_condition = BTreeMap::<
            (CognitiveFieldRole, CognitiveMemoryCondition),
            Vec<CognitiveFieldExecutionKey>,
        >::new();
        let smoke_role = |case_id: &str| match case_id {
            "H01" => Some(CognitiveFieldRole::CodexWorker),
            "H02" | "H03" | "H04" => Some(CognitiveFieldRole::UnderstandingReader),
            _ => None,
        };
        for case in suite.cases.iter().filter(|case| case.model_backed) {
            for condition in execution_conditions(case) {
                for role in &case.required_roles {
                    if smoke_role(&case.case_id) == Some(*role)
                        && condition == CognitiveMemoryCondition::Treatment
                    {
                        continue;
                    }
                    by_role_condition
                        .entry((*role, condition))
                        .or_default()
                        .push(CognitiveFieldExecutionKey {
                            case_id: case.case_id.clone(),
                            memory_condition: condition,
                        });
                }
            }
        }
        for executions in by_role_condition.values_mut() {
            executions.sort();
        }
        let model = |host: AgentHostId| match host {
            AgentHostId::Codex => "gpt-5.6-codex",
            AgentHostId::Claude => "claude-opus-5",
            AgentHostId::Antigravity => "gemini-3-flash",
            AgentHostId::OpenCode => "openai/gpt-5.6-codex",
        };
        let mut add_call = |role: CognitiveFieldRole,
                            host: AgentHostId,
                            provider_smoke: bool,
                            executions: Vec<CognitiveFieldExecutionKey>|
         -> Result<(), Box<dyn std::error::Error>> {
            let call_number = u8::try_from(calls.len() + 1)?;
            let call_id = format!("field-call-{call_number:02}");
            let prompt_ref = format!("prompts/{call_id}.txt");
            let prompt = format!("{call_id} exact provider role prompt\n");
            fs::write(private_root.join(&prompt_ref), prompt.as_bytes())?;
            calls.push(CognitiveFieldProviderCallPlan {
                call_number,
                call_id,
                role,
                host,
                requested_model: model(host).to_owned(),
                expected_provider_executable_sha256: "a".repeat(64),
                prompt_ref,
                prompt_sha256: sha256_bytes(prompt.as_bytes()),
                provider_smoke,
                counts_against_cap: !provider_smoke,
                executions,
            });
            Ok(())
        };
        for (case_id, host, role) in [
            ("H01", AgentHostId::Codex, CognitiveFieldRole::CodexWorker),
            (
                "H02",
                AgentHostId::Claude,
                CognitiveFieldRole::UnderstandingReader,
            ),
            (
                "H03",
                AgentHostId::Antigravity,
                CognitiveFieldRole::UnderstandingReader,
            ),
            (
                "H04",
                AgentHostId::OpenCode,
                CognitiveFieldRole::UnderstandingReader,
            ),
        ] {
            add_call(
                role,
                host,
                true,
                vec![CognitiveFieldExecutionKey {
                    case_id: case_id.to_owned(),
                    memory_condition: CognitiveMemoryCondition::Treatment,
                }],
            )?;
        }
        for role in [
            CognitiveFieldRole::CodexWorker,
            CognitiveFieldRole::UnderstandingReader,
            CognitiveFieldRole::CodexJudge,
        ] {
            let host = if role == CognitiveFieldRole::UnderstandingReader {
                AgentHostId::Claude
            } else {
                AgentHostId::Codex
            };
            for (condition, target_chunks) in [
                (CognitiveMemoryCondition::Treatment, 4_usize),
                (CognitiveMemoryCondition::MemoryFreeControl, 2),
                (CognitiveMemoryCondition::RawCorpus, 1),
                (CognitiveMemoryCondition::DistilledCorpus, 1),
            ] {
                let executions = by_role_condition
                    .remove(&(role, condition))
                    .ok_or("missing role/condition executions")?;
                let chunk_size = executions.len().div_ceil(target_chunks);
                for chunk in executions.chunks(chunk_size) {
                    add_call(role, host, false, chunk.to_vec())?;
                }
            }
        }
        let (capped, smokes) = validate_provider_calls(&suite, &calls, &private_root)?;
        assert_eq!(capped, suite.hard_provider_call_cap);
        assert_eq!(smokes, 4);
        assert_eq!(usize::from(capped) + usize::from(smokes), calls.len());

        calls[0].requested_model = "opus".to_owned();
        assert!(validate_provider_calls(&suite, &calls, &private_root).is_err());
        fs::remove_dir_all(&private_root)?;
        Ok(())
    }

    #[test]
    fn provider_receipt_rejects_aliases_unknown_outcomes_and_binary_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let private_root = std::env::temp_dir().join(format!(
            "eliot-cognitive-provider-receipt-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(private_root.join("prompts"))?;
        let executable = private_root.join("claude.exe");
        let prompt = private_root.join("prompts/reader-01.txt");
        fs::write(&executable, b"provider executable fixture")?;
        fs::write(&prompt, b"isolated reader prompt")?;
        let private_root = fs::canonicalize(private_root)?;
        let execution = CognitiveFieldExecutionKey {
            case_id: "U01".to_owned(),
            memory_condition: CognitiveMemoryCondition::Treatment,
        };
        let model = "claude-opus-5";
        let executable_sha256 = sha256_bytes(&fs::read(&executable)?);
        let prompt_sha256 = sha256_bytes(&fs::read(&prompt)?);
        let call = CognitiveFieldProviderCallPlan {
            call_number: 1,
            call_id: "reader-01".to_owned(),
            role: CognitiveFieldRole::UnderstandingReader,
            host: AgentHostId::Claude,
            requested_model: model.to_owned(),
            expected_provider_executable_sha256: executable_sha256.clone(),
            prompt_ref: "prompts/reader-01.txt".to_owned(),
            prompt_sha256: prompt_sha256.clone(),
            provider_smoke: false,
            counts_against_cap: true,
            executions: vec![execution.clone()],
        };
        let mut receipt = CognitiveFieldProviderEvidenceReceipt {
            schema_version: eliot_types::COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION
                .to_owned(),
            run_id: "run".to_owned(),
            contract_hash: "contract".to_owned(),
            provider_plan_hash: "plan".to_owned(),
            source_commit: "a".repeat(40),
            call_id: call.call_id.clone(),
            role: call.role,
            host: call.host,
            requested_model: model.to_owned(),
            resolved_model: model.to_owned(),
            provider_session_id: "session-1".to_owned(),
            provider_receipt_ref: "provider-receipt-1".to_owned(),
            provider_executable: executable.to_string_lossy().into_owned(),
            provider_executable_sha256: executable_sha256,
            prompt_path: prompt.to_string_lossy().into_owned(),
            prompt_sha256,
            raw_stdout_path: "stdout.json".to_owned(),
            raw_stdout_sha256: "b".repeat(64),
            raw_stderr_path: "stderr.log".to_owned(),
            raw_stderr_sha256: "c".repeat(64),
            outputs: vec![CognitiveFieldProviderOutputReceipt {
                execution,
                output_path: "reader.json".to_owned(),
                output_sha256: "d".repeat(64),
            }],
            provider_calls: 1,
            exit_code: 0,
            elapsed_ms: 10,
            timed_out: false,
            unknown_outcome: false,
            controller_substitution: false,
            oracle_exposed: false,
            worker_transcript_exposed: false,
            read_only: true,
        };
        validate_provider_receipt_envelope(&call, &receipt, &private_root)?;

        receipt.resolved_model = "opus".to_owned();
        assert!(validate_provider_receipt_envelope(&call, &receipt, &private_root).is_err());
        receipt.resolved_model = model.to_owned();
        receipt.unknown_outcome = true;
        assert!(validate_provider_receipt_envelope(&call, &receipt, &private_root).is_err());
        receipt.unknown_outcome = false;
        fs::write(&executable, b"drifted provider executable")?;
        assert!(validate_provider_receipt_envelope(&call, &receipt, &private_root).is_err());
        fs::remove_dir_all(&private_root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn provider_import_writes_only_sanitized_bound_reader_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-cognitive-provider-import-{}",
            Uuid::new_v4()
        ));
        let report_root = root.join("report");
        let private_root = root.join("private");
        fs::create_dir_all(&report_root)?;
        fs::create_dir_all(private_root.join("oracles"))?;
        fs::create_dir_all(private_root.join("prompts"))?;
        fs::create_dir_all(private_root.join("outputs"))?;
        let report_root = fs::canonicalize(report_root)?;
        let private_root = fs::canonicalize(private_root)?;
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let suite_bytes = fs::read(suite_root.join("tests/cognitive/field-v2/suite.json"))?;
        let suite: CognitiveFieldSuite = serde_json::from_slice(&suite_bytes)?;
        let case = suite
            .cases
            .iter()
            .find(|case| case.case_id == "U01")
            .ok_or("find U01")?;
        let contract = CognitiveFieldRunContract {
            schema_version: COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION.to_owned(),
            run_id: "provider-import".to_owned(),
            suite_sha256: sha256_bytes(&suite_bytes),
            source_commit: super::git_commit(suite_root)?,
            primary_repository: suite_root.to_string_lossy().into_owned(),
            second_repository: "C:/second".to_owned(),
            second_repository_commit: "b".repeat(40),
            output_root: super::canonical_path(&report_root),
            private_root_sha256: sha256_bytes(super::canonical_path(&private_root).as_bytes()),
            hard_provider_call_cap: suite.hard_provider_call_cap,
            contract_hash: "contract".to_owned(),
            sealed_at: OffsetDateTime::UNIX_EPOCH,
        };
        write_new_or_same_json(&report_root.join("suite.json"), &suite)?;
        write_new_or_same_json(&report_root.join("contract.json"), &contract)?;

        let mut oracle = generated_oracle(case, 0, &contract, &suite_bytes);
        CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
        write_new_or_same_json(&private_root.join("oracles/U01.json"), &oracle)?;
        let project_id = eliot_types::ProjectId::new_v7();
        let task_id = eliot_types::TaskId::new_v7();
        let mut deterministic = CognitiveDeterministicReport {
            schema_version: COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION.to_owned(),
            case_id: case.case_id.clone(),
            project_id,
            task_id,
            source_commit: contract.source_commit.clone(),
            verifier_refs: case.deterministic_verifier_refs.clone(),
            hard_gate_evidence: suite
                .shared_hard_gates
                .iter()
                .copied()
                .map(|gate| CognitiveHardGateEvidence {
                    gate,
                    passed: true,
                    evidence_refs: vec!["test:provider-import".to_owned()],
                    explanation: "test hard gate passed".to_owned(),
                })
                .collect(),
            controller_provider_calls: 0,
            truth_revision_before: "revision:1".to_owned(),
            truth_revision_after_observability: "revision:1".to_owned(),
            report_hash: String::new(),
            passed: true,
        };
        CognitiveFieldGradingService::seal_deterministic_report(&mut deterministic)?;
        let evidence_root = report_root.join("evidence/U01/treatment");
        write_new_or_same_json(&evidence_root.join("deterministic.json"), &deterministic)?;

        let executable = private_root.join("claude.exe");
        let prompt = private_root.join("prompts/reader-01.txt");
        fs::write(&executable, b"provider executable fixture")?;
        fs::write(&prompt, b"isolated reader prompt without oracle")?;
        let model = "claude-opus-5";
        let execution = CognitiveFieldExecutionKey {
            case_id: "U01".to_owned(),
            memory_condition: CognitiveMemoryCondition::Treatment,
        };
        let call = CognitiveFieldProviderCallPlan {
            call_number: 1,
            call_id: "reader-01".to_owned(),
            role: CognitiveFieldRole::UnderstandingReader,
            host: AgentHostId::Claude,
            requested_model: model.to_owned(),
            expected_provider_executable_sha256: sha256_bytes(&fs::read(&executable)?),
            prompt_ref: "prompts/reader-01.txt".to_owned(),
            prompt_sha256: sha256_bytes(&fs::read(&prompt)?),
            provider_smoke: false,
            counts_against_cap: true,
            executions: vec![execution.clone()],
        };
        let mut provider_plan = CognitiveFieldProviderPlan {
            schema_version: COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION.to_owned(),
            run_id: contract.run_id.clone(),
            contract_hash: contract.contract_hash.clone(),
            calls: vec![call.clone()],
            planned_provider_calls: 1,
            planned_smoke_calls: 0,
            plan_hash: String::new(),
            sealed_at: OffsetDateTime::UNIX_EPOCH,
        };
        provider_plan.plan_hash =
            CognitiveFieldGradingService::hash_json(&provider_plan_without_hash(&provider_plan))?;
        write_new_or_same_json(&report_root.join("provider-plan.json"), &provider_plan)?;

        let mut reader = minimal_cognitive_understanding_answer();
        reader.case_id = "U01".to_owned();
        reader.project_id = project_id;
        reader.task_id = task_id;
        reader.memory_condition = CognitiveMemoryCondition::Treatment;
        let reader_path = private_root.join("outputs/reader.json");
        write_new_or_same_json(&reader_path, &reader)?;
        let raw_stdout = private_root.join("raw.stdout.json");
        let raw_stderr = private_root.join("raw.stderr.log");
        fs::write(
            &raw_stdout,
            format!(
                "{{\"model\":\"{model}\",\"session\":\"session-1\",\"receipt\":\"provider-receipt-1\"}}"
            ),
        )?;
        fs::write(&raw_stderr, b"")?;
        let receipt = CognitiveFieldProviderEvidenceReceipt {
            schema_version: COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION.to_owned(),
            run_id: contract.run_id.clone(),
            contract_hash: contract.contract_hash.clone(),
            provider_plan_hash: provider_plan.plan_hash.clone(),
            source_commit: contract.source_commit.clone(),
            call_id: call.call_id.clone(),
            role: call.role,
            host: call.host,
            requested_model: model.to_owned(),
            resolved_model: model.to_owned(),
            provider_session_id: "session-1".to_owned(),
            provider_receipt_ref: "provider-receipt-1".to_owned(),
            provider_executable: executable.to_string_lossy().into_owned(),
            provider_executable_sha256: call.expected_provider_executable_sha256,
            prompt_path: prompt.to_string_lossy().into_owned(),
            prompt_sha256: call.prompt_sha256,
            raw_stdout_path: raw_stdout.to_string_lossy().into_owned(),
            raw_stdout_sha256: sha256_bytes(&fs::read(&raw_stdout)?),
            raw_stderr_path: raw_stderr.to_string_lossy().into_owned(),
            raw_stderr_sha256: sha256_bytes(&fs::read(&raw_stderr)?),
            outputs: vec![CognitiveFieldProviderOutputReceipt {
                execution,
                output_path: reader_path.to_string_lossy().into_owned(),
                output_sha256: sha256_bytes(&fs::read(&reader_path)?),
            }],
            provider_calls: 1,
            exit_code: 0,
            elapsed_ms: 12,
            timed_out: false,
            unknown_outcome: false,
            controller_substitution: false,
            oracle_exposed: false,
            worker_transcript_exposed: false,
            read_only: true,
        };
        let receipt_path = private_root.join("receipt.json");
        write_new_or_same_json(&receipt_path, &receipt)?;
        record_provider(&report_root, &private_root, &receipt_path)?;
        assert!(evidence_root.join("reader.json").is_file());
        let reader_binding: serde_json::Value =
            serde_json::from_slice(&fs::read(evidence_root.join("reader-binding.json"))?)?;
        assert_eq!(
            reader_binding["reader_output_hash"],
            CognitiveFieldGradingService::hash_json(&reader)?
        );
        assert_eq!(
            reader_binding["reader_output_sha256"],
            sha256_bytes(&fs::read(&reader_path)?)
        );
        assert!(evidence_root.join("provider-reader.json").is_file());
        assert!(
            report_root
                .join("provider-invocations/reader-01.json")
                .is_file()
        );
        assert!(!evidence_root.join("worker.json").exists());
        assert!(!evidence_root.join("judge.json").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
