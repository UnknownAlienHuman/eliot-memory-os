use anyhow::{Context, Result, bail, ensure};
use eliot_engine::CognitiveFieldGradingService;
use eliot_types::{
    AgentHostId, COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION,
    COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS, COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION,
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
use serde::{Deserialize, Serialize};
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
        "reader" => cognitive_understanding_answer_schema(),
        "judge" => cognitive_judge_result_schema()?,
        other => {
            bail!("unsupported cognitive field schema {other}; expected worker, reader, or judge")
        }
    };
    print_json(&schema)
}

const READER_SCHEMA_JSON_PLACEHOLDER: &str = "{{COGNITIVE_UNDERSTANDING_SCHEMA_JSON}}";
const READER_SCHEMA_SHA256_PLACEHOLDER: &str = "{{COGNITIVE_UNDERSTANDING_SCHEMA_SHA256}}";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RenderedProviderContract {
    canonical_json: String,
    sha256: String,
}

const CORE_ROLE_EVIDENCE_PLAN_SCHEMA_VERSION: &str = "eliot-core-role-evidence-plan-v1";
const CORE_ROLE_REUSE_PROJECTION_SCHEMA_VERSION: &str = "eliot-core-role-reuse-projection-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreRoleEvidencePlan {
    schema_version: String,
    run_id: String,
    sources: Vec<CoreRoleEvidenceSource>,
    plan_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source_kind", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum CoreRoleEvidenceSource {
    FreshProviderCall {
        planned_call_id: String,
    },
    AcceptedPriorRoleArtifact {
        source_run_id: String,
        source_call_id: String,
        role: CognitiveFieldRole,
        case_id: String,
        provider_session_id: String,
        source_commit: String,
        provider_executable_sha256: String,
        output_schema_sha256: String,
        artifact_sha256: String,
        provider_receipt_ref: String,
        deterministic_receipt_refs: Vec<String>,
        contamination_receipt_ref: String,
        worktree_diff_sha256: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreRoleReuseProjection {
    schema_version: String,
    run_id: String,
    contract_hash: String,
    provider_plan_hash: String,
    source_run_id: String,
    source_call_id: String,
    role: CognitiveFieldRole,
    case_id: String,
    provider_session_id: String,
    provider_receipt_ref: String,
    provider_executable_sha256: String,
    output_schema_sha256: String,
    artifact_sha256: String,
    deterministic_receipt_refs: Vec<String>,
    contamination_receipt_ref: String,
    worktree_diff_sha256: Option<String>,
    outputs: Vec<CognitiveFieldProviderOutputProjection>,
    recorded_at: OffsetDateTime,
}

#[derive(Debug)]
struct VerifiedPriorRole {
    source_private_root: PathBuf,
    outputs: Vec<(CognitiveFieldExecutionKey, Vec<u8>)>,
    candidate_diff: Option<Vec<u8>>,
}

fn provider_compatible_reader_schema(canonical: &Value) -> Result<Value> {
    let mut provider = canonical.clone();
    let root = provider
        .as_object_mut()
        .context("CognitiveUnderstandingAnswer schema root must be an object")?;
    root.remove("$schema");
    sort_json_object_keys(&mut provider);
    Ok(provider)
}

fn render_provider_contract(schema: &Value) -> Result<RenderedProviderContract> {
    let mut stable = schema.clone();
    sort_json_object_keys(&mut stable);
    let canonical_json = serde_json::to_string(&stable)?;
    Ok(RenderedProviderContract {
        sha256: sha256_bytes(canonical_json.as_bytes()),
        canonical_json,
    })
}

fn render_reader_prompt(template: &str, contract: &RenderedProviderContract) -> Result<String> {
    ensure!(
        template.matches(READER_SCHEMA_JSON_PLACEHOLDER).count() == 1
            && template.matches(READER_SCHEMA_SHA256_PLACEHOLDER).count() == 1,
        "Reader prompt must contain each generated schema placeholder exactly once"
    );
    let rendered = template
        .replace(
            READER_SCHEMA_JSON_PLACEHOLDER,
            contract.canonical_json.as_str(),
        )
        .replace(READER_SCHEMA_SHA256_PLACEHOLDER, contract.sha256.as_str());
    ensure!(
        rendered.matches(&contract.canonical_json).count() == 1
            && rendered.matches(&contract.sha256).count() == 1,
        "Reader prompt must contain the generated schema bytes and hash exactly once"
    );
    Ok(rendered)
}

fn sort_json_object_keys(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let mut sorted = object
                .iter_mut()
                .map(|(key, value)| {
                    sort_json_object_keys(value);
                    (key.clone(), std::mem::take(value))
                })
                .collect::<Vec<_>>();
            sorted.sort_by(|left, right| left.0.cmp(&right.0));
            object.clear();
            object.extend(sorted);
        }
        Value::Array(values) => {
            for value in values {
                sort_json_object_keys(value);
            }
        }
        _ => {}
    }
}

fn schema_validation_projection(schema: &Value) -> Value {
    const ANNOTATIONS: [&str; 7] = [
        "$schema",
        "$id",
        "title",
        "description",
        "examples",
        "default",
        "deprecated",
    ];
    match schema {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| !ANNOTATIONS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), schema_validation_projection(value)))
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.iter().map(schema_validation_projection).collect())
        }
        _ => schema.clone(),
    }
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
    let reader_prompt_template =
        fs::read_to_string(suite_root.join("templates/reader-prompt.txt"))?;
    let canonical_reader_schema = cognitive_understanding_answer_schema();
    let provider_reader_schema = provider_compatible_reader_schema(&canonical_reader_schema)?;
    ensure!(
        schema_validation_projection(&canonical_reader_schema)
            == schema_validation_projection(&provider_reader_schema),
        "provider-compatible Reader schema changed validation semantics"
    );
    let canonical_reader_contract = render_provider_contract(&canonical_reader_schema)?;
    let provider_reader_contract = render_provider_contract(&provider_reader_schema)?;
    let reader_prompt =
        render_reader_prompt(&reader_prompt_template, &provider_reader_contract)?.into_bytes();
    let reader_schema = provider_reader_contract.canonical_json.as_bytes().to_vec();
    let core_qualification = suite.harness_version == COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION;
    let core_surfaces = core_qualification
        .then(|| {
            let exposure_path = private_root
                .join("contamination")
                .join("eliot-exposure-set.json");
            ensure!(
                exposure_path.is_file(),
                "core qualification requires a private ELIOT exposure-set export"
            );
            Ok::<_, anyhow::Error>(vec![
                (
                    "fixture-repo-and-git-history".to_owned(),
                    git_history(&primary)?,
                ),
                (
                    "provider-environment".to_owned(),
                    provider_environment_surface(),
                ),
                (
                    "accessible-contract".to_owned(),
                    serde_json::to_vec(&contract)?,
                ),
                ("accessible-plan".to_owned(), serde_json::to_vec(&plan)?),
                ("eliot-exposure-set".to_owned(), fs::read(exposure_path)?),
            ])
        })
        .transpose()?
        .unwrap_or_default();
    let mut leak_reports = Vec::new();
    for (index, case) in suite.cases.iter().enumerate() {
        let mut oracle = if core_qualification {
            read_json::<TaskIntentOracle>(
                &private_root
                    .join("oracle-inputs")
                    .join(format!("{}.json", case.case_id)),
            )
            .with_context(|| format!("load private core oracle input for {}", case.case_id))?
        } else {
            generated_oracle(case, index, &contract, &suite_bytes)
        };
        if core_qualification {
            ensure!(
                oracle.source_commit == contract.source_commit,
                "core oracle source commit differs from the sealed contract"
            );
            ensure!(
                oracle.exact_user_prompt_hash == sha256_bytes(case.title.as_bytes()),
                "core oracle prompt hash differs from the scenario task"
            );
        }
        CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
        let mut surfaces = vec![
            ("worker-prompt".to_owned(), worker_prompt.clone()),
            ("reader-prompt".to_owned(), reader_prompt.clone()),
            ("reader-output-schema".to_owned(), reader_schema.clone()),
            ("suite-manifest".to_owned(), suite_bytes.clone()),
        ];
        surfaces.extend(core_surfaces.clone());
        let scan = CognitiveFieldGradingService::scan_reader_surfaces(&oracle, &surfaces);
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
    write_new_or_same(
        &report_root.join("schemas/reader-canonical.json"),
        canonical_reader_contract.canonical_json.as_bytes(),
    )?;
    write_new_or_same(
        &report_root.join("schemas/reader-provider.json"),
        provider_reader_contract.canonical_json.as_bytes(),
    )?;
    write_new_or_same(
        &private_root.join("schemas/reader-canonical.json"),
        canonical_reader_contract.canonical_json.as_bytes(),
    )?;
    write_new_or_same(
        &private_root.join("schemas/reader-provider.json"),
        provider_reader_contract.canonical_json.as_bytes(),
    )?;
    write_new_or_same(
        &private_root.join("schemas/reader-prompt-bound.txt"),
        &reader_prompt,
    )?;
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
            "canonical_reader_schema_sha256": canonical_reader_contract.sha256,
            "provider_reader_schema_sha256": provider_reader_contract.sha256,
            "rendered_reader_prompt_sha256": sha256_bytes(&reader_prompt),
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
    let (project_id, task_id) =
        if suite.harness_version == COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION {
            let binding: CoreQualificationBinding = read_json(
                &private_root
                    .join("bindings")
                    .join(format!("{}.json", case.case_id)),
            )
            .with_context(|| format!("load private core binding for {}", case.case_id))?;
            ensure!(
                binding.schema_version == "eliot-core-qualification-binding-v1"
                    && binding.run_id == contract.run_id
                    && binding.case_id == case.case_id,
                "private core binding differs from the sealed execution"
            );
            (
                ProjectId::from_uuid(
                    Uuid::parse_str(&binding.project_id).context("parse core project id")?,
                ),
                TaskId::from_uuid(Uuid::parse_str(&binding.task_id).context("parse core task id")?),
            )
        } else {
            let binding = format!(
                "{}:{}:{}:{}",
                contract.run_id,
                case.case_id,
                condition_name(condition),
                contract.source_commit
            );
            stable_binding_ids(&binding)
        };
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
    if suite.harness_version != COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION {
        ensure_deterministic_evidence_complete(&suite, &report_root)?;
    }

    let calls: Vec<CognitiveFieldProviderCallPlan> = read_json(&calls_path)?;
    let role_evidence_plan =
        load_core_role_evidence_plan(&suite, &contract, &report_root, &private_root, &calls)?;
    let role_sources = role_evidence_plan
        .as_ref()
        .map_or(&[][..], |plan| plan.sources.as_slice());
    let (planned_provider_calls, planned_smoke_calls) =
        validate_provider_calls_with_sources(&suite, &calls, &private_root, role_sources)?;
    let planned_reused_roles = u8::try_from(prior_role_sources(role_sources).count())
        .context("reused role count exceeds u8")?;
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
        planned_reused_roles,
        role_evidence_plan_hash: role_evidence_plan
            .as_ref()
            .map(|role_plan| role_plan.plan_hash.clone()),
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
    if let Some(role_plan) = &role_evidence_plan {
        write_new_or_same_json(&report_root.join("role-evidence-plan.json"), role_plan)?;
        materialize_accepted_prior_roles(
            &suite,
            &contract,
            &plan,
            role_plan,
            &report_root,
            &private_root,
        )?;
    }
    print_json(&json!({
        "status": "provider_plan_sealed",
        "run_id": contract.run_id,
        "provider_plan_hash": plan.plan_hash,
        "planned_provider_calls": plan.planned_provider_calls,
        "planned_smoke_calls": plan.planned_smoke_calls,
        "planned_reused_roles": plan.planned_reused_roles,
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
    let mut required_stdout_attestations = vec![
        receipt.provider_session_id.as_str(),
        receipt.provider_receipt_ref.as_str(),
    ];
    if suite.harness_version != COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION
        || receipt.host != AgentHostId::Codex
    {
        required_stdout_attestations.push(receipt.resolved_model.as_str());
    }
    for required in required_stdout_attestations {
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
                let value: Value = serde_json::from_slice(&bytes)?;
                let canonical_schema = cognitive_understanding_answer_schema();
                let provider_schema = provider_compatible_reader_schema(&canonical_schema)?;
                validate_json_schema_instance(
                    &provider_schema,
                    &value,
                    "Reader provider-compatible output",
                )?;
                validate_json_schema_instance(
                    &canonical_schema,
                    &value,
                    "Reader canonical output",
                )?;
                let reader: CognitiveUnderstandingAnswer = serde_json::from_value(value)?;
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
    let role_plan = if let Some(plan) = &provider_plan {
        validate_provider_plan_hash(plan)?;
        ensure!(
            plan.run_id == contract.run_id && plan.contract_hash == contract.contract_hash,
            "provider plan differs from the sealed run contract"
        );
        let role_plan = plan
            .role_evidence_plan_hash
            .as_ref()
            .map(|expected_hash| {
                let role_plan: CoreRoleEvidencePlan =
                    read_json(&report_root.join("role-evidence-plan.json"))?;
                ensure!(
                    role_plan.plan_hash == *expected_hash
                        && role_plan.run_id == contract.run_id
                        && role_plan.schema_version == CORE_ROLE_EVIDENCE_PLAN_SCHEMA_VERSION,
                    "role evidence plan differs from the sealed provider plan"
                );
                let mut material = role_plan.clone();
                material.plan_hash.clear();
                ensure!(
                    CognitiveFieldGradingService::hash_json(&material)? == role_plan.plan_hash,
                    "role evidence plan hash is invalid"
                );
                Ok::<_, anyhow::Error>(role_plan)
            })
            .transpose()?;
        let role_sources = role_plan
            .as_ref()
            .map_or(&[][..], |role_plan| role_plan.sources.as_slice());
        let (capped, smokes) =
            validate_provider_calls_with_sources(&suite, &plan.calls, &private_root, role_sources)?;
        let reused = u8::try_from(prior_role_sources(role_sources).count())
            .context("reused role count exceeds u8")?;
        ensure!(
            capped == plan.planned_provider_calls
                && smokes == plan.planned_smoke_calls
                && reused == plan.planned_reused_roles,
            "provider plan summary counts are invalid"
        );
        role_plan
    } else {
        None
    };
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
            && plan.planned_reused_roles <= 1
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
                role_plan.as_ref(),
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
        "reused_provider_roles": provider_plan
            .as_ref()
            .map_or(0, |plan| plan.planned_reused_roles),
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

#[allow(clippy::too_many_lines)]
fn provider_role_errors(
    plan: &CognitiveFieldProviderPlan,
    role_plan: Option<&CoreRoleEvidencePlan>,
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
        let target = evidence_root.join(match role {
            CognitiveFieldRole::CodexWorker => "worker.json",
            CognitiveFieldRole::UnderstandingReader => "reader.json",
            CognitiveFieldRole::CodexJudge => "judge.json",
        });
        let reuse_path = evidence_root.join("reused-worker.json");
        if role == CognitiveFieldRole::CodexWorker && reuse_path.is_file() {
            let projection: CoreRoleReuseProjection = read_json(&reuse_path)?;
            let output = projection
                .outputs
                .iter()
                .find(|output| output.execution == *execution);
            let output_hash_matches = output.is_some_and(|output| {
                target
                    .is_file()
                    .then(|| fs::read(&target).ok())
                    .flatten()
                    .is_some_and(|bytes| sha256_bytes(&bytes) == output.output_sha256)
            });
            let source_matches = role_plan.is_some_and(|role_plan| {
                prior_role_sources(&role_plan.sources).any(|source| {
                    let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
                        source_run_id,
                        source_call_id,
                        role,
                        case_id,
                        provider_session_id,
                        provider_executable_sha256,
                        output_schema_sha256,
                        artifact_sha256,
                        provider_receipt_ref,
                        deterministic_receipt_refs,
                        contamination_receipt_ref,
                        worktree_diff_sha256,
                        ..
                    } = source
                    else {
                        return false;
                    };
                    projection.source_run_id == *source_run_id
                        && projection.source_call_id == *source_call_id
                        && projection.role == *role
                        && projection.case_id == *case_id
                        && projection.provider_session_id == *provider_session_id
                        && projection.provider_executable_sha256 == *provider_executable_sha256
                        && projection.output_schema_sha256 == *output_schema_sha256
                        && projection.artifact_sha256 == *artifact_sha256
                        && projection.provider_receipt_ref == *provider_receipt_ref
                        && projection.deterministic_receipt_refs == *deterministic_receipt_refs
                        && projection.contamination_receipt_ref == *contamination_receipt_ref
                        && projection.worktree_diff_sha256 == *worktree_diff_sha256
                })
            });
            if projection.schema_version != CORE_ROLE_REUSE_PROJECTION_SCHEMA_VERSION
                || projection.run_id != plan.run_id
                || projection.contract_hash != plan.contract_hash
                || projection.provider_plan_hash != plan.plan_hash
                || projection.role != CognitiveFieldRole::CodexWorker
                || projection.case_id != execution.case_id
                || plan.planned_reused_roles == 0
                || plan.role_evidence_plan_hash.is_none()
                || !source_matches
                || !output_hash_matches
                || evidence_root.join("provider-worker.json").is_file()
            {
                errors.push(
                    "worker reuse projection failed its plan/session/output binding".to_owned(),
                );
            }
            sessions.insert(projection.provider_session_id);
            receipts.insert(projection.provider_receipt_ref);
            continue;
        }
        if role != CognitiveFieldRole::CodexWorker && reuse_path.is_file() {
            errors.push("only Worker evidence may be reused".to_owned());
        }
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
    let reader_schema = cognitive_understanding_answer_schema();
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
    let differs = if kind == "reader" {
        checked_in != *generated
    } else {
        required_set(&checked_in) != required_set(generated)
    };
    if differs {
        report.errors.push(format!(
            "{kind} output schema differs from the Rust-derived contract"
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

fn git_history(repository: &Path) -> Result<Vec<u8>> {
    const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["log", "--all", "-p", "--no-ext-diff", "--no-textconv"])
        .output()
        .context("read fixture repository Git history for contamination scan")?;
    ensure!(
        output.status.success(),
        "fixture repository Git history scan command failed"
    );
    ensure!(
        output.stdout.len() <= MAX_HISTORY_BYTES,
        "fixture repository Git history exceeds the bounded contamination-scan surface"
    );
    Ok(output.stdout)
}

fn provider_environment_surface() -> Vec<u8> {
    let mut entries = std::env::vars_os()
        .map(|(key, value)| {
            let key = key.to_string_lossy();
            let upper = key.to_ascii_uppercase();
            let sensitive = ["TOKEN", "PASSWORD", "SECRET", "COOKIE", "AUTH", "API_KEY"]
                .iter()
                .any(|marker| upper.contains(marker));
            if sensitive {
                format!("{key}=<redacted>")
            } else {
                format!("{key}={}", value.to_string_lossy())
            }
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries.join("\n").into_bytes()
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
#[cfg(test)]
fn validate_provider_calls(
    suite: &CognitiveFieldSuite,
    calls: &[CognitiveFieldProviderCallPlan],
    private_root: &Path,
) -> Result<(u8, u8)> {
    validate_provider_calls_with_sources(suite, calls, private_root, &[])
}

#[allow(clippy::too_many_lines)]
fn validate_provider_calls_with_sources(
    suite: &CognitiveFieldSuite,
    calls: &[CognitiveFieldProviderCallPlan],
    private_root: &Path,
    role_sources: &[CoreRoleEvidenceSource],
) -> Result<(u8, u8)> {
    ensure!(!calls.is_empty(), "provider call plan must not be empty");
    let core_qualification = suite.harness_version == COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION;
    let mut call_ids = BTreeSet::new();
    let mut observed =
        BTreeMap::<(String, CognitiveMemoryCondition, CognitiveFieldRole), u8>::new();
    let mut source_call_ids = BTreeSet::new();
    let mut reused_roles = 0_u8;
    for source in role_sources {
        match source {
            CoreRoleEvidenceSource::FreshProviderCall { planned_call_id } => {
                ensure!(
                    safe_segment(planned_call_id)
                        && source_call_ids.insert(planned_call_id.clone()),
                    "role evidence plan contains a duplicate or unsafe fresh call id"
                );
            }
            CoreRoleEvidenceSource::AcceptedPriorRoleArtifact { role, case_id, .. } => {
                ensure!(
                    core_qualification
                        && *role == CognitiveFieldRole::CodexWorker
                        && case_id == "U03"
                        && reused_roles == 0,
                    "Task-02R permits only the accepted prior U03 Worker role"
                );
                reused_roles = reused_roles
                    .checked_add(1)
                    .context("reused role count overflow")?;
                for memory_condition in [
                    CognitiveMemoryCondition::Treatment,
                    CognitiveMemoryCondition::MemoryFreeControl,
                ] {
                    observed.insert((case_id.clone(), memory_condition, *role), 1);
                }
            }
        }
    }
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
            is_sha256(&call.expected_provider_executable_sha256)
                && is_sha256(&call.prompt_sha256)
                && is_sha256(&call.canonical_schema_sha256)
                && is_sha256(&call.provider_schema_sha256),
            "provider executable, prompt, and output schema hashes must be SHA-256 values"
        );
        let prompt_path = private_relative_file(private_root, &call.prompt_ref, "provider prompt")?;
        let prompt_bytes = fs::read(&prompt_path)?;
        ensure!(
            sha256_bytes(&prompt_bytes) == call.prompt_sha256,
            "provider prompt hash differs from the sealed call plan"
        );
        let (canonical_contract, provider_contract) = role_schema_contracts(call.role)?;
        ensure!(
            call.canonical_schema_sha256 == canonical_contract.sha256
                && call.provider_schema_sha256 == provider_contract.sha256,
            "provider output schema hashes differ from the Rust-owned role contract"
        );
        if call.role == CognitiveFieldRole::UnderstandingReader {
            let prompt = String::from_utf8(prompt_bytes).context("Reader prompt must be UTF-8")?;
            ensure!(
                prompt.matches(&provider_contract.canonical_json).count() == 1
                    && prompt.matches(&provider_contract.sha256).count() == 1
                    && prompt.contains("BEGIN_COGNITIVE_UNDERSTANDING_SCHEMA")
                    && prompt.contains("END_COGNITIVE_UNDERSTANDING_SCHEMA"),
                "Reader prompt is not bound to the exact generated provider schema"
            );
        }
        ensure!(
            !call.executions.is_empty() && call.executions.windows(2).all(|pair| pair[0] < pair[1]),
            "provider call executions must be non-empty, unique, and sorted"
        );
        if core_qualification
            && matches!(
                call.role,
                CognitiveFieldRole::CodexWorker | CognitiveFieldRole::CodexJudge
            )
        {
            let case_ids = call
                .executions
                .iter()
                .map(|execution| execution.case_id.as_str())
                .collect::<BTreeSet<_>>();
            let conditions = call
                .executions
                .iter()
                .map(|execution| execution.memory_condition)
                .collect::<BTreeSet<_>>();
            ensure!(
                call.executions.len() == 2
                    && case_ids.len() == 1
                    && conditions
                        == [
                            CognitiveMemoryCondition::Treatment,
                            CognitiveMemoryCondition::MemoryFreeControl,
                        ]
                        .into_iter()
                        .collect(),
                "core Worker and Judge calls must cover both conditions for exactly one case"
            );
        } else {
            let memory_condition = call.executions[0].memory_condition;
            ensure!(
                call.executions
                    .iter()
                    .all(|execution| execution.memory_condition == memory_condition),
                "one provider call must not mix memory conditions"
            );
        }
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
        if core_qualification && call.role == CognitiveFieldRole::UnderstandingReader {
            ensure!(
                call.executions.len() == 1,
                "each core Reader call must cover exactly one condition"
            );
            let expected_host = match call.executions[0].case_id.as_str() {
                "U03" => AgentHostId::Claude,
                "U06" => AgentHostId::Antigravity,
                "U11" => AgentHostId::OpenCode,
                _ => bail!("core Reader call targets an unknown scenario"),
            };
            ensure!(
                call.host == expected_host,
                "core Reader host does not match the scenario contract"
            );
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
    if !role_sources.is_empty() {
        ensure!(
            source_call_ids == call_ids,
            "role evidence plan must name every fresh provider call exactly once"
        );
    }
    if core_qualification {
        ensure!(
            capped.saturating_add(reused_roles) == COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS
                && smokes == 0,
            "core qualification must seal twelve logical role sources and no smokes"
        );
    }
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

fn prior_role_sources(
    sources: &[CoreRoleEvidenceSource],
) -> impl Iterator<Item = &CoreRoleEvidenceSource> {
    sources.iter().filter(|source| {
        matches!(
            source,
            CoreRoleEvidenceSource::AcceptedPriorRoleArtifact { .. }
        )
    })
}

fn load_core_role_evidence_plan(
    suite: &CognitiveFieldSuite,
    contract: &CognitiveFieldRunContract,
    report_root: &Path,
    private_root: &Path,
    calls: &[CognitiveFieldProviderCallPlan],
) -> Result<Option<CoreRoleEvidencePlan>> {
    if suite.harness_version != COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION {
        return Ok(None);
    }
    let path = private_root.join("core-role-evidence.json");
    ensure!(
        path.is_file(),
        "core qualification requires private core-role-evidence.json"
    );
    let mut plan: CoreRoleEvidencePlan = read_json(&path)?;
    ensure!(
        plan.schema_version == CORE_ROLE_EVIDENCE_PLAN_SCHEMA_VERSION
            && plan.run_id == contract.run_id,
        "core role evidence plan differs from the sealed run"
    );
    let mut material = plan.clone();
    material.plan_hash.clear();
    let expected_hash = CognitiveFieldGradingService::hash_json(&material)?;
    ensure!(
        plan.plan_hash.is_empty() || expected_hash == plan.plan_hash,
        "core role evidence plan hash is invalid"
    );
    plan.plan_hash = expected_hash;
    validate_provider_calls_with_sources(suite, calls, private_root, &plan.sources)?;
    for source in prior_role_sources(&plan.sources) {
        verify_accepted_prior_role(suite, contract, report_root, private_root, source)?;
    }
    Ok(Some(plan))
}

fn source_run_roots(
    report_root: &Path,
    private_root: &Path,
    source_run_id: &str,
) -> Result<(PathBuf, PathBuf)> {
    ensure!(
        safe_segment(source_run_id),
        "prior role source run id is unsafe"
    );
    let source_report_root = canonical_directory(
        &report_root
            .parent()
            .context("current report root has no qualification parent")?
            .join(source_run_id),
        "prior cognitive report root",
    )?;
    let source_private_root = canonical_directory(
        &private_root
            .parent()
            .context("current private root has no qualification parent")?
            .join(source_run_id),
        "prior private certification root",
    )?;
    Ok((source_report_root, source_private_root))
}

fn content_ref_path(reference: &str, allowed_roots: &[&Path]) -> Result<PathBuf> {
    let (path, expected_sha256) = reference
        .rsplit_once("#sha256=")
        .context("content reference must end with #sha256=<hex>")?;
    ensure!(
        is_sha256(expected_sha256),
        "content reference hash is not SHA-256"
    );
    let path =
        fs::canonicalize(path).with_context(|| format!("resolve content reference {path}"))?;
    ensure!(
        path.is_file() && allowed_roots.iter().any(|root| path.starts_with(root)),
        "content reference is outside the accepted prior run roots"
    );
    ensure!(
        sha256_bytes(&fs::read(&path)?) == expected_sha256,
        "content reference hash mismatch for {}",
        path.display()
    );
    Ok(path)
}

fn git_diff_bytes(repository: &Path) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["diff", "--binary", "--no-ext-diff", "HEAD", "--"])
        .output()
        .with_context(|| format!("read candidate diff from {}", repository.display()))?;
    ensure!(
        output.status.success(),
        "git diff failed for {}: {}",
        repository.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn paired_artifact_sha256(outputs: &[(CognitiveFieldExecutionKey, Vec<u8>)]) -> Result<String> {
    let mut material = Vec::new();
    for (execution, bytes) in outputs {
        let execution = serde_json::to_vec(execution)?;
        for part in [&execution, bytes] {
            let length = u64::try_from(part.len()).context("artifact part length exceeds u64")?;
            material.extend_from_slice(&length.to_le_bytes());
            material.extend_from_slice(part);
        }
    }
    Ok(sha256_bytes(&material))
}

#[allow(clippy::too_many_lines)]
fn verify_accepted_prior_role(
    suite: &CognitiveFieldSuite,
    contract: &CognitiveFieldRunContract,
    report_root: &Path,
    private_root: &Path,
    source: &CoreRoleEvidenceSource,
) -> Result<VerifiedPriorRole> {
    let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
        source_run_id,
        source_call_id,
        role,
        case_id,
        provider_session_id,
        source_commit,
        provider_executable_sha256,
        output_schema_sha256,
        artifact_sha256,
        provider_receipt_ref,
        deterministic_receipt_refs,
        contamination_receipt_ref,
        worktree_diff_sha256,
    } = source
    else {
        bail!("fresh provider call is not a prior role artifact");
    };
    ensure!(
        *role == CognitiveFieldRole::CodexWorker && case_id == "U03",
        "only the accepted run-003 U03 Worker may be reused"
    );
    let (source_report_root, source_private_root) =
        source_run_roots(report_root, private_root, source_run_id)?;
    let source_contract: CognitiveFieldRunContract =
        read_json(&source_report_root.join("contract.json"))?;
    ensure!(
        source_contract.run_id == *source_run_id
            && source_contract.source_commit == *source_commit
            && contract.source_commit == *source_commit
            && same_git_repository(
                Path::new(&source_contract.primary_repository),
                Path::new(&contract.primary_repository),
            )?,
        "prior Worker repository or source commit differs from the resumed run"
    );
    let source_plan: Value = read_json(&source_report_root.join("provider-plan.json"))?;
    ensure!(
        source_plan.get("run_id").and_then(Value::as_str) == Some(source_run_id)
            && source_plan.get("contract_hash").and_then(Value::as_str)
                == Some(source_contract.contract_hash.as_str()),
        "prior Worker provider plan differs from its run contract"
    );
    let source_call = source_plan
        .get("calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|call| call.get("call_id").and_then(Value::as_str) == Some(source_call_id))
        .context("prior Worker call is absent from its provider plan")?;
    ensure!(
        source_call.get("role").and_then(Value::as_str) == Some("codex_worker")
            && source_call.get("host").and_then(Value::as_str) == Some("codex")
            && source_call
                .get("expected_provider_executable_sha256")
                .and_then(Value::as_str)
                == Some(provider_executable_sha256)
            && source_call
                .get("counts_against_cap")
                .and_then(Value::as_bool)
                == Some(true)
            && source_call.get("provider_smoke").and_then(Value::as_bool) == Some(false),
        "prior Worker call plan binding is invalid"
    );
    let source_suite: CognitiveFieldSuite = read_json(&source_report_root.join("suite.json"))?;
    let current_case = suite
        .cases
        .iter()
        .find(|candidate| candidate.case_id == *case_id)
        .context("current suite lacks prior Worker case")?;
    let source_case = source_suite
        .cases
        .iter()
        .find(|candidate| candidate.case_id == *case_id)
        .context("prior suite lacks Worker case")?;
    ensure!(
        current_case == source_case,
        "prior Worker public task differs from the resumed scenario"
    );
    let source_oracle: TaskIntentOracle = read_json(
        &source_private_root
            .join("oracles")
            .join(format!("{case_id}.json")),
    )?;
    let current_oracle: TaskIntentOracle =
        read_json(&private_root.join("oracles").join(format!("{case_id}.json")))?;
    ensure!(
        source_oracle.oracle_hash == current_oracle.oracle_hash
            && source_oracle.source_commit == contract.source_commit,
        "prior Worker private oracle differs from the resumed oracle"
    );

    let projection: CognitiveFieldProviderProjection = read_json(
        &source_report_root
            .join("provider-invocations")
            .join(format!("{source_call_id}.json")),
    )?;
    ensure!(
        projection.run_id == *source_run_id
            && projection.call_id == *source_call_id
            && projection.role == *role
            && projection.provider_session_id == *provider_session_id
            && projection.provider_receipt_ref == *provider_receipt_ref
            && projection.provider_executable_sha256 == *provider_executable_sha256
            && projection.source_commit == *source_commit
            && projection.contract_hash == source_contract.contract_hash
            && source_plan.get("plan_hash").and_then(Value::as_str)
                == Some(projection.provider_plan_hash.as_str())
            && projection.outputs.len() == 2,
        "prior Worker provider projection differs from the sealed dependency"
    );
    let receipt: CognitiveFieldProviderEvidenceReceipt =
        read_json(&source_private_root.join("provider-calls/core-call-01/receipt.json"))?;
    ensure!(
        receipt.run_id == *source_run_id
            && receipt.call_id == *source_call_id
            && receipt.role == *role
            && receipt.provider_session_id == *provider_session_id
            && receipt.provider_receipt_ref == *provider_receipt_ref
            && receipt.provider_executable_sha256 == *provider_executable_sha256
            && receipt.source_commit == *source_commit
            && receipt.contract_hash == source_contract.contract_hash
            && receipt.provider_plan_hash == projection.provider_plan_hash
            && receipt.provider_calls == 1
            && receipt.exit_code == 0
            && !receipt.timed_out
            && !receipt.unknown_outcome
            && !receipt.controller_substitution,
        "prior Worker provider receipt is not a canonical successful invocation"
    );
    let (worker_canonical, _) = role_schema_contracts(CognitiveFieldRole::CodexWorker)?;
    ensure!(
        worker_canonical.sha256 == *output_schema_sha256,
        "prior Worker output schema differs from the current Rust contract"
    );
    let worker_schema = cognitive_worker_result_schema()?;
    let mut outputs = Vec::new();
    for output in &receipt.outputs {
        ensure!(
            output.execution.case_id == *case_id
                && matches!(
                    output.execution.memory_condition,
                    CognitiveMemoryCondition::Treatment
                        | CognitiveMemoryCondition::MemoryFreeControl
                ),
            "prior Worker output belongs to a different execution"
        );
        let output_path = fs::canonicalize(&output.output_path)?;
        ensure!(
            output_path.starts_with(&source_private_root) && output_path.is_file(),
            "prior Worker output is outside its private run"
        );
        let bytes = fs::read(&output_path)?;
        ensure!(
            sha256_bytes(&bytes) == output.output_sha256
                && projection.outputs.iter().any(|candidate| {
                    candidate.execution == output.execution
                        && candidate.output_sha256 == output.output_sha256
                }),
            "prior Worker output bytes differ from provider evidence"
        );
        let value: Value = serde_json::from_slice(&bytes)?;
        validate_json_schema_instance(&worker_schema, &value, "prior Worker output")?;
        let worker: CognitiveWorkerResult = serde_json::from_value(value)?;
        ensure!(
            worker.case_id == *case_id
                && worker.memory_condition == output.execution.memory_condition,
            "prior Worker output binding is invalid"
        );
        if output.execution.memory_condition == CognitiveMemoryCondition::Treatment {
            ensure!(
                !worker.memory_handles_used.is_empty() && !worker.influence_receipt_refs.is_empty(),
                "prior treatment Worker lacks canonical ELIOT influence evidence"
            );
        } else {
            ensure!(
                worker.memory_handles_used.is_empty() && worker.influence_receipt_refs.is_empty(),
                "prior control Worker contains ELIOT memory influence"
            );
        }
        let source_evidence_root = source_report_root
            .join("evidence")
            .join(case_id)
            .join(condition_name(output.execution.memory_condition));
        ensure!(
            fs::read(source_evidence_root.join("worker.json"))? == bytes,
            "prior public Worker artifact differs from provider-owned output bytes"
        );
        let public_projection: CognitiveFieldProviderProjection =
            read_json(&source_evidence_root.join("provider-worker.json"))?;
        ensure!(
            public_projection == projection,
            "prior public Worker projection differs from the invocation registry"
        );
        let deterministic: CognitiveDeterministicReport =
            read_json(&source_evidence_root.join("deterministic.json"))?;
        ensure!(
            deterministic_report_is_valid(&deterministic)?
                && deterministic.source_commit == *source_commit
                && deterministic.project_id == worker.project_id
                && deterministic.task_id == worker.task_id,
            "prior Worker deterministic acceptance is invalid"
        );
        outputs.push((output.execution.clone(), bytes));
    }
    outputs.sort_by(|left, right| left.0.cmp(&right.0));
    ensure!(
        paired_artifact_sha256(&outputs)? == *artifact_sha256,
        "prior Worker paired artifact hash differs from the dependency"
    );

    ensure!(
        deterministic_receipt_refs.len() == 2,
        "prior Worker requires exact treatment and control deterministic receipts"
    );
    let mut deterministic_conditions = BTreeSet::new();
    for reference in deterministic_receipt_refs {
        let path = content_ref_path(reference, &[&source_report_root, &source_private_root])?;
        let value: Value = read_json(&path)?;
        ensure!(
            value.get("case_id").and_then(Value::as_str) == Some(case_id)
                && value.get("source_commit").and_then(Value::as_str) == Some(source_commit),
            "prior deterministic receipt differs from Worker dependencies"
        );
        let condition = value
            .get("memory_condition")
            .and_then(Value::as_str)
            .context("deterministic receipt lacks memory condition")?;
        deterministic_conditions.insert(condition.to_owned());
    }
    ensure!(
        deterministic_conditions
            == ["memory_free_control".to_owned(), "treatment".to_owned()]
                .into_iter()
                .collect(),
        "prior deterministic receipts do not cover treatment and control"
    );
    content_ref_path(
        contamination_receipt_ref,
        &[&source_report_root, &source_private_root],
    )?;
    let preflight: Value = read_json(&source_report_root.join("preflight.json"))?;
    ensure!(
        preflight
            .get("reader_surface_scans")
            .and_then(Value::as_array)
            .is_some_and(|scans| {
                !scans.is_empty()
                    && scans
                        .iter()
                        .all(|scan| scan.get("clean").and_then(Value::as_bool) == Some(true))
            }),
        "prior contamination preflight was not clean"
    );

    let candidate_diff = if let Some(expected) = worktree_diff_sha256 {
        ensure!(is_sha256(expected), "candidate diff hash is not SHA-256");
        let candidate_root = canonical_directory(
            &source_private_root.join("worktrees/cq1"),
            "prior CQ1 worktree",
        )?;
        ensure!(
            git_commit(&candidate_root)? == *source_commit,
            "prior CQ1 worktree base commit differs from Worker source"
        );
        let bytes = git_diff_bytes(&candidate_root)?;
        ensure!(
            !bytes.is_empty() && sha256_bytes(&bytes) == *expected,
            "prior CQ1 candidate diff is absent or hash-mismatched"
        );
        Some(bytes)
    } else {
        bail!("Task-02R U03 Worker reuse requires a candidate worktree diff hash");
    };
    Ok(VerifiedPriorRole {
        source_private_root,
        outputs,
        candidate_diff,
    })
}

fn materialize_accepted_prior_roles(
    suite: &CognitiveFieldSuite,
    contract: &CognitiveFieldRunContract,
    provider_plan: &CognitiveFieldProviderPlan,
    role_plan: &CoreRoleEvidencePlan,
    report_root: &Path,
    private_root: &Path,
) -> Result<()> {
    for source in prior_role_sources(&role_plan.sources) {
        let verified =
            verify_accepted_prior_role(suite, contract, report_root, private_root, source)?;
        let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
            source_run_id,
            source_call_id,
            role,
            case_id,
            provider_session_id,
            provider_executable_sha256,
            output_schema_sha256,
            artifact_sha256,
            provider_receipt_ref,
            deterministic_receipt_refs,
            contamination_receipt_ref,
            worktree_diff_sha256,
            ..
        } = source
        else {
            unreachable!("filtered prior role source");
        };
        let outputs = verified
            .outputs
            .iter()
            .map(
                |(execution, bytes)| CognitiveFieldProviderOutputProjection {
                    execution: execution.clone(),
                    output_sha256: sha256_bytes(bytes),
                },
            )
            .collect::<Vec<_>>();
        let reuse_root = private_root.join("reused").join(artifact_sha256);
        for (execution, bytes) in &verified.outputs {
            write_new_or_same(
                &reuse_root.join(format!(
                    "{}-worker.json",
                    condition_name(execution.memory_condition)
                )),
                bytes,
            )?;
        }
        if let Some(candidate_diff) = &verified.candidate_diff {
            write_new_or_same(&reuse_root.join("candidate.diff"), candidate_diff)?;
        }
        write_new_or_same_json(
            &reuse_root.join("source-private-root.json"),
            &json!({
                "source_private_root_sha256":
                    sha256_bytes(canonical_path(&verified.source_private_root).as_bytes()),
                "source_run_id": source_run_id,
            }),
        )?;
        let projection = CoreRoleReuseProjection {
            schema_version: CORE_ROLE_REUSE_PROJECTION_SCHEMA_VERSION.to_owned(),
            run_id: contract.run_id.clone(),
            contract_hash: contract.contract_hash.clone(),
            provider_plan_hash: provider_plan.plan_hash.clone(),
            source_run_id: source_run_id.clone(),
            source_call_id: source_call_id.clone(),
            role: *role,
            case_id: case_id.clone(),
            provider_session_id: provider_session_id.clone(),
            provider_receipt_ref: provider_receipt_ref.clone(),
            provider_executable_sha256: provider_executable_sha256.clone(),
            output_schema_sha256: output_schema_sha256.clone(),
            artifact_sha256: artifact_sha256.clone(),
            deterministic_receipt_refs: deterministic_receipt_refs.clone(),
            contamination_receipt_ref: contamination_receipt_ref.clone(),
            worktree_diff_sha256: worktree_diff_sha256.clone(),
            outputs,
            recorded_at: OffsetDateTime::now_utc(),
        };
        for (execution, bytes) in verified.outputs {
            let evidence_root = report_root
                .join("evidence")
                .join(&execution.case_id)
                .join(condition_name(execution.memory_condition));
            let deterministic: CognitiveDeterministicReport =
                read_json(&evidence_root.join("deterministic.json"))?;
            let worker: CognitiveWorkerResult = serde_json::from_slice(&bytes)?;
            ensure!(
                deterministic.passed
                    && deterministic.source_commit == contract.source_commit
                    && deterministic.project_id == worker.project_id
                    && deterministic.task_id == worker.task_id,
                "resumed deterministic binding differs from the accepted Worker artifact"
            );
            write_new_or_same(&evidence_root.join("worker.json"), &bytes)?;
            write_new_or_same_json(&evidence_root.join("reused-worker.json"), &projection)?;
        }
    }
    Ok(())
}

fn role_schema_contracts(
    role: CognitiveFieldRole,
) -> Result<(RenderedProviderContract, RenderedProviderContract)> {
    let canonical = match role {
        CognitiveFieldRole::CodexWorker => cognitive_worker_result_schema()?,
        CognitiveFieldRole::UnderstandingReader => cognitive_understanding_answer_schema(),
        CognitiveFieldRole::CodexJudge => cognitive_judge_result_schema()?,
    };
    let provider = if role == CognitiveFieldRole::UnderstandingReader {
        provider_compatible_reader_schema(&canonical)?
    } else {
        canonical.clone()
    };
    Ok((
        render_provider_contract(&canonical)?,
        render_provider_contract(&provider)?,
    ))
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

fn validate_json_schema_instance(schema: &Value, instance: &Value, label: &str) -> Result<()> {
    let errors = json_schema_errors(schema, schema, instance, "$", 0);
    ensure!(
        errors.is_empty(),
        "{label} failed JSON Schema validation: {}",
        errors.join("; ")
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn json_schema_errors(
    root: &Value,
    schema: &Value,
    instance: &Value,
    path: &str,
    depth: usize,
) -> Vec<String> {
    if depth > 64 {
        return vec![format!("{path}: schema recursion exceeded 64 levels")];
    }
    if schema == &Value::Bool(true) {
        return Vec::new();
    }
    if schema == &Value::Bool(false) {
        return vec![format!("{path}: rejected by false schema")];
    }
    let Some(object) = schema.as_object() else {
        return vec![format!("{path}: schema node is not an object or boolean")];
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let Some(pointer) = reference.strip_prefix('#') else {
            return vec![format!(
                "{path}: non-local schema ref {reference} is unsupported"
            )];
        };
        let Some(target) = root.pointer(pointer) else {
            return vec![format!("{path}: unresolved schema ref {reference}")];
        };
        return json_schema_errors(root, target, instance, path, depth + 1);
    }

    let mut errors = Vec::new();
    if let Some(expected) = object.get("const")
        && expected != instance
    {
        errors.push(format!("{path}: value differs from const"));
    }
    if let Some(variants) = object.get("enum").and_then(Value::as_array)
        && !variants.contains(instance)
    {
        errors.push(format!("{path}: value is outside enum"));
    }
    if let Some(types) = object.get("type") {
        let type_matches = match types {
            Value::String(expected) => json_type_matches(expected, instance),
            Value::Array(expected) => expected
                .iter()
                .filter_map(Value::as_str)
                .any(|expected| json_type_matches(expected, instance)),
            _ => false,
        };
        if !type_matches {
            errors.push(format!(
                "{path}: actual type {} does not satisfy schema type {types}",
                json_type_name(instance)
            ));
            return errors;
        }
    }

    if let Some(all_of) = object.get("allOf").and_then(Value::as_array) {
        for branch in all_of {
            errors.extend(json_schema_errors(root, branch, instance, path, depth + 1));
        }
    }
    if let Some(any_of) = object.get("anyOf").and_then(Value::as_array)
        && !any_of
            .iter()
            .any(|branch| json_schema_errors(root, branch, instance, path, depth + 1).is_empty())
    {
        errors.push(format!("{path}: no anyOf branch accepted the value"));
    }
    if let Some(one_of) = object.get("oneOf").and_then(Value::as_array) {
        let accepted = one_of
            .iter()
            .filter(|branch| json_schema_errors(root, branch, instance, path, depth + 1).is_empty())
            .count();
        if accepted != 1 {
            errors.push(format!(
                "{path}: expected exactly one oneOf branch, accepted {accepted}"
            ));
        }
    }

    if let Some(actual) = instance.as_object() {
        let required = object
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        for key in required {
            if !actual.contains_key(key) {
                errors.push(format!("{path}/{key}: required property is missing"));
            }
        }
        let properties = object.get("properties").and_then(Value::as_object);
        if let Some(properties) = properties {
            for (key, value) in actual {
                if let Some(property_schema) = properties.get(key) {
                    errors.extend(json_schema_errors(
                        root,
                        property_schema,
                        value,
                        &format!("{path}/{}", escape_json_pointer(key)),
                        depth + 1,
                    ));
                    continue;
                }
                match object.get("additionalProperties") {
                    Some(Value::Bool(false)) => errors.push(format!(
                        "{path}/{}: additional property is forbidden",
                        escape_json_pointer(key)
                    )),
                    Some(additional @ (Value::Object(_) | Value::Bool(true))) => {
                        errors.extend(json_schema_errors(
                            root,
                            additional,
                            value,
                            &format!("{path}/{}", escape_json_pointer(key)),
                            depth + 1,
                        ));
                    }
                    _ => {}
                }
            }
        } else if let Some(additional @ Value::Object(_)) = object.get("additionalProperties") {
            for (key, value) in actual {
                errors.extend(json_schema_errors(
                    root,
                    additional,
                    value,
                    &format!("{path}/{}", escape_json_pointer(key)),
                    depth + 1,
                ));
            }
        }
        check_size_bound(
            object,
            "minProperties",
            actual.len(),
            path,
            true,
            &mut errors,
        );
        check_size_bound(
            object,
            "maxProperties",
            actual.len(),
            path,
            false,
            &mut errors,
        );
    }

    if let Some(actual) = instance.as_array() {
        if let Some(item_schema) = object.get("items") {
            for (index, value) in actual.iter().enumerate() {
                errors.extend(json_schema_errors(
                    root,
                    item_schema,
                    value,
                    &format!("{path}/{index}"),
                    depth + 1,
                ));
            }
        }
        check_size_bound(object, "minItems", actual.len(), path, true, &mut errors);
        check_size_bound(object, "maxItems", actual.len(), path, false, &mut errors);
        if object.get("uniqueItems") == Some(&Value::Bool(true)) {
            for (index, value) in actual.iter().enumerate() {
                if actual[..index].contains(value) {
                    errors.push(format!("{path}/{index}: array item is not unique"));
                }
            }
        }
    }

    if let Some(actual) = instance.as_str() {
        let length = actual.chars().count();
        check_size_bound(object, "minLength", length, path, true, &mut errors);
        check_size_bound(object, "maxLength", length, path, false, &mut errors);
    }

    if let Some(actual) = instance.as_f64() {
        for (keyword, comparison) in [
            ("minimum", std::cmp::Ordering::Less),
            ("maximum", std::cmp::Ordering::Greater),
        ] {
            if let Some(bound) = object.get(keyword).and_then(Value::as_f64)
                && actual.partial_cmp(&bound) == Some(comparison)
            {
                errors.push(format!("{path}: number violates {keyword} {bound}"));
            }
        }
        if let Some(bound) = object.get("exclusiveMinimum").and_then(Value::as_f64)
            && actual <= bound
        {
            errors.push(format!("{path}: number violates exclusiveMinimum {bound}"));
        }
        if let Some(bound) = object.get("exclusiveMaximum").and_then(Value::as_f64)
            && actual >= bound
        {
            errors.push(format!("{path}: number violates exclusiveMaximum {bound}"));
        }
    }
    errors
}

fn check_size_bound(
    schema: &serde_json::Map<String, Value>,
    keyword: &str,
    actual: usize,
    path: &str,
    minimum: bool,
    errors: &mut Vec<String>,
) {
    let Some(bound) = schema
        .get(keyword)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return;
    };
    if (minimum && actual < bound) || (!minimum && actual > bound) {
        errors.push(format!("{path}: size {actual} violates {keyword} {bound}"));
    }
}

fn json_type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "string" => value.is_string(),
        _ => false,
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreQualificationBinding {
    schema_version: String,
    run_id: String,
    case_id: String,
    project_id: String,
    task_id: String,
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

fn same_git_repository(left: &Path, right: &Path) -> Result<bool> {
    fn common_directory(repository: &Path) -> Result<PathBuf> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["rev-parse", "--git-common-dir"])
            .output()
            .with_context(|| {
                format!("resolve Git common directory for {}", repository.display())
            })?;
        ensure!(
            output.status.success(),
            "git rev-parse --git-common-dir failed for {}: {}",
            repository.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        let value = String::from_utf8(output.stdout)?.trim().to_owned();
        let path = PathBuf::from(value);
        let path = if path.is_absolute() {
            path
        } else {
            repository.join(path)
        };
        fs::canonicalize(path).context("canonicalize Git common directory")
    }
    Ok(common_directory(left)? == common_directory(right)?)
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
        CoreRoleEvidenceSource, READER_SCHEMA_JSON_PLACEHOLDER, READER_SCHEMA_SHA256_PLACEHOLDER,
        execution_conditions, generated_oracle, provider_compatible_reader_schema,
        provider_plan_without_hash, record_provider, render_provider_contract,
        render_reader_prompt, role_schema_contracts, schema_validation_projection, sha256_bytes,
        validate_deterministic_receipt, validate_json_schema_instance, validate_provider_calls,
        validate_provider_calls_with_sources, validate_provider_receipt_envelope,
        validate_reader_output, write_new_or_same_json,
    };
    use eliot_engine::CognitiveFieldGradingService;
    use eliot_types::{
        AgentHostId, COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION,
        COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS,
        COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION,
        COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION, COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION,
        COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION,
        COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION, CognitiveDeterministicEvidenceReceipt,
        CognitiveDeterministicReport, CognitiveFieldExecutionKey, CognitiveFieldProviderCallPlan,
        CognitiveFieldProviderEvidenceReceipt, CognitiveFieldProviderOutputReceipt,
        CognitiveFieldProviderPlan, CognitiveFieldRole, CognitiveFieldRunContract,
        CognitiveFieldSuite, CognitiveHardGateEvidence, CognitiveMemoryCondition,
        CognitiveUnderstandingAnswer, CognitiveVerifierCommandReceipt,
        cognitive_understanding_answer_schema, minimal_cognitive_understanding_answer,
    };
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::Path;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn provider_test_prompt(
        role: CognitiveFieldRole,
        label: &str,
    ) -> Result<(String, String, String), Box<dyn std::error::Error>> {
        let (canonical, provider) = role_schema_contracts(role)?;
        let prompt = if role == CognitiveFieldRole::UnderstandingReader {
            format!(
                "{label}\nBEGIN_COGNITIVE_UNDERSTANDING_SCHEMA\nsha256={}\n{}\nEND_COGNITIVE_UNDERSTANDING_SCHEMA\n",
                provider.sha256, provider.canonical_json
            )
        } else {
            format!("{label} exact provider role prompt\n")
        };
        Ok((prompt, canonical.sha256, provider.sha256))
    }

    fn complete_reader(condition: CognitiveMemoryCondition) -> CognitiveUnderstandingAnswer {
        let mut reader = minimal_cognitive_understanding_answer();
        reader.case_id = "U03".to_owned();
        reader.memory_condition = condition;
        reader.files_to_change = vec!["crates/eliot-engine/src/host.rs".to_owned()];
        reader.known_failures = vec!["failure:stale-cli-discovery".to_owned()];
        reader.stale_or_rejected_memory_refs = vec!["claim:rejected-route".to_owned()];
        reader.open_unknowns = vec!["unknown:future-desktop-cache-layout".to_owned()];
        reader.predicted_changed_paths = vec!["crates/eliot-engine/src/host.rs".to_owned()];
        reader.predicted_failing_verifiers = vec!["cargo:test:host-integration".to_owned()];
        reader
            .confidence_by_section
            .insert("causal_hops".to_owned(), 3);
        if condition == CognitiveMemoryCondition::Treatment {
            reader.memory_handles_received = vec!["claim:received".to_owned()];
            reader.memory_handles_expanded = vec!["claim:expanded".to_owned()];
            reader.memory_handles_used = vec!["claim:used".to_owned()];
            reader.influence_receipt_refs = vec!["influence:verified".to_owned()];
        } else {
            reader.memory_handles_received.clear();
            reader.memory_handles_expanded.clear();
            reader.memory_handles_used.clear();
            reader.influence_receipt_refs.clear();
        }
        reader
    }

    #[test]
    fn canonical_and_provider_reader_contracts_accept_complete_fixture()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = complete_reader(CognitiveMemoryCondition::Treatment);
        let value = serde_json::to_value(&fixture)?;
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        validate_json_schema_instance(&canonical, &value, "canonical fixture")?;
        validate_json_schema_instance(&provider, &value, "provider fixture")?;
        let roundtrip: CognitiveUnderstandingAnswer = serde_json::from_value(value.clone())?;
        assert_eq!(roundtrip, fixture);
        let properties = canonical["properties"]
            .as_object()
            .ok_or("canonical properties object")?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let serialized = value
            .as_object()
            .ok_or("serialized reader object")?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(serialized, properties);
        Ok(())
    }

    #[test]
    fn provider_transform_preserves_recursive_validation_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        assert!(canonical.get("$schema").is_some());
        assert!(provider.get("$schema").is_none());
        assert_eq!(
            schema_validation_projection(&canonical),
            schema_validation_projection(&provider)
        );
        Ok(())
    }

    #[test]
    fn desired_state_is_array_in_provider_contract() -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        let mut valid = serde_json::to_value(complete_reader(CognitiveMemoryCondition::Treatment))?;
        valid["desired_state"] = json!([]);
        validate_json_schema_instance(&canonical, &valid, "canonical desired_state array")?;
        validate_json_schema_instance(&provider, &valid, "provider desired_state array")?;

        let mut invalid = valid;
        invalid["desired_state"] = json!("text");
        let canonical_error =
            validate_json_schema_instance(&canonical, &invalid, "canonical desired_state");
        let provider_error =
            validate_json_schema_instance(&provider, &invalid, "provider desired_state");
        assert!(canonical_error.is_err());
        assert!(provider_error.is_err());
        let canonical_message = canonical_error
            .err()
            .ok_or("canonical schema accepted desired_state string")?
            .to_string();
        let provider_message = provider_error
            .err()
            .ok_or("provider schema accepted desired_state string")?
            .to_string();
        assert!(canonical_message.contains("/desired_state"));
        assert!(provider_message.contains("/desired_state"));
        Ok(())
    }

    #[test]
    fn nested_causal_hop_is_closed_and_typed() -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        let valid = serde_json::to_value(complete_reader(CognitiveMemoryCondition::Treatment))?;
        for field in [
            "hop_kind",
            "from",
            "relation",
            "to",
            "evidence_refs",
            "status",
        ] {
            let mut missing = valid.clone();
            missing["causal_hops"][0]
                .as_object_mut()
                .ok_or("causal hop object")?
                .remove(field);
            assert!(
                validate_json_schema_instance(&canonical, &missing, "missing causal field")
                    .is_err()
            );
            assert!(
                validate_json_schema_instance(&provider, &missing, "missing causal field").is_err()
            );

            let mut wrong = valid.clone();
            wrong["causal_hops"][0][field] = if field == "evidence_refs" {
                json!("not-an-array")
            } else {
                json!(7)
            };
            assert!(
                validate_json_schema_instance(&canonical, &wrong, "wrong causal field type")
                    .is_err()
            );
            assert!(
                validate_json_schema_instance(&provider, &wrong, "wrong causal field type")
                    .is_err()
            );
        }
        let mut additional = valid;
        additional["causal_hops"][0]["seventh"] = json!(true);
        assert!(
            validate_json_schema_instance(&canonical, &additional, "additional causal field")
                .is_err()
        );
        assert!(
            validate_json_schema_instance(&provider, &additional, "additional causal field")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn treatment_and_control_reader_fixtures_preserve_binding_and_isolation()
    -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        for condition in [
            CognitiveMemoryCondition::Treatment,
            CognitiveMemoryCondition::MemoryFreeControl,
        ] {
            let reader = complete_reader(condition);
            let value = serde_json::to_value(&reader)?;
            validate_json_schema_instance(&canonical, &value, "canonical bound fixture")?;
            validate_json_schema_instance(&provider, &value, "provider bound fixture")?;
            let roundtrip: CognitiveUnderstandingAnswer = serde_json::from_value(value)?;
            let execution = CognitiveFieldExecutionKey {
                case_id: reader.case_id.clone(),
                memory_condition: condition,
            };
            let deterministic = CognitiveDeterministicReport {
                schema_version: COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION.to_owned(),
                case_id: reader.case_id.clone(),
                project_id: reader.project_id,
                task_id: reader.task_id,
                source_commit: "a".repeat(40),
                verifier_refs: vec!["verifier:test".to_owned()],
                hard_gate_evidence: Vec::new(),
                controller_provider_calls: 0,
                truth_revision_before: "revision:1".to_owned(),
                truth_revision_after_observability: "revision:1".to_owned(),
                report_hash: "report".to_owned(),
                passed: true,
            };
            validate_reader_output(&roundtrip, &execution, &deterministic)?;
            if condition == CognitiveMemoryCondition::MemoryFreeControl {
                assert!(roundtrip.memory_handles_received.is_empty());
                assert!(roundtrip.memory_handles_expanded.is_empty());
                assert!(roundtrip.memory_handles_used.is_empty());
                assert!(roundtrip.influence_receipt_refs.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn reader_prompt_binds_exact_generated_schema_and_hash_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let template = fs::read_to_string(
            suite_root.join("tests/cognitive/field-v2/templates/reader-prompt.txt"),
        )?;
        let provider_schema =
            provider_compatible_reader_schema(&cognitive_understanding_answer_schema())?;
        let contract = render_provider_contract(&provider_schema)?;
        let prompt = render_reader_prompt(&template, &contract)?;
        assert_eq!(prompt.matches(&contract.canonical_json).count(), 1);
        assert_eq!(prompt.matches(&contract.sha256).count(), 1);
        assert_eq!(
            sha256_bytes(contract.canonical_json.as_bytes()),
            contract.sha256
        );
        assert!(!prompt.contains("all plural fields are arrays"));
        assert!(!prompt.contains("do not emit any key other than"));
        assert_eq!(
            provider_schema["properties"]["desired_state"]["type"],
            json!("array")
        );
        let (_, canonical_hash, provider_hash) =
            provider_test_prompt(CognitiveFieldRole::UnderstandingReader, "reader")?;
        assert_eq!(provider_hash, contract.sha256);
        assert_ne!(canonical_hash, provider_hash);
        Ok(())
    }

    #[test]
    fn provider_transform_rejects_at_least_one_hundred_invalid_mutations()
    -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        let valid = serde_json::to_value(complete_reader(CognitiveMemoryCondition::Treatment))?;
        let required = canonical["required"]
            .as_array()
            .ok_or("required field array")?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let array_fields = canonical["properties"]
            .as_object()
            .ok_or("properties object")?
            .iter()
            .filter(|(_, schema)| schema.get("type") == Some(&json!("array")))
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        assert!(!required.is_empty());
        assert!(!array_fields.is_empty());
        for index in 0..120_usize {
            let mut mutation = valid.clone();
            match index % 6 {
                0 => {
                    let field = &array_fields[index % array_fields.len()];
                    mutation[field] = json!("wrong-array-type");
                }
                1 => {
                    let field = &required[index % required.len()];
                    mutation
                        .as_object_mut()
                        .ok_or("reader object")?
                        .remove(field);
                }
                2 => mutation["unknown_contract_field"] = json!(index),
                3 => mutation["memory_condition"] = json!("invalid_condition"),
                4 => mutation["causal_hops"][0]["evidence_refs"] = json!([7]),
                _ => mutation["confidence_by_section"]["project_purpose"] = json!(256),
            }
            assert!(
                validate_json_schema_instance(
                    &canonical,
                    &mutation,
                    "canonical deterministic mutation"
                )
                .is_err(),
                "canonical schema accepted mutation {index}"
            );
            assert!(
                validate_json_schema_instance(
                    &provider,
                    &mutation,
                    "provider deterministic mutation"
                )
                .is_err(),
                "provider schema widened semantics for mutation {index}"
            );
        }
        Ok(())
    }

    #[test]
    fn reader_contract_has_one_rust_owner_and_placeholder_only_template()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let owner =
            fs::read_to_string(workspace.join("crates/eliot-types/src/cognitive_field.rs"))?;
        let runner =
            fs::read_to_string(workspace.join("crates/eliot-app/src/cognitive_field_runner.rs"))?;
        let template = fs::read_to_string(
            workspace.join("tests/cognitive/field-v2/templates/reader-prompt.txt"),
        )?;
        assert_eq!(
            owner
                .matches("schema_for!(CognitiveUnderstandingAnswer)")
                .count(),
            1
        );
        let production_runner = runner
            .split("#[cfg(test)]")
            .next()
            .ok_or("production runner section")?;
        let forbidden_derivation = ["schema_for!(", "CognitiveUnderstandingAnswer", ")"].concat();
        assert_eq!(production_runner.matches(&forbidden_derivation).count(), 0);
        assert_eq!(template.matches(READER_SCHEMA_JSON_PLACEHOLDER).count(), 1);
        assert_eq!(
            template.matches(READER_SCHEMA_SHA256_PLACEHOLDER).count(),
            1
        );
        assert!(!template.contains("all plural fields are arrays"));
        assert!(!template.contains("`desired_state`"));
        assert!(!template.contains("do not emit any key other than"));
        Ok(())
    }

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
            let (prompt, canonical_schema_sha256, provider_schema_sha256) =
                provider_test_prompt(role, &call_id)?;
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
                canonical_schema_sha256,
                provider_schema_sha256,
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
    fn core_provider_plan_uses_four_fresh_calls_per_scenario()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let mut suite: CognitiveFieldSuite = serde_json::from_slice(&fs::read(
            suite_root.join("tests/cognitive/field-v2/suite.json"),
        )?)?;
        suite.harness_version = COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION.to_owned();
        suite.hard_provider_call_cap = COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS;
        suite
            .cases
            .retain(|case| matches!(case.case_id.as_str(), "U03" | "U06" | "U11"));

        let private_root =
            std::env::temp_dir().join(format!("eliot-core-provider-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(private_root.join("prompts"))?;
        let private_root = fs::canonicalize(private_root)?;
        let mut calls = Vec::new();
        for (case_id, reader_host, reader_model) in [
            ("U03", AgentHostId::Claude, "claude-opus-5"),
            ("U06", AgentHostId::Antigravity, "gemini-3-flash"),
            ("U11", AgentHostId::OpenCode, "openai/gpt-5.6-codex"),
        ] {
            for (role, host, model, conditions) in [
                (
                    CognitiveFieldRole::CodexWorker,
                    AgentHostId::Codex,
                    "gpt-5.6-codex",
                    vec![
                        CognitiveMemoryCondition::Treatment,
                        CognitiveMemoryCondition::MemoryFreeControl,
                    ],
                ),
                (
                    CognitiveFieldRole::UnderstandingReader,
                    reader_host,
                    reader_model,
                    vec![CognitiveMemoryCondition::Treatment],
                ),
                (
                    CognitiveFieldRole::UnderstandingReader,
                    reader_host,
                    reader_model,
                    vec![CognitiveMemoryCondition::MemoryFreeControl],
                ),
                (
                    CognitiveFieldRole::CodexJudge,
                    AgentHostId::Codex,
                    "gpt-5.6-codex",
                    vec![
                        CognitiveMemoryCondition::Treatment,
                        CognitiveMemoryCondition::MemoryFreeControl,
                    ],
                ),
            ] {
                let call_number = u8::try_from(calls.len() + 1)?;
                let call_id = format!("core-call-{call_number:02}");
                let prompt_ref = format!("prompts/{call_id}.txt");
                let (prompt, canonical_schema_sha256, provider_schema_sha256) =
                    provider_test_prompt(role, &call_id)?;
                fs::write(private_root.join(&prompt_ref), prompt.as_bytes())?;
                let mut executions = conditions
                    .into_iter()
                    .map(|memory_condition| CognitiveFieldExecutionKey {
                        case_id: case_id.to_owned(),
                        memory_condition,
                    })
                    .collect::<Vec<_>>();
                executions.sort();
                calls.push(CognitiveFieldProviderCallPlan {
                    call_number,
                    call_id,
                    role,
                    host,
                    requested_model: model.to_owned(),
                    expected_provider_executable_sha256: "a".repeat(64),
                    prompt_ref,
                    prompt_sha256: sha256_bytes(prompt.as_bytes()),
                    canonical_schema_sha256,
                    provider_schema_sha256,
                    provider_smoke: false,
                    counts_against_cap: true,
                    executions,
                });
            }
        }

        let (capped, smokes) = validate_provider_calls(&suite, &calls, &private_root)?;
        assert_eq!(capped, COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS);
        assert_eq!(smokes, 0);
        assert_eq!(calls.len(), 12);

        calls[1].host = AgentHostId::OpenCode;
        assert!(validate_provider_calls(&suite, &calls, &private_root).is_err());
        fs::remove_dir_all(&private_root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn core_provider_preflight_accepts_eleven_fresh_calls_plus_exact_prior_worker_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let mut suite: CognitiveFieldSuite = serde_json::from_slice(&fs::read(
            suite_root.join("tests/cognitive/field-v2/suite.json"),
        )?)?;
        suite.harness_version = COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION.to_owned();
        suite.hard_provider_call_cap = COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS;
        suite
            .cases
            .retain(|case| matches!(case.case_id.as_str(), "U03" | "U06" | "U11"));
        let private_root =
            std::env::temp_dir().join(format!("eliot-core-resume-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(private_root.join("prompts"))?;
        let private_root = fs::canonicalize(private_root)?;
        let mut calls = Vec::new();
        for (case_id, reader_host, reader_model) in [
            ("U03", AgentHostId::Claude, "claude-opus-5"),
            ("U06", AgentHostId::Antigravity, "gemini-3.6-flash-high"),
            ("U11", AgentHostId::OpenCode, "openai/gpt-5.4"),
        ] {
            for (role, host, model, conditions) in [
                (
                    CognitiveFieldRole::CodexWorker,
                    AgentHostId::Codex,
                    "gpt-5.6-sol",
                    vec![
                        CognitiveMemoryCondition::Treatment,
                        CognitiveMemoryCondition::MemoryFreeControl,
                    ],
                ),
                (
                    CognitiveFieldRole::UnderstandingReader,
                    reader_host,
                    reader_model,
                    vec![CognitiveMemoryCondition::Treatment],
                ),
                (
                    CognitiveFieldRole::UnderstandingReader,
                    reader_host,
                    reader_model,
                    vec![CognitiveMemoryCondition::MemoryFreeControl],
                ),
                (
                    CognitiveFieldRole::CodexJudge,
                    AgentHostId::Codex,
                    "gpt-5.6-sol",
                    vec![
                        CognitiveMemoryCondition::Treatment,
                        CognitiveMemoryCondition::MemoryFreeControl,
                    ],
                ),
            ] {
                if case_id == "U03" && role == CognitiveFieldRole::CodexWorker {
                    continue;
                }
                let call_number = u8::try_from(calls.len() + 1)?;
                let call_id = format!("resumed-call-{call_number:02}");
                let prompt_ref = format!("prompts/{call_id}.txt");
                let (prompt, canonical_schema_sha256, provider_schema_sha256) =
                    provider_test_prompt(role, &call_id)?;
                fs::write(private_root.join(&prompt_ref), prompt.as_bytes())?;
                let mut executions = conditions
                    .into_iter()
                    .map(|memory_condition| CognitiveFieldExecutionKey {
                        case_id: case_id.to_owned(),
                        memory_condition,
                    })
                    .collect::<Vec<_>>();
                executions.sort();
                calls.push(CognitiveFieldProviderCallPlan {
                    call_number,
                    call_id,
                    role,
                    host,
                    requested_model: model.to_owned(),
                    expected_provider_executable_sha256: "a".repeat(64),
                    prompt_ref,
                    prompt_sha256: sha256_bytes(prompt.as_bytes()),
                    canonical_schema_sha256,
                    provider_schema_sha256,
                    provider_smoke: false,
                    counts_against_cap: true,
                    executions,
                });
            }
        }
        let (worker_schema, _) = role_schema_contracts(CognitiveFieldRole::CodexWorker)?;
        let mut sources = calls
            .iter()
            .map(|call| CoreRoleEvidenceSource::FreshProviderCall {
                planned_call_id: call.call_id.clone(),
            })
            .collect::<Vec<_>>();
        sources.push(CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
            source_run_id: "cq-core-20260729-003".to_owned(),
            source_call_id: "6f04e449-ecab-4555-8bd0-4a6bd762c1b4".to_owned(),
            role: CognitiveFieldRole::CodexWorker,
            case_id: "U03".to_owned(),
            provider_session_id: "019fb120-97b7-78c1-8a27-0a54c1a573ae".to_owned(),
            source_commit: "9e6d9161a133d7e501c163a6cc69a3da86713e7a".to_owned(),
            provider_executable_sha256: "a".repeat(64),
            output_schema_sha256: worker_schema.sha256,
            artifact_sha256: "b".repeat(64),
            provider_receipt_ref: "receipt:accepted-worker".to_owned(),
            deterministic_receipt_refs: vec![
                "treatment#sha256=".to_owned() + &"c".repeat(64),
                "control#sha256=".to_owned() + &"d".repeat(64),
            ],
            contamination_receipt_ref: "contamination#sha256=".to_owned() + &"e".repeat(64),
            worktree_diff_sha256: Some("f".repeat(64)),
        });
        let (fresh, smokes) =
            validate_provider_calls_with_sources(&suite, &calls, &private_root, &sources)?;
        assert_eq!(fresh, 11);
        assert_eq!(smokes, 0);

        if let Some(CoreRoleEvidenceSource::AcceptedPriorRoleArtifact { case_id, .. }) =
            sources.last_mut()
        {
            *case_id = "U06".to_owned();
        }
        assert!(
            validate_provider_calls_with_sources(&suite, &calls, &private_root, &sources).is_err()
        );
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
        let (_, canonical_schema_sha256, provider_schema_sha256) =
            provider_test_prompt(CognitiveFieldRole::UnderstandingReader, "reader-01")?;
        let call = CognitiveFieldProviderCallPlan {
            call_number: 1,
            call_id: "reader-01".to_owned(),
            role: CognitiveFieldRole::UnderstandingReader,
            host: AgentHostId::Claude,
            requested_model: model.to_owned(),
            expected_provider_executable_sha256: executable_sha256.clone(),
            prompt_ref: "prompts/reader-01.txt".to_owned(),
            prompt_sha256: prompt_sha256.clone(),
            canonical_schema_sha256,
            provider_schema_sha256,
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
        let (_, canonical_schema_sha256, provider_schema_sha256) =
            provider_test_prompt(CognitiveFieldRole::UnderstandingReader, "reader-01")?;
        let call = CognitiveFieldProviderCallPlan {
            call_number: 1,
            call_id: "reader-01".to_owned(),
            role: CognitiveFieldRole::UnderstandingReader,
            host: AgentHostId::Claude,
            requested_model: model.to_owned(),
            expected_provider_executable_sha256: sha256_bytes(&fs::read(&executable)?),
            prompt_ref: "prompts/reader-01.txt".to_owned(),
            prompt_sha256: sha256_bytes(&fs::read(&prompt)?),
            canonical_schema_sha256,
            provider_schema_sha256,
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
            planned_reused_roles: 0,
            role_evidence_plan_hash: None,
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
