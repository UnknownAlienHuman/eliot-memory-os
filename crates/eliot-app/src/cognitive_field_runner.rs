use anyhow::{Context, Result, bail, ensure};
use eliot_engine::CognitiveFieldGradingService;
use eliot_types::{
    COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION, COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION,
    COGNITIVE_FIELD_PLAN_SCHEMA_VERSION, CognitiveDeterministicReport, CognitiveFieldCase,
    CognitiveFieldPlan, CognitiveFieldPlanItem, CognitiveFieldRunContract, CognitiveFieldSuite,
    CognitiveFieldValidationReport, CognitiveJudgeResult, CognitiveMemoryCondition,
    CognitiveUnderstandingAnswer, TaskIntentOracle, cognitive_judge_result_schema,
    cognitive_understanding_answer_schema,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;

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
        "reader" => cognitive_understanding_answer_schema()?,
        "judge" => cognitive_judge_result_schema()?,
        other => bail!("unsupported cognitive field schema {other}; expected reader or judge"),
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
    let reader_prompt = fs::read(suite_root.join("templates/reader-prompt.txt"))?;
    let reader_schema = fs::read(suite_root.join(&suite.reader_output_schema_ref))?;
    let mut leak_reports = Vec::new();
    for (index, case) in suite.cases.iter().enumerate() {
        let mut oracle = generated_oracle(case, index, &contract, &suite_bytes);
        CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
        let scan = CognitiveFieldGradingService::scan_reader_surfaces(
            &oracle,
            &[
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
    ensure!(
        sha256_bytes(canonical_path(&private_root).as_bytes()) == contract.private_root_sha256,
        "private certification root does not match the sealed contract"
    );

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
            let reader_path = evidence_root.join("reader.json");
            let judge_path = evidence_root.join("judge.json");
            if !reader_path.is_file() || !judge_path.is_file() {
                missing_executions = missing_executions.saturating_add(1);
                judge_results.push(json!({
                    "case_id": case.case_id,
                    "memory_condition": condition_name,
                    "status": "not_run",
                }));
                continue;
            }
            let reader: CognitiveUnderstandingAnswer = read_json(&reader_path)?;
            let judge: CognitiveJudgeResult = read_json(&judge_path)?;
            let oracle: TaskIntentOracle = read_json(
                &private_root
                    .join("oracles")
                    .join(format!("{}.json", case.case_id)),
            )?;
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
        && expected_executions > 0;
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
    );
    crate::runtime_instance::atomic_write_bytes(
        &report_root.join("report.md"),
        markdown.as_bytes(),
    )?;
    print_json(&metrics)?;
    ensure!(all_passed, "cognitive field certification is incomplete");
    Ok(())
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
        acceptance_items: case.deterministic_verifier_refs.clone(),
        non_goals: vec![
            "Do not substitute controller output for a provider role".to_owned(),
            "Do not promote candidate-only evidence to current truth".to_owned(),
        ],
        architecture_constraints: vec![
            "Current source and deterministic verifier evidence outrank memory".to_owned(),
            "Worker, Reader, and Judge sessions remain isolated".to_owned(),
        ],
        expected_subsystem_set: vec![format!("family:{:?}", case.family)],
        acceptable_owner_file_symbol_alternatives: vec![format!(
            "sealed-suite-case:{}:{}",
            case.case_id,
            sha256_bytes(suite_bytes)
        )],
        required_invariant_refs: vec![
            "contract:truth-hierarchy".to_owned(),
            "contract:role-isolation".to_owned(),
        ],
        required_verifier_refs: case.deterministic_verifier_refs.clone(),
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
    path.to_string_lossy().replace('\\', "/")
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

fn render_report(
    contract: &CognitiveFieldRunContract,
    status: &str,
    expected: usize,
    passed: usize,
    missing: usize,
    semantic_median: Option<u16>,
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
