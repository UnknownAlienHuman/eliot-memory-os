use eliot_engine::CognitiveFieldGradingService;
use eliot_types::{
    COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION, COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS,
    COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION, COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION,
    COGNITIVE_FIELD_SUITE_SCHEMA_VERSION, CognitiveDeterministicReport, CognitiveFieldSuite,
    CognitiveHardGateEvidence, CognitiveMemoryCondition, ProjectId, TaskId, TaskIntentOracle,
    minimal_cognitive_judge_result, minimal_cognitive_understanding_answer,
};
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn exact_forty_eight_case_suite_is_valid_and_invalid_fields_are_aggregated() -> TestResult {
    let suite = suite()?;
    let report = CognitiveFieldGradingService::validate_suite(&suite);
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.case_count, 48);

    let mut invalid = suite;
    invalid.schema_version = "wrong".to_owned();
    invalid.hard_provider_call_cap = 25;
    invalid.cases[1].case_id = invalid.cases[0].case_id.clone();
    invalid.cases[0].required_roles.clear();
    let report = CognitiveFieldGradingService::validate_suite(&invalid);
    assert!(!report.valid);
    assert!(report.errors.len() >= 4, "{:?}", report.errors);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains(COGNITIVE_FIELD_SUITE_SCHEMA_VERSION))
    );
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("provider call cap"))
    );
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("duplicate case_id"))
    );
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("three isolated roles"))
    );
    Ok(())
}

#[test]
fn bounded_core_qualification_profile_is_separate_from_field_v2() -> TestResult {
    let mut core = suite()?;
    core.harness_version = COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION.to_owned();
    core.hard_provider_call_cap = COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS;
    core.cases
        .retain(|case| matches!(case.case_id.as_str(), "U03" | "U06" | "U11"));
    let report = CognitiveFieldGradingService::validate_suite(&core);
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.case_count, 3);
    assert_eq!(report.model_backed_case_count, 3);

    core.hard_provider_call_cap -= 1;
    let report = CognitiveFieldGradingService::validate_suite(&core);
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("exactly 12"))
    );
    Ok(())
}

#[test]
fn oracle_seal_is_stable_and_reader_surface_scan_finds_hidden_exact_values() -> TestResult {
    let mut oracle = oracle();
    CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
    let first = oracle.oracle_hash.clone();
    CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
    assert_eq!(oracle.oracle_hash, first);

    let clean = CognitiveFieldGradingService::scan_reader_surfaces(
        &oracle,
        &[(
            "reader-prompt".to_owned(),
            b"Use current repository evidence and report unknowns.".to_vec(),
        )],
    );
    assert!(clean.clean);

    let contaminated = CognitiveFieldGradingService::scan_reader_surfaces(
        &oracle,
        &[(
            "provider-bundle".to_owned(),
            format!("hidden answer: {}", oracle.forbidden_conclusions[0]).into_bytes(),
        )],
    );
    assert!(!contaminated.clean);
    assert_eq!(contaminated.findings.len(), 1);
    assert_eq!(contaminated.findings[0].field, "forbidden_conclusions");
    assert!(!contaminated.findings[0].value_hash.is_empty());
    assert!(!serde_json::to_string(&contaminated)?.contains(&oracle.forbidden_conclusions[0]));

    oracle.normalized_goal.push_str(" changed");
    CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
    assert_ne!(oracle.oracle_hash, first);
    Ok(())
}

#[test]
fn hard_failure_or_memory_free_contamination_cannot_be_overridden_by_judge() -> TestResult {
    let suite = suite()?;
    let case = suite
        .cases
        .iter()
        .find(|case| case.case_id == "U01")
        .ok_or("U01 is missing")?;
    let mut oracle = oracle();
    CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
    let mut reader = minimal_cognitive_understanding_answer();
    reader.case_id = case.case_id.clone();
    reader.project_id = ProjectId::new_v7();
    reader.task_id = TaskId::new_v7();
    reader.memory_condition = CognitiveMemoryCondition::MemoryFreeControl;
    let mut deterministic = deterministic_report(
        &suite,
        case,
        reader.project_id,
        reader.task_id,
        &oracle.source_commit,
    );
    CognitiveFieldGradingService::seal_deterministic_report(&mut deterministic)?;
    let mut judge = minimal_cognitive_judge_result();
    judge.case_id = case.case_id.clone();
    judge.oracle_hash = oracle.oracle_hash.clone();
    judge.reader_output_hash = CognitiveFieldGradingService::hash_json(&reader)?;
    judge.deterministic_report_hash = deterministic.report_hash.clone();

    let grade = CognitiveFieldGradingService::grade_case(
        &suite,
        case,
        &oracle,
        &reader,
        &deterministic,
        &judge,
    );
    assert!(grade.passed, "{:?}", grade.errors);
    assert_eq!(grade.semantic_average_milli, 4_000);

    reader
        .memory_handles_received
        .push("evidence_atom:cross-control".to_owned());
    judge.reader_output_hash = CognitiveFieldGradingService::hash_json(&reader)?;
    let contaminated = CognitiveFieldGradingService::grade_case(
        &suite,
        case,
        &oracle,
        &reader,
        &deterministic,
        &judge,
    );
    assert!(!contaminated.passed);
    assert!(
        contaminated
            .errors
            .iter()
            .any(|error| error.contains("memory-free control"))
    );

    reader.memory_handles_received.clear();
    deterministic.hard_gate_evidence[0].passed = false;
    deterministic.passed = false;
    CognitiveFieldGradingService::seal_deterministic_report(&mut deterministic)?;
    judge.reader_output_hash = CognitiveFieldGradingService::hash_json(&reader)?;
    judge.deterministic_report_hash = deterministic.report_hash.clone();
    judge.semantic_pass = true;
    let hard_failed = CognitiveFieldGradingService::grade_case(
        &suite,
        case,
        &oracle,
        &reader,
        &deterministic,
        &judge,
    );
    assert!(!hard_failed.passed);
    assert!(!hard_failed.deterministic_pass);
    assert!(
        hard_failed
            .errors
            .iter()
            .any(|error| error.contains("deterministic hard gate"))
    );
    Ok(())
}

fn deterministic_report(
    suite: &CognitiveFieldSuite,
    case: &eliot_types::CognitiveFieldCase,
    project_id: ProjectId,
    task_id: TaskId,
    source_commit: &str,
) -> CognitiveDeterministicReport {
    let mut gates = suite.shared_hard_gates.clone();
    gates.extend(case.hard_gates.iter().copied());
    gates.sort_unstable();
    gates.dedup();
    CognitiveDeterministicReport {
        schema_version: COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION.to_owned(),
        case_id: case.case_id.clone(),
        project_id,
        task_id,
        source_commit: source_commit.to_owned(),
        verifier_refs: case.deterministic_verifier_refs.clone(),
        hard_gate_evidence: gates
            .into_iter()
            .map(|gate| CognitiveHardGateEvidence {
                gate,
                passed: true,
                evidence_refs: vec![format!("test:{}", case.case_id)],
                explanation: "exact deterministic fixture passed".to_owned(),
            })
            .collect(),
        controller_provider_calls: 0,
        truth_revision_before: "revision:1".to_owned(),
        truth_revision_after_observability: "revision:1".to_owned(),
        report_hash: String::new(),
        passed: true,
    }
}

fn oracle() -> TaskIntentOracle {
    TaskIntentOracle {
        schema_version: COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION.to_owned(),
        oracle_id: "oracle:U01".to_owned(),
        exact_user_prompt_hash: "sha256:prompt".to_owned(),
        exact_user_prompt_ref: "suite.json#/cases/0/title".to_owned(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        normalized_goal: "Identify the current project purpose".to_owned(),
        desired_state: vec!["Evidence-backed purpose".to_owned()],
        acceptance_items: vec!["Purpose and owners cite current sources".to_owned()],
        non_goals: vec!["No source mutation".to_owned()],
        architecture_constraints: vec!["Current source outranks memory".to_owned()],
        expected_subsystem_set: vec!["project_understanding".to_owned()],
        acceptable_owner_file_symbol_alternatives: vec!["ProjectUnderstandingCompiler".to_owned()],
        required_invariant_refs: vec!["invariant:truth-hierarchy".to_owned()],
        required_verifier_refs: vec!["verifier:cognitive-field-contract".to_owned()],
        forbidden_conclusions: vec!["PRIVATE-ORACLE-MARKER-U01".to_owned()],
        authoritative_source_refs: vec!["source:Cargo.toml".to_owned()],
        oracle_hash: String::new(),
    }
}

fn suite() -> Result<CognitiveFieldSuite, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&std::fs::read(
        workspace_root()?.join("tests/cognitive/field-v2/suite.json"),
    )?)?)
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("resolve workspace root"))?
        .to_path_buf())
}
