use crate::EngineError;
use eliot_types::{
    COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION, COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS,
    COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION, COGNITIVE_FIELD_MAX_PROVIDER_CALLS,
    COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION, COGNITIVE_FIELD_SUITE_SCHEMA_VERSION,
    COGNITIVE_FIELD_V2_HARNESS_VERSION, COGNITIVE_JUDGE_SCHEMA_VERSION,
    COGNITIVE_UNDERSTANDING_SCHEMA_VERSION, CognitiveDeterministicReport, CognitiveFieldCase,
    CognitiveFieldCaseGrade, CognitiveFieldFamily, CognitiveFieldRole, CognitiveFieldSuite,
    CognitiveFieldValidationReport, CognitiveHardGateKind, CognitiveJudgeResult,
    CognitiveMemoryCondition, CognitiveOracleLeakFinding, CognitiveOracleLeakReport,
    CognitiveRepositoryCondition, CognitiveUnderstandingAnswer, TaskIntentOracle,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub struct CognitiveFieldGradingService;

impl CognitiveFieldGradingService {
    #[allow(clippy::too_many_lines)]
    pub fn validate_suite(suite: &CognitiveFieldSuite) -> CognitiveFieldValidationReport {
        let mut errors = Vec::new();
        if suite.schema_version != COGNITIVE_FIELD_SUITE_SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {COGNITIVE_FIELD_SUITE_SCHEMA_VERSION}"
            ));
        }
        let field_v2 = suite.harness_version == COGNITIVE_FIELD_V2_HARNESS_VERSION;
        let core_qualification =
            suite.harness_version == COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION;
        if !field_v2 && !core_qualification {
            errors.push(format!(
                "harness_version must be {COGNITIVE_FIELD_V2_HARNESS_VERSION} or \
                 {COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION}"
            ));
        }
        if suite.hard_provider_call_cap == 0
            || suite.hard_provider_call_cap > COGNITIVE_FIELD_MAX_PROVIDER_CALLS
        {
            errors.push(format!(
                "provider call cap must be within 1..={COGNITIVE_FIELD_MAX_PROVIDER_CALLS}"
            ));
        }
        if suite.reader_output_schema_ref.trim().is_empty()
            || suite.judge_output_schema_ref.trim().is_empty()
        {
            errors.push("reader and judge schema refs must not be empty".to_owned());
        }
        if suite
            .second_repository
            .environment_variable
            .trim()
            .is_empty()
            || !suite.second_repository.require_real_repository
            || !suite.second_repository.require_permissive_license
            || suite
                .second_repository
                .synthetic_fixture_satisfies_portability
        {
            errors.push(
                "second repository policy must require a real permissively licensed repository"
                    .to_owned(),
            );
        }

        let required_gates = CognitiveHardGateKind::ALL
            .into_iter()
            .collect::<BTreeSet<_>>();
        let published_gates = suite
            .shared_hard_gates
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if published_gates != required_gates
            || suite.shared_hard_gates.len() != required_gates.len()
        {
            errors.push(
                "shared hard gates must contain each canonical hard gate exactly once".into(),
            );
        }

        let mut case_ids = BTreeSet::new();
        let mut ordinals = BTreeSet::new();
        let mut family_counts = BTreeMap::new();
        let required_roles = vec![
            CognitiveFieldRole::CodexWorker,
            CognitiveFieldRole::UnderstandingReader,
            CognitiveFieldRole::CodexJudge,
        ];
        for case in &suite.cases {
            *family_counts.entry(case.family).or_insert(0usize) += 1;
            if !case_ids.insert(case.case_id.clone()) {
                errors.push(format!("duplicate case_id {}", case.case_id));
            }
            if !ordinals.insert(case.ordinal) {
                errors.push(format!("duplicate ordinal {}", case.ordinal));
            }
            if case.case_id != format!("{:?}{:02}", case.family, family_ordinal(case)) {
                errors.push(format!(
                    "case {} does not match its family-local ordinal",
                    case.case_id
                ));
            }
            if case.title.trim().is_empty()
                || case.oracle_ref.trim().is_empty()
                || case.reader_prompt_ref.trim().is_empty()
                || case.deterministic_verifier_refs.is_empty()
                || case
                    .deterministic_verifier_refs
                    .iter()
                    .any(|value| value.trim().is_empty())
            {
                errors.push(format!(
                    "case {} has an empty title, authority ref, prompt ref, or verifier ref",
                    case.case_id
                ));
            }
            if case.model_backed && case.required_roles != required_roles {
                errors.push(format!(
                    "model-backed case {} must use the three isolated roles in canonical order",
                    case.case_id
                ));
            }
            if !case.model_backed && !case.required_roles.is_empty() {
                errors.push(format!(
                    "non-model case {} must not reserve provider roles",
                    case.case_id
                ));
            }
            if case.memory_conditions.is_empty() {
                errors.push(format!(
                    "case {} must declare at least one memory condition",
                    case.case_id
                ));
            }
            let case_gates = case.hard_gates.iter().copied().collect::<BTreeSet<_>>();
            if case_gates.len() != case.hard_gates.len() {
                errors.push(format!("case {} repeats a hard gate", case.case_id));
            }
        }

        if field_v2 {
            if suite.cases.len() != 48 {
                errors.push(format!(
                    "field-v2 suite must contain exactly 48 cases, found {}",
                    suite.cases.len()
                ));
            }
            let expected_ordinals = (1..=48).collect::<BTreeSet<_>>();
            if ordinals != expected_ordinals {
                errors.push("field-v2 suite ordinals must be exactly 1 through 48".to_owned());
            }
            for (family, expected) in [
                (CognitiveFieldFamily::U, 12usize),
                (CognitiveFieldFamily::M, 8),
                (CognitiveFieldFamily::D, 10),
                (CognitiveFieldFamily::A, 6),
                (CognitiveFieldFamily::H, 6),
                (CognitiveFieldFamily::R, 6),
            ] {
                if family_counts.get(&family).copied().unwrap_or_default() != expected {
                    errors.push(format!(
                        "family {family:?} must contain exactly {expected} cases"
                    ));
                }
            }
            match suite.cases.iter().find(|case| case.case_id == "H06") {
                Some(case)
                    if case.repository_condition
                        == CognitiveRepositoryCondition::SecondRepository => {}
                _ => errors.push("H06 must use the real second-repository condition".to_owned()),
            }
            if suite.cases.iter().any(|case| {
                case.repository_condition == CognitiveRepositoryCondition::SecondRepository
                    && case.case_id != "H06"
            }) {
                errors.push("only H06 may declare the second-repository condition".to_owned());
            }
        }
        if core_qualification {
            let expected_case_ids = ["U03", "U06", "U11"]
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>();
            let expected_ordinals = [3_u8, 6, 11].into_iter().collect::<BTreeSet<_>>();
            if case_ids != expected_case_ids
                || ordinals != expected_ordinals
                || suite.cases.len() != 3
            {
                errors.push("core qualification must contain exactly U03, U06, and U11".to_owned());
            }
            if suite.hard_provider_call_cap != COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS {
                errors.push(format!(
                    "core qualification provider call cap must be exactly \
                     {COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS}"
                ));
            }
            let expected_conditions = vec![
                CognitiveMemoryCondition::Treatment,
                CognitiveMemoryCondition::MemoryFreeControl,
            ];
            if suite.cases.iter().any(|case| {
                !case.model_backed
                    || case.repository_condition != CognitiveRepositoryCondition::PrimaryRepository
                    || case.memory_conditions != expected_conditions
            }) {
                errors.push(
                    "core qualification cases must be model-backed primary-repository \
                     treatment/control pairs"
                        .to_owned(),
                );
            }
        }

        CognitiveFieldValidationReport {
            valid: errors.is_empty(),
            errors,
            case_count: suite.cases.len(),
            family_counts,
            model_backed_case_count: suite.cases.iter().filter(|case| case.model_backed).count(),
        }
    }

    pub fn seal_oracle(oracle: &mut TaskIntentOracle) -> Result<(), EngineError> {
        let errors = oracle_validation_errors(oracle);
        if !errors.is_empty() {
            return Err(EngineError::WriteRejected(format!(
                "invalid task-intent oracle: {}",
                errors.join("; ")
            )));
        }
        let mut material = oracle.clone();
        material.oracle_hash.clear();
        oracle.oracle_hash = Self::hash_json(&material)?;
        Ok(())
    }

    pub fn seal_deterministic_report(
        report: &mut CognitiveDeterministicReport,
    ) -> Result<(), EngineError> {
        report.passed = report.schema_version == COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION
            && report.controller_provider_calls == 0
            && report.truth_revision_before == report.truth_revision_after_observability
            && !report.hard_gate_evidence.is_empty()
            && report
                .hard_gate_evidence
                .iter()
                .all(|evidence| evidence.passed && !evidence.evidence_refs.is_empty());
        let mut material = report.clone();
        material.report_hash.clear();
        report.report_hash = Self::hash_json(&material)?;
        Ok(())
    }

    pub fn hash_json<T: Serialize>(value: &T) -> Result<String, EngineError> {
        let encoded = serde_json::to_vec(value)?;
        Ok(format!("blake3:{}", blake3::hash(&encoded).to_hex()))
    }

    pub fn scan_reader_surfaces(
        oracle: &TaskIntentOracle,
        surfaces: &[(String, Vec<u8>)],
    ) -> CognitiveOracleLeakReport {
        let mut hidden_values = vec![
            ("oracle_id", oracle.oracle_id.as_str()),
            ("oracle_hash", oracle.oracle_hash.as_str()),
        ];
        hidden_values.extend(
            oracle
                .acceptable_owner_file_symbol_alternatives
                .iter()
                .map(|value| ("acceptable_owner_file_symbol_alternatives", value.as_str())),
        );
        hidden_values.extend(
            oracle
                .required_invariant_refs
                .iter()
                .map(|value| ("required_invariant_refs", value.as_str())),
        );
        hidden_values.extend(
            oracle
                .required_verifier_refs
                .iter()
                .map(|value| ("required_verifier_refs", value.as_str())),
        );
        hidden_values.extend(
            oracle
                .forbidden_conclusions
                .iter()
                .map(|value| ("forbidden_conclusions", value.as_str())),
        );

        let mut findings = Vec::new();
        for (surface, bytes) in surfaces {
            let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
            for (field, hidden) in &hidden_values {
                if hidden.trim().len() >= 8 && text.contains(&hidden.to_ascii_lowercase()) {
                    findings.push(CognitiveOracleLeakFinding {
                        surface: surface.clone(),
                        field: (*field).to_owned(),
                        value_hash: format!("blake3:{}", blake3::hash(hidden.as_bytes()).to_hex()),
                    });
                }
            }
        }
        CognitiveOracleLeakReport {
            clean: findings.is_empty(),
            scanned_surfaces: surfaces.iter().map(|(label, _)| label.clone()).collect(),
            findings,
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn grade_case(
        suite: &CognitiveFieldSuite,
        case: &CognitiveFieldCase,
        oracle: &TaskIntentOracle,
        reader: &CognitiveUnderstandingAnswer,
        deterministic: &CognitiveDeterministicReport,
        judge: &CognitiveJudgeResult,
    ) -> CognitiveFieldCaseGrade {
        let mut errors = Vec::new();
        if oracle_validation_errors(oracle).is_empty() {
            let mut material = oracle.clone();
            material.oracle_hash.clear();
            match Self::hash_json(&material) {
                Ok(expected) if expected == oracle.oracle_hash => {}
                Ok(_) => {
                    errors.push("oracle hash does not match the sealed oracle body".to_owned());
                }
                Err(error) => errors.push(format!("oracle hash could not be verified: {error}")),
            }
        } else {
            errors.push("oracle contract is invalid".to_owned());
        }

        if reader.schema_version != COGNITIVE_UNDERSTANDING_SCHEMA_VERSION
            || reader.case_id != case.case_id
            || deterministic.case_id != case.case_id
            || judge.case_id != case.case_id
        {
            errors.push("case or reader schema binding is invalid".to_owned());
        }
        if reader.project_id != deterministic.project_id || reader.task_id != deterministic.task_id
        {
            errors.push("project/task binding differs between reader and verifier".to_owned());
        }
        if deterministic.source_commit != oracle.source_commit {
            errors.push("deterministic report source commit differs from oracle".to_owned());
        }
        if reader.expected_observable.trim().is_empty() {
            errors.push("material action has an empty expected observable".to_owned());
        }
        if reader.verifier_ref.trim().is_empty() {
            errors.push("reader omitted the registered verifier ref".to_owned());
        }
        if reader
            .causal_hops
            .iter()
            .any(|hop| hop.status != "unknown" && hop.evidence_refs.is_empty())
        {
            errors.push("reader has a required causal hop without evidence".to_owned());
        }
        if reader.memory_condition == CognitiveMemoryCondition::MemoryFreeControl
            && (!reader.memory_handles_received.is_empty()
                || !reader.memory_handles_expanded.is_empty()
                || !reader.memory_handles_used.is_empty()
                || !reader.influence_receipt_refs.is_empty())
        {
            errors.push("memory-free control contains memory exposure or influence".to_owned());
        }
        let reader_output = serde_json::to_string(reader)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if oracle.forbidden_conclusions.iter().any(|forbidden| {
            forbidden.trim().len() >= 8 && reader_output.contains(&forbidden.to_ascii_lowercase())
        }) {
            errors.push("reader output contains a forbidden private oracle marker".to_owned());
        }

        let mut required_gates = suite.shared_hard_gates.clone();
        required_gates.extend(case.hard_gates.iter().copied());
        required_gates.sort_unstable();
        required_gates.dedup();
        let observed_gates = deterministic
            .hard_gate_evidence
            .iter()
            .map(|evidence| evidence.gate)
            .collect::<Vec<_>>();
        let mut observed_unique = observed_gates.clone();
        observed_unique.sort_unstable();
        observed_unique.dedup();
        if observed_unique != required_gates || observed_unique.len() != observed_gates.len() {
            errors.push("deterministic report does not cover each required hard gate once".into());
        }
        if deterministic.controller_provider_calls != 0 {
            errors.push("controller substitution/provider call is forbidden".to_owned());
        }
        if deterministic.truth_revision_before != deterministic.truth_revision_after_observability {
            errors.push("observability moved the truth revision".to_owned());
        }
        if deterministic
            .hard_gate_evidence
            .iter()
            .any(|evidence| !evidence.passed || evidence.evidence_refs.is_empty())
        {
            errors.push("a deterministic hard gate failed or lacks evidence".to_owned());
        }
        let deterministic_pass = deterministic.passed
            && deterministic.schema_version == COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION
            && deterministic_report_hash_is_valid(deterministic)
            && !errors
                .iter()
                .any(|error| error.contains("deterministic") || error.contains("controller"));
        if !deterministic_report_hash_is_valid(deterministic) {
            errors.push("deterministic report hash is invalid".to_owned());
        }

        if judge.schema_version != COGNITIVE_JUDGE_SCHEMA_VERSION {
            errors.push("judge schema version is invalid".to_owned());
        }
        if judge.oracle_hash != oracle.oracle_hash {
            errors.push("judge oracle hash differs from the sealed oracle".to_owned());
        }
        match Self::hash_json(reader) {
            Ok(hash) if judge.reader_output_hash == hash => {}
            Ok(_) => errors.push("judge reader-output hash is invalid".to_owned()),
            Err(error) => errors.push(format!("reader-output hash failed: {error}")),
        }
        if judge.deterministic_report_hash != deterministic.report_hash {
            errors.push("judge deterministic-report hash is invalid".to_owned());
        }
        let scores = judge.scores.values();
        if scores.iter().any(|score| *score > 5) {
            errors.push("judge score exceeds the 0..5 range".to_owned());
        }
        let sum = scores.iter().map(|score| u16::from(*score)).sum::<u16>();
        let semantic_average_milli = sum.saturating_mul(100);
        let score_semantic_pass = semantic_average_milli >= 4_000
            && scores.iter().all(|score| *score >= 3)
            && !judge.forbidden_conclusion_detected;
        if judge.semantic_pass != score_semantic_pass {
            errors.push("judge semantic_pass contradicts its published scores".to_owned());
        }
        let semantic_pass = judge.semantic_pass && score_semantic_pass;

        CognitiveFieldCaseGrade {
            case_id: case.case_id.clone(),
            deterministic_pass,
            semantic_pass,
            semantic_average_milli,
            passed: errors.is_empty() && deterministic_pass && semantic_pass,
            errors,
        }
    }
}

fn family_ordinal(case: &CognitiveFieldCase) -> usize {
    match case.family {
        CognitiveFieldFamily::U => usize::from(case.ordinal),
        CognitiveFieldFamily::M => usize::from(case.ordinal.saturating_sub(12)),
        CognitiveFieldFamily::D => usize::from(case.ordinal.saturating_sub(20)),
        CognitiveFieldFamily::A => usize::from(case.ordinal.saturating_sub(30)),
        CognitiveFieldFamily::H => usize::from(case.ordinal.saturating_sub(36)),
        CognitiveFieldFamily::R => usize::from(case.ordinal.saturating_sub(42)),
    }
}

fn oracle_validation_errors(oracle: &TaskIntentOracle) -> Vec<String> {
    let mut errors = Vec::new();
    if oracle.schema_version != COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION}"
        ));
    }
    for (name, value) in [
        ("oracle_id", oracle.oracle_id.as_str()),
        (
            "exact_user_prompt_hash",
            oracle.exact_user_prompt_hash.as_str(),
        ),
        (
            "exact_user_prompt_ref",
            oracle.exact_user_prompt_ref.as_str(),
        ),
        ("source_commit", oracle.source_commit.as_str()),
        ("normalized_goal", oracle.normalized_goal.as_str()),
    ] {
        if value.trim().is_empty() {
            errors.push(format!("{name} must not be empty"));
        }
    }
    for (name, values) in [
        ("desired_state", oracle.desired_state.as_slice()),
        ("acceptance_items", oracle.acceptance_items.as_slice()),
        (
            "architecture_constraints",
            oracle.architecture_constraints.as_slice(),
        ),
        (
            "expected_subsystem_set",
            oracle.expected_subsystem_set.as_slice(),
        ),
        (
            "required_invariant_refs",
            oracle.required_invariant_refs.as_slice(),
        ),
        (
            "required_verifier_refs",
            oracle.required_verifier_refs.as_slice(),
        ),
        (
            "authoritative_source_refs",
            oracle.authoritative_source_refs.as_slice(),
        ),
    ] {
        if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
            errors.push(format!("{name} must contain non-empty values"));
        }
    }
    errors
}

fn deterministic_report_hash_is_valid(report: &CognitiveDeterministicReport) -> bool {
    let mut material = report.clone();
    material.report_hash.clear();
    CognitiveFieldGradingService::hash_json(&material)
        .is_ok_and(|expected| expected == report.report_hash)
}
