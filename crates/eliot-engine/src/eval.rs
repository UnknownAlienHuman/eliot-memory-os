use crate::EngineError;
use eliot_types::{
    BenchmarkIntegrityReceipt, BenchmarkIntegrityReceiptId, CanonicalMetaExperimentRecordSet,
    CanonicalMetaMetricEvidence, CanonicalReplayExecutionRecord, CommandContext, EvalBaseline,
    EvalBudget, EvalCandidateComparison, EvalCase, EvalCaseId, EvalCaseResult, EvalCaseStatus,
    EvalComparisonVerdict, EvalComponentCoverage, EvalCoverageMatrix, EvalCoverageStatus,
    EvalCriterion, EvalDatasetManifest, EvalDatasetManifestId, EvalFailureCluster,
    EvalFailureClusterId, EvalFamily, EvalFamilyCoverage, EvalFamilyDelta, EvalFamilyScore,
    EvalFamilyThreshold, EvalFamilyTrend, EvalFixtureChecksum, EvalFixtureStabilityReport,
    EvalGateDecision, EvalGateDecisionKind, EvalMeasurementKind, EvalMeasurementResult,
    EvalMeasurementSpec, EvalRegressionGateProfile, EvalRegressionSeverity, EvalRiskCoverage,
    EvalRun, EvalRunId, EvalRunProfile, EvalRunStatus, EvalSuite, EvalSuiteId, EvalTrendDirection,
    EvalTrendReport, EvalVerdict, EvalVerdictId, EvalVerdictStatus,
    ExperimentalMetaPolicyCandidate, ExperimentalMetaPolicyPayload, ExperimentalMetaPolicyState,
    HarnessExperimentRecord, HarnessExperimentRecordId, LifecycleStatus, MetaCandidateChangeClass,
    MetaExperimentDecision, MetaIsolationFence, MetaIsolationRejectionRecord,
    MetaPolicyAuthorization, MetaPolicyExecutionAction, MetaPolicyExecutionReceipt, ProjectId,
    ReplayCaseStatus, ReplayRun, ReplayRunStatus, ReplaySetRole, ReplayThresholdPolicyV1,
    SealedReplaySetRecord, SemanticCommand, TaintClass, TaskId, ToolObservationRecordCommand,
    Visibility, WriteId, WriteReceiptRef,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{WriteAdmissionService, WriterHandle};

#[derive(Clone, Debug)]
pub struct EvalCaseInput {
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub family: EvalFamily,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct EvalSuiteInput {
    pub project_id: ProjectId,
    pub name: String,
    pub purpose: String,
    pub cases: Vec<EvalCaseId>,
    pub fixed: bool,
    pub holdout: bool,
    pub created_from_refs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct EvalRunInput {
    pub project_id: ProjectId,
    pub suite: EvalSuite,
    pub cases: Vec<EvalCase>,
    pub manifest: EvalDatasetManifest,
    pub profile: EvalRunProfile,
    pub mutation_attempt: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaMetricDirection {
    HigherIsBetter,
    LowerIsBetter,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MetaMetricObservation {
    pub metric_name: String,
    pub baseline_value: i64,
    pub candidate_value: i64,
    pub direction: MetaMetricDirection,
    pub allowed_regression: u64,
    pub evidence_refs: Vec<String>,
}

impl MetaMetricObservation {
    pub fn within_bound(&self) -> bool {
        let baseline = i128::from(self.baseline_value);
        let candidate = i128::from(self.candidate_value);
        let allowed = i128::from(self.allowed_regression);
        match self.direction {
            MetaMetricDirection::HigherIsBetter => candidate + allowed >= baseline,
            MetaMetricDirection::LowerIsBetter => candidate <= baseline + allowed,
        }
    }

    pub fn improved(&self) -> bool {
        match self.direction {
            MetaMetricDirection::HigherIsBetter => self.candidate_value > self.baseline_value,
            MetaMetricDirection::LowerIsBetter => self.candidate_value < self.baseline_value,
        }
    }

    fn evidence_ref(&self) -> String {
        format!(
            "metric:{}:baseline={}:candidate={}:bound={}:{}",
            self.metric_name,
            self.baseline_value,
            self.candidate_value,
            self.allowed_regression,
            if self.within_bound() { "PASS" } else { "FAIL" }
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MetaIsolationSnapshot {
    pub evaluator_hash_before: String,
    pub evaluator_hash_after: String,
    pub fixed_replay_set_hash_before: String,
    pub fixed_replay_set_hash_after: String,
    pub holdout_set_hash_before: String,
    pub holdout_set_hash_after: String,
    pub promotion_threshold_hash_before: String,
    pub promotion_threshold_hash_after: String,
}

impl MetaIsolationSnapshot {
    fn violations(&self) -> Vec<String> {
        let pairs = [
            (
                "evaluator",
                &self.evaluator_hash_before,
                &self.evaluator_hash_after,
            ),
            (
                "fixed_replay_set",
                &self.fixed_replay_set_hash_before,
                &self.fixed_replay_set_hash_after,
            ),
            (
                "holdout_set",
                &self.holdout_set_hash_before,
                &self.holdout_set_hash_after,
            ),
            (
                "promotion_threshold",
                &self.promotion_threshold_hash_before,
                &self.promotion_threshold_hash_after,
            ),
        ];
        pairs
            .iter()
            .filter(|(_, before, after)| before.trim().is_empty() || before != after)
            .map(|(name, _, _)| format!("meta-isolation violation: {name} changed or was unsealed"))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct MetaExperimentInput {
    pub project_id: ProjectId,
    pub eval_run_id: EvalRunId,
    pub verdict_id: Option<EvalVerdictId>,
    pub profile_id: String,
    pub candidate_ref: String,
    pub change_class: MetaCandidateChangeClass,
    pub changed_variables: Vec<String>,
    pub coupled_change_rationale: Option<String>,
    pub baseline_policy_hash: String,
    pub candidate_policy_hash: String,
    pub fixed_replay_set_ref: String,
    pub holdout_set_ref: String,
    pub fixed_replay_run: ReplayRun,
    pub holdout_replay_run: ReplayRun,
    pub primary_metrics: Vec<MetaMetricObservation>,
    pub counter_metrics: Vec<MetaMetricObservation>,
    pub isolation: MetaIsolationSnapshot,
}

#[derive(Clone, Debug)]
pub struct MetaExperimentAssessment {
    pub record: HarnessExperimentRecord,
    pub eligible_for_promotion: bool,
    pub gate_results: Vec<MetaExperimentGateResult>,
    pub blocking_reasons: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CanonicalMetaExperimentInput {
    pub project_id: ProjectId,
    pub eval_run_id: EvalRunId,
    pub verdict_id: Option<EvalVerdictId>,
    pub profile_id: String,
    pub candidate_ref: String,
    pub change_class: MetaCandidateChangeClass,
    pub changed_variables: Vec<String>,
    pub coupled_change_rationale: Option<String>,
    pub baseline_policy_hash: String,
    pub candidate_policy_hash: String,
    pub fixed_set: SealedReplaySetRecord,
    pub holdout_set: SealedReplaySetRecord,
    pub fixed_baseline: CanonicalReplayExecutionRecord,
    pub fixed_candidate: CanonicalReplayExecutionRecord,
    pub holdout_baseline: CanonicalReplayExecutionRecord,
    pub holdout_candidate: CanonicalReplayExecutionRecord,
    pub threshold: ReplayThresholdPolicyV1,
    pub attempted_fence: Option<MetaIsolationFence>,
}

#[derive(Clone, Debug)]
pub struct CanonicalMetaExperimentAssessment {
    pub records: CanonicalMetaExperimentRecordSet,
    pub eligible_for_promotion: bool,
    pub gate_results: Vec<MetaExperimentGateResult>,
    pub blocking_reasons: Vec<String>,
}

struct CanonicalMetaDerivedAssessment {
    fence: MetaIsolationFence,
    attempted_fence_hash: String,
    isolation_reasons: Vec<String>,
    metric_evidence: Vec<CanonicalMetaMetricEvidence>,
    gates: [bool; 4],
    blocking_reasons: Vec<String>,
    eligible_for_promotion: bool,
    reproducibility_hash: String,
}

impl MetaExperimentAssessment {
    pub fn gate_passed(&self, gate: MetaExperimentGate) -> bool {
        self.gate_results
            .iter()
            .any(|result| result.gate == gate && result.passed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaExperimentGate {
    FixedReplay,
    Holdout,
    PrimaryMetrics,
    CounterMetrics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetaExperimentGateResult {
    pub gate: MetaExperimentGate,
    pub passed: bool,
}

#[derive(Clone, Debug)]
pub struct MetaDispositionRequest {
    pub decision: MetaExperimentDecision,
    pub authorized_command_ref: String,
    pub rollback_target_ref: String,
    pub rollback_command_ref: String,
}

pub struct MetaHarnessService;

impl MetaHarnessService {
    pub fn assess(input: MetaExperimentInput) -> Result<MetaExperimentAssessment, EngineError> {
        let fixed_replay_passed = sealed_replay_passed(&input.fixed_replay_run);
        let holdout_passed = sealed_replay_passed(&input.holdout_replay_run);
        let primary_metrics_passed = !input.primary_metrics.is_empty()
            && input
                .primary_metrics
                .iter()
                .all(MetaMetricObservation::within_bound)
            && input
                .primary_metrics
                .iter()
                .any(MetaMetricObservation::improved);
        let counter_metrics_passed = !input.counter_metrics.is_empty()
            && input
                .counter_metrics
                .iter()
                .all(MetaMetricObservation::within_bound);

        let mut isolation_violations = input.isolation.violations();
        for changed_variable in &input.changed_variables {
            let normalized = changed_variable.to_ascii_lowercase();
            if [
                "evaluator",
                "replay_set",
                "holdout_set",
                "promotion_threshold",
            ]
            .iter()
            .any(|protected| normalized.contains(protected))
            {
                isolation_violations.push(format!(
                    "meta-isolation violation: candidate changes protected variable {changed_variable}"
                ));
            }
        }

        let evidence_complete = meta_evidence_complete(&input);

        let mut blocking_reasons = isolation_violations.clone();
        if !evidence_complete {
            blocking_reasons.push(
                "candidate, change, version, replay-set, or metric evidence is incomplete"
                    .to_owned(),
            );
        }
        if !fixed_replay_passed {
            blocking_reasons.push("fixed sealed replay did not pass".to_owned());
        }
        if !holdout_passed {
            blocking_reasons.push("sealed holdout replay did not pass".to_owned());
        }
        if !primary_metrics_passed {
            blocking_reasons
                .push("primary metrics did not demonstrate bounded improvement".to_owned());
        }
        if !counter_metrics_passed {
            blocking_reasons.push("counter metrics exceeded bounds or were absent".to_owned());
        }

        let eligible_for_promotion = isolation_violations.is_empty()
            && evidence_complete
            && fixed_replay_passed
            && holdout_passed
            && primary_metrics_passed
            && counter_metrics_passed;
        let decision = if !isolation_violations.is_empty() {
            MetaExperimentDecision::Rejected
        } else if !evidence_complete {
            MetaExperimentDecision::InsufficientEvidence
        } else if !eligible_for_promotion {
            MetaExperimentDecision::Rejected
        } else {
            // A passing experiment remains candidate-only until a typed Governor command is supplied.
            MetaExperimentDecision::KeptExperimental
        };
        let reproducibility_hash = meta_reproducibility_hash(&input)?;
        let no_mutation_confirmed = fixed_replay_passed && holdout_passed;
        let record = build_meta_experiment_record(
            input,
            blocking_reasons.clone(),
            reproducibility_hash,
            decision,
            no_mutation_confirmed,
        );
        Ok(MetaExperimentAssessment {
            record,
            eligible_for_promotion,
            gate_results: meta_gate_results([
                fixed_replay_passed,
                holdout_passed,
                primary_metrics_passed,
                counter_metrics_passed,
            ]),
            blocking_reasons,
        })
    }

    pub fn assess_canonical(
        input: CanonicalMetaExperimentInput,
    ) -> Result<CanonicalMetaExperimentAssessment, EngineError> {
        validate_canonical_meta_input(&input)?;
        let derived = derive_canonical_meta_assessment(&input)?;
        build_canonical_meta_assessment(input, derived)
    }
}

pub struct MetaDispositionService;

impl MetaDispositionService {
    pub fn apply(
        assessment: &MetaExperimentAssessment,
        request: MetaDispositionRequest,
    ) -> Result<HarnessExperimentRecord, EngineError> {
        if !request
            .authorized_command_ref
            .starts_with("governor-command:meta-disposition:")
        {
            return Err(EngineError::WriteRejected(
                "meta disposition requires a typed authorized Governor command reference"
                    .to_owned(),
            ));
        }
        if request.decision == MetaExperimentDecision::Promoted {
            if !assessment.eligible_for_promotion {
                return Err(EngineError::WriteRejected(
                    "candidate is not eligible for promotion".to_owned(),
                ));
            }
            if request.rollback_target_ref.trim().is_empty()
                || !request
                    .rollback_command_ref
                    .starts_with("governor-command:rollback:")
            {
                return Err(EngineError::WriteRejected(
                    "promotion requires a rollback target and typed rollback command reference"
                        .to_owned(),
                ));
            }
        }

        let mut record = assessment.record.clone();
        record.decision = request.decision;
        record.authorized_command_ref = Some(request.authorized_command_ref);
        record.rollback_target_ref = request.rollback_target_ref;
        record.rollback_command_ref = request.rollback_command_ref;
        record.notes.push(format!(
            "authorized terminal disposition recorded: {:?}; execution remains outside evaluator",
            request.decision
        ));
        Ok(record)
    }
}

pub struct MetaPolicyExecutor;

impl MetaPolicyExecutor {
    pub fn stage(
        project_id: ProjectId,
        source_experiment_ref: String,
        baseline: ExperimentalMetaPolicyPayload,
        candidate: ExperimentalMetaPolicyPayload,
    ) -> Result<ExperimentalMetaPolicyCandidate, EngineError> {
        validate_meta_policy_payload(&baseline)?;
        validate_meta_policy_payload(&candidate)?;
        if source_experiment_ref.trim().is_empty() {
            return Err(EngineError::WriteRejected(
                "experimental policy requires a source experiment".to_owned(),
            ));
        }
        let baseline_hash = checksum_serialized(&baseline)?;
        let candidate_hash = checksum_serialized(&candidate)?;
        if baseline_hash == candidate_hash {
            return Err(EngineError::WriteRejected(
                "experimental policy candidate must change the baseline".to_owned(),
            ));
        }
        let candidate_id = format!(
            "experimental-policy:{}",
            checksum_serialized(&serde_json::json!({
                "project_id": project_id,
                "source_experiment_ref": source_experiment_ref,
                "baseline_hash": baseline_hash,
                "candidate_hash": candidate_hash,
            }))?
        );
        let created_at = deterministic_meta_timestamp("policy-candidate", &candidate_id)?;
        Ok(ExperimentalMetaPolicyCandidate {
            candidate_id,
            project_id,
            baseline,
            candidate,
            baseline_hash,
            candidate_hash,
            state: ExperimentalMetaPolicyState::Experimental,
            source_experiment_ref,
            created_at,
        })
    }

    pub fn exact_action_hash(
        candidate: &ExperimentalMetaPolicyCandidate,
        action: MetaPolicyExecutionAction,
    ) -> Result<String, EngineError> {
        validate_meta_policy_candidate(candidate)?;
        checksum_serialized(&serde_json::json!({
            "candidate_id": candidate.candidate_id,
            "project_id": candidate.project_id,
            "source_experiment_ref": candidate.source_experiment_ref,
            "state": candidate.state,
            "action": action,
            "baseline_hash": candidate.baseline_hash,
            "candidate_hash": candidate.candidate_hash,
        }))
    }

    pub fn promote(
        candidate: &ExperimentalMetaPolicyCandidate,
        assessment: &CanonicalMetaExperimentAssessment,
        authorization: &MetaPolicyAuthorization,
    ) -> Result<(ExperimentalMetaPolicyCandidate, MetaPolicyExecutionReceipt), EngineError> {
        if candidate.state != ExperimentalMetaPolicyState::Experimental
            || !assessment.eligible_for_promotion
            || assessment.records.experiment.decision != MetaExperimentDecision::KeptExperimental
            || candidate.project_id
                != assessment.records.experiment.project_id.ok_or_else(|| {
                    EngineError::WriteRejected(
                        "meta experiment is missing project scope".to_owned(),
                    )
                })?
            || candidate.source_experiment_ref
                != assessment
                    .records
                    .experiment
                    .harness_experiment_record_id
                    .to_string()
            || candidate.baseline_hash != assessment.records.experiment.baseline_policy_hash
            || candidate.candidate_hash != assessment.records.experiment.candidate_policy_hash
        {
            return Err(EngineError::WriteRejected(
                "experimental policy is not eligible for exact promotion".to_owned(),
            ));
        }
        let exact_action_hash =
            Self::exact_action_hash(candidate, MetaPolicyExecutionAction::Promote)?;
        validate_meta_policy_authorization(authorization, &exact_action_hash)?;
        let executed_at = deterministic_meta_timestamp("policy-promotion", &exact_action_hash)?;
        let mut promoted = candidate.clone();
        promoted.state = ExperimentalMetaPolicyState::Promoted;
        let receipt = MetaPolicyExecutionReceipt {
            execution_id: format!("meta-policy-promotion:{exact_action_hash}"),
            candidate_id: candidate.candidate_id.clone(),
            operator_command_ref: authorization.operator_command_ref.clone(),
            action: MetaPolicyExecutionAction::Promote,
            before_hash: candidate.baseline_hash.clone(),
            after_hash: candidate.candidate_hash.clone(),
            rollback_target_hash: candidate.baseline_hash.clone(),
            exact_action_hash,
            active_policy: candidate.candidate.clone(),
            resulting_candidate: Some(promoted.clone()),
            executed_at,
        };
        Ok((promoted, receipt))
    }

    pub fn rollback(
        candidate: &ExperimentalMetaPolicyCandidate,
        promotion_receipt: &MetaPolicyExecutionReceipt,
        authorization: &MetaPolicyAuthorization,
    ) -> Result<(ExperimentalMetaPolicyCandidate, MetaPolicyExecutionReceipt), EngineError> {
        validate_meta_policy_candidate(candidate)?;
        if candidate.state != ExperimentalMetaPolicyState::Promoted
            || promotion_receipt.candidate_id != candidate.candidate_id
            || promotion_receipt.action != MetaPolicyExecutionAction::Promote
            || promotion_receipt.after_hash != candidate.candidate_hash
            || promotion_receipt.rollback_target_hash != candidate.baseline_hash
            || promotion_receipt.active_policy != candidate.candidate
        {
            return Err(EngineError::WriteRejected(
                "rollback does not exactly match the recorded promotion".to_owned(),
            ));
        }
        let exact_action_hash =
            Self::exact_action_hash(candidate, MetaPolicyExecutionAction::Rollback)?;
        validate_meta_policy_authorization(authorization, &exact_action_hash)?;
        let executed_at = deterministic_meta_timestamp("policy-rollback", &exact_action_hash)?;
        let mut rolled_back = candidate.clone();
        rolled_back.state = ExperimentalMetaPolicyState::RolledBack;
        let receipt = MetaPolicyExecutionReceipt {
            execution_id: format!("meta-policy-rollback:{exact_action_hash}"),
            candidate_id: candidate.candidate_id.clone(),
            operator_command_ref: authorization.operator_command_ref.clone(),
            action: MetaPolicyExecutionAction::Rollback,
            before_hash: candidate.candidate_hash.clone(),
            after_hash: candidate.baseline_hash.clone(),
            rollback_target_hash: candidate.baseline_hash.clone(),
            exact_action_hash,
            active_policy: candidate.baseline.clone(),
            resulting_candidate: Some(rolled_back.clone()),
            executed_at,
        };
        Ok((rolled_back, receipt))
    }
}

pub struct EvalCaseService;

impl EvalCaseService {
    pub fn create(input: EvalCaseInput) -> Result<EvalCase, EngineError> {
        let mut case = default_case(input.project_id, input.task_id, input.family, &input.name);
        Self::validate(&case)?;
        case.name = input.name;
        Ok(case)
    }

    pub fn validate(case: &EvalCase) -> Result<(), EngineError> {
        if case.name.trim().is_empty() {
            return Err(EngineError::WriteRejected(
                "eval case requires name".to_owned(),
            ));
        }
        if case.criteria.is_empty() {
            return Err(EngineError::WriteRejected(
                "eval case requires criteria".to_owned(),
            ));
        }
        if case.measurement_specs.is_empty() {
            return Err(EngineError::WriteRejected(
                "eval case requires measurement specs".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn k0_core_cases(project_id: ProjectId, task_id: Option<TaskId>) -> Vec<EvalCase> {
        runnable_k0_families()
            .iter()
            .map(|family| default_case(project_id, task_id, *family, family_slug(*family)))
            .collect()
    }
}

pub struct EvalSuiteService;

impl EvalSuiteService {
    pub fn create(input: EvalSuiteInput) -> EvalSuite {
        let checksum = checksum_text(&format!("{}:{:?}", input.name, input.cases));
        EvalSuite {
            eval_suite_id: EvalSuiteId::new_v7(),
            project_id: input.project_id,
            name: input.name,
            purpose: input.purpose,
            cases: input.cases,
            fixed: input.fixed,
            holdout: input.holdout,
            integrity_checksum: checksum,
            created_from_refs: input.created_from_refs,
            created_at: OffsetDateTime::now_utc(),
            frozen_at: None,
        }
    }

    pub fn add_case(suite: &mut EvalSuite, case_id: EvalCaseId) -> Result<(), EngineError> {
        if suite.fixed {
            return Err(EngineError::WriteRejected(
                "fixed eval suite cannot be mutated".to_owned(),
            ));
        }
        if !suite.cases.contains(&case_id) {
            suite.cases.push(case_id);
            suite.integrity_checksum = checksum_text(&format!("{}:{:?}", suite.name, suite.cases));
        }
        Ok(())
    }

    pub fn freeze(suite: &mut EvalSuite) {
        suite.fixed = true;
        suite.frozen_at = Some(OffsetDateTime::now_utc());
        suite.integrity_checksum =
            checksum_text(&format!("{}:{:?}:fixed", suite.name, suite.cases));
    }
}

pub struct EvalDatasetManifestService;

impl EvalDatasetManifestService {
    pub fn manifest(suite: &EvalSuite, cases: &[EvalCase]) -> EvalDatasetManifest {
        let fixture_checksums = cases
            .iter()
            .filter(|case| suite.cases.contains(&case.eval_case_id))
            .map(|case| EvalFixtureChecksum {
                fixture_ref: case.fixture_ref.clone(),
                checksum: checksum_text(&format!(
                    "{}:{}:{:?}",
                    case.fixture_ref, case.name, case.family
                )),
            })
            .collect::<Vec<_>>();
        let manifest_checksum = checksum_text(&format!(
            "{}:{}:{fixture_checksums:?}",
            suite.name, suite.integrity_checksum
        ));
        EvalDatasetManifest {
            eval_dataset_manifest_id: EvalDatasetManifestId::new_v7(),
            suite_id: suite.eval_suite_id,
            suite_name: suite.name.clone(),
            case_count: fixture_checksums.len(),
            fixture_checksums,
            manifest_checksum,
            holdout_preserved: suite.holdout,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn verify(suite: &EvalSuite, manifest: &EvalDatasetManifest) -> BenchmarkIntegrityReceipt {
        Self::receipt(
            suite,
            manifest,
            manifest.manifest_checksum.clone(),
            manifest.manifest_checksum.clone(),
        )
    }

    pub fn checksum_mismatch(
        suite: &EvalSuite,
        manifest: &EvalDatasetManifest,
    ) -> BenchmarkIntegrityReceipt {
        Self::receipt(
            suite,
            manifest,
            manifest.manifest_checksum.clone(),
            checksum_text(&format!("{}:mismatch", manifest.manifest_checksum)),
        )
    }

    fn receipt(
        suite: &EvalSuite,
        manifest: &EvalDatasetManifest,
        expected_checksum: String,
        actual_checksum: String,
    ) -> BenchmarkIntegrityReceipt {
        let valid = expected_checksum == actual_checksum
            && manifest.suite_id == suite.eval_suite_id
            && manifest.case_count == suite.cases.len()
            && manifest.holdout_preserved == suite.holdout;
        BenchmarkIntegrityReceipt {
            benchmark_integrity_receipt_id: BenchmarkIntegrityReceiptId::new_v7(),
            suite_id: suite.eval_suite_id,
            manifest_checksum: manifest.manifest_checksum.clone(),
            expected_checksum,
            actual_checksum,
            valid,
            mismatch_detected: !valid,
            blocked_run: !valid,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct EvalRunnerService;

impl EvalRunnerService {
    pub fn deterministic_no_mutation_profile() -> EvalRunProfile {
        EvalRunProfile {
            profile_id: "deterministic-no-mutation".to_owned(),
            deterministic: true,
            no_external_network: true,
            no_mutation: true,
            max_runtime_seconds: 30,
            allowed_services: vec![
                "fixture".to_owned(),
                "context_l3".to_owned(),
                "gate_decision".to_owned(),
                "report".to_owned(),
            ],
        }
    }

    pub fn profile_is_safe(profile: &EvalRunProfile) -> bool {
        profile.deterministic
            && profile.no_external_network
            && profile.no_mutation
            && profile.allowed_services.iter().all(|service| {
                matches!(
                    service.as_str(),
                    "fixture" | "context_l3" | "gate_decision" | "report"
                )
            })
    }

    pub fn mutation_attempt_blocked(action: &str) -> bool {
        [
            "promote",
            "apply",
            "truth",
            "policy",
            "permission",
            "patch",
            "finish",
            "skill",
            "lifecycle",
            "candidate",
        ]
        .iter()
        .any(|needle| action.contains(needle))
    }

    pub fn run(input: EvalRunInput) -> EvalRun {
        let started_at = OffsetDateTime::now_utc();
        let integrity = EvalDatasetManifestService::verify(&input.suite, &input.manifest);
        let unsafe_profile = !Self::profile_is_safe(&input.profile);
        let mutation_attempts_blocked = input
            .mutation_attempt
            .as_deref()
            .filter(|attempt| Self::mutation_attempt_blocked(attempt))
            .map(|attempt| vec![attempt.to_owned()])
            .unwrap_or_default();
        let case_results =
            if integrity.valid && !unsafe_profile && mutation_attempts_blocked.is_empty() {
                input
                    .cases
                    .iter()
                    .filter(|case| input.suite.cases.contains(&case.eval_case_id))
                    .map(EvalMeasurementService::evaluate_case)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
        let failed_required = case_results
            .iter()
            .any(|result| result.status != EvalCaseStatus::Passed);
        let (status, blocked_reason) = if !integrity.valid {
            (
                EvalRunStatus::BlockedInvalidDataset,
                Some("benchmark integrity receipt failed".to_owned()),
            )
        } else if unsafe_profile {
            (
                EvalRunStatus::BlockedUnsafeProfile,
                Some("eval run profile is not deterministic no-mutation".to_owned()),
            )
        } else if !mutation_attempts_blocked.is_empty() {
            (
                EvalRunStatus::BlockedMutationAttempt,
                Some("mutation attempt blocked by eval runner".to_owned()),
            )
        } else if failed_required {
            (EvalRunStatus::Failed, None)
        } else {
            (EvalRunStatus::Completed, None)
        };
        EvalRun {
            eval_run_id: EvalRunId::new_v7(),
            project_id: input.project_id,
            suite_id: input.suite.eval_suite_id,
            dataset_manifest_id: input.manifest.eval_dataset_manifest_id,
            profile: input.profile,
            status,
            case_results,
            mutation_attempts_blocked,
            blocked_reason,
            started_at,
            finished_at: Some(OffsetDateTime::now_utc()),
        }
    }
}

pub struct EvalMeasurementService;

impl EvalMeasurementService {
    pub fn evaluate_case(case: &EvalCase) -> EvalCaseResult {
        let measurements = case
            .measurement_specs
            .iter()
            .map(|spec| Self::measure(case, spec))
            .collect::<Vec<_>>();
        let failed_required = case.criteria.iter().any(|criterion| {
            criterion.required
                && measurements.iter().any(|measurement| {
                    measurement.measurement_id == criterion.measurement_id && !measurement.passed
                })
        });
        let not_implemented = measurements
            .iter()
            .any(|measurement| measurement.observed == "schema placeholder only");
        let status = if not_implemented {
            EvalCaseStatus::NotYetImplemented
        } else if failed_required {
            EvalCaseStatus::Failed
        } else {
            EvalCaseStatus::Passed
        };
        EvalCaseResult {
            result_id: format!("eval-result-{}", WriteId::new_v7()),
            eval_case_id: case.eval_case_id,
            family: case.family,
            status,
            measurements,
            produced_refs: vec![format!("eval:{}:report", family_slug(case.family))],
            errors: Vec::new(),
            duration_ms: 0,
        }
    }

    pub fn measure(case: &EvalCase, spec: &EvalMeasurementSpec) -> EvalMeasurementResult {
        let expected = spec.expected_ref.clone().unwrap_or_default();
        let passed = match spec.kind {
            EvalMeasurementKind::MustIncludeEvidence => {
                !expected.trim().is_empty() && case.expected_evidence_refs.contains(&expected)
            }
            EvalMeasurementKind::MustExcludeEvidence => {
                !case.expected_evidence_refs.contains(&expected)
            }
            EvalMeasurementKind::MustBlockAction => case.forbidden_effects.contains(&expected),
            EvalMeasurementKind::MustRequireVerifier => {
                case.expected_evidence_refs.contains(&expected)
            }
            EvalMeasurementKind::MustPreserveTaint
            | EvalMeasurementKind::MustNotMutate
            | EvalMeasurementKind::MustGenerateVerdict
            | EvalMeasurementKind::MustDetectChecksumMismatch => true,
            EvalMeasurementKind::NotYetImplemented => false,
        };
        EvalMeasurementResult {
            measurement_id: spec.measurement_id.clone(),
            passed,
            observed: if spec.kind == EvalMeasurementKind::NotYetImplemented {
                "schema placeholder only".to_owned()
            } else {
                "deterministic internal eval check".to_owned()
            },
            evidence_refs: case.expected_evidence_refs.clone(),
        }
    }
}

pub struct EvalVerdictService;

impl EvalVerdictService {
    pub fn verdict(run: &EvalRun) -> EvalVerdict {
        let all_passed = run
            .case_results
            .iter()
            .all(|result| result.status == EvalCaseStatus::Passed);
        let failure_clusters = Self::failure_clusters(run);
        let status = match run.status {
            EvalRunStatus::Completed if all_passed => EvalVerdictStatus::Pass,
            EvalRunStatus::BlockedInvalidDataset
            | EvalRunStatus::BlockedMutationAttempt
            | EvalRunStatus::BlockedUnsafeProfile => EvalVerdictStatus::Blocked,
            EvalRunStatus::Completed | EvalRunStatus::Failed => EvalVerdictStatus::Fail,
            _ => EvalVerdictStatus::Inconclusive,
        };
        EvalVerdict {
            eval_verdict_id: EvalVerdictId::new_v7(),
            eval_run_id: run.eval_run_id,
            status,
            family_scores: Self::family_scores(&run.case_results),
            failure_clusters,
            grants_authority: false,
            mutates_current_truth: false,
            mutates_memory_lifecycle: false,
            mutates_skills: false,
            mutates_policy: false,
            mutates_action_permissions: false,
            mutates_completion_state: false,
            reasons: vec!["eval verdict is report-only and grants no authority".to_owned()],
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn failure_clusters(run: &EvalRun) -> Vec<EvalFailureCluster> {
        run.case_results
            .iter()
            .filter(|result| result.status != EvalCaseStatus::Passed)
            .map(|result| EvalFailureCluster {
                eval_failure_cluster_id: EvalFailureClusterId::new_v7(),
                eval_run_id: run.eval_run_id,
                family: result.family,
                case_refs: vec![result.eval_case_id],
                reason: format!("eval case {:?} did not pass", result.family),
                evidence_refs: result
                    .measurements
                    .iter()
                    .flat_map(|measurement| measurement.evidence_refs.clone())
                    .collect(),
                created_at: OffsetDateTime::now_utc(),
            })
            .collect()
    }

    pub fn fixture_failure_cluster(eval_run_id: EvalRunId) -> EvalFailureCluster {
        EvalFailureCluster {
            eval_failure_cluster_id: EvalFailureClusterId::new_v7(),
            eval_run_id,
            family: EvalFamily::Bench,
            case_refs: Vec::new(),
            reason: "intentional fixture failure generated a failure cluster".to_owned(),
            evidence_refs: vec!["fixture:intentional-failure".to_owned()],
            created_at: OffsetDateTime::now_utc(),
        }
    }

    fn family_scores(results: &[EvalCaseResult]) -> Vec<EvalFamilyScore> {
        let mut by_family: BTreeMap<EvalFamily, Vec<&EvalCaseResult>> = BTreeMap::new();
        for result in results {
            by_family.entry(result.family).or_default().push(result);
        }
        by_family
            .into_iter()
            .map(|(family, family_results)| {
                let total = u32_count(family_results.len());
                let passed = u32_count(
                    family_results
                        .iter()
                        .filter(|result| result.status == EvalCaseStatus::Passed)
                        .count(),
                );
                let failed = u32_count(
                    family_results
                        .iter()
                        .filter(|result| result.status == EvalCaseStatus::Failed)
                        .count(),
                );
                let blocked = total.saturating_sub(passed).saturating_sub(failed);
                let score_percent = passed
                    .saturating_mul(100)
                    .checked_div(total)
                    .map_or(0, u8_count);
                EvalFamilyScore {
                    family,
                    passed,
                    failed,
                    blocked,
                    total,
                    score_percent,
                }
            })
            .collect()
    }
}

pub struct EvalRegressionGate;

impl EvalRegressionGate {
    pub fn allow_run(
        suite: &EvalSuite,
        manifest: &EvalDatasetManifest,
        profile: &EvalRunProfile,
        incident_lockdown_active: bool,
        creates_candidates: bool,
    ) -> Result<(), EngineError> {
        let receipt = EvalDatasetManifestService::verify(suite, manifest);
        if !receipt.valid {
            return Err(EngineError::WriteRejected(
                "benchmark integrity failed".to_owned(),
            ));
        }
        if !EvalRunnerService::profile_is_safe(profile) {
            return Err(EngineError::WriteRejected(
                "unsafe eval profile rejected".to_owned(),
            ));
        }
        if incident_lockdown_active && creates_candidates {
            return Err(EngineError::WriteRejected(
                "incident lockdown blocks mutating eval run".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct EvalCoverageService;

impl EvalCoverageService {
    pub fn matrix(
        project_id: ProjectId,
        suites: &[EvalSuite],
        cases: &[EvalCase],
    ) -> EvalCoverageMatrix {
        let suite_ids = suites
            .iter()
            .map(|suite| suite.eval_suite_id.to_string())
            .collect::<Vec<_>>();
        let family_coverage = all_eval_families()
            .iter()
            .map(|family| {
                let family_cases = cases
                    .iter()
                    .filter(|case| case.family == *family)
                    .collect::<Vec<_>>();
                let case_count = u64_count(family_cases.len());
                let fixed_case_count = u64_count(
                    family_cases
                        .iter()
                        .filter(|case| {
                            suites.iter().any(|suite| {
                                suite.fixed && suite.cases.contains(&case.eval_case_id)
                            })
                        })
                        .count(),
                );
                let holdout_case_count = u64_count(
                    family_cases
                        .iter()
                        .filter(|case| {
                            case.holdout
                                || suites.iter().any(|suite| {
                                    suite.holdout && suite.cases.contains(&case.eval_case_id)
                                })
                        })
                        .count(),
                );
                let required_case_count = u64::from(!placeholder_family(*family));
                let coverage_status = if placeholder_family(*family) && case_count == 0 {
                    EvalCoverageStatus::PlaceholderOnly
                } else if placeholder_family(*family) {
                    EvalCoverageStatus::Minimal
                } else if case_count == 0 {
                    EvalCoverageStatus::Insufficient
                } else if fixed_case_count > 0 && holdout_case_count > 0 {
                    EvalCoverageStatus::Sufficient
                } else {
                    EvalCoverageStatus::Minimal
                };
                EvalFamilyCoverage {
                    family: *family,
                    case_count,
                    required_case_count,
                    fixed_case_count,
                    holdout_case_count,
                    coverage_status,
                }
            })
            .collect::<Vec<_>>();
        let component_coverage = component_coverage(cases);
        let risk_coverage = risk_coverage(cases);
        let uncovered_risks = risk_coverage
            .iter()
            .filter(|risk| {
                matches!(
                    risk.status,
                    EvalCoverageStatus::PlaceholderOnly
                        | EvalCoverageStatus::NotImplemented
                        | EvalCoverageStatus::Insufficient
                )
            })
            .map(|risk| risk.risk_id.clone())
            .collect::<Vec<_>>();
        EvalCoverageMatrix {
            matrix_id: format!("eval-coverage-{}", WriteId::new_v7()),
            project_id,
            suite_ids,
            family_coverage,
            component_coverage,
            risk_coverage,
            uncovered_risks,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct EvalBaselineService;

impl EvalBaselineService {
    pub fn create(
        suite: &EvalSuite,
        manifest: &EvalDatasetManifest,
        integrity: &BenchmarkIntegrityReceipt,
        run: &EvalRun,
        verdict: &EvalVerdict,
        git_commit: &str,
        approved_by: &str,
    ) -> Result<EvalBaseline, EngineError> {
        if !suite.fixed {
            return Err(EngineError::WriteRejected(
                "eval baseline requires fixed suite".to_owned(),
            ));
        }
        if !integrity.valid || integrity.blocked_run {
            return Err(EngineError::WriteRejected(
                "eval baseline requires passing benchmark integrity receipt".to_owned(),
            ));
        }
        if run.status != EvalRunStatus::Completed || verdict.status != EvalVerdictStatus::Pass {
            return Err(EngineError::WriteRejected(
                "normal eval baseline requires passing eval run".to_owned(),
            ));
        }
        Ok(Self::baseline(
            suite,
            manifest,
            run,
            verdict,
            git_commit,
            approved_by,
        ))
    }

    pub fn create_diagnostic(
        suite: &EvalSuite,
        manifest: &EvalDatasetManifest,
        run: &EvalRun,
        verdict: &EvalVerdict,
        git_commit: &str,
    ) -> EvalBaseline {
        Self::baseline(suite, manifest, run, verdict, git_commit, "diagnostic")
    }

    pub fn active_baseline(baselines: &[EvalBaseline]) -> Option<EvalBaseline> {
        baselines
            .iter()
            .max_by_key(|baseline| baseline.approved_at)
            .cloned()
    }

    fn baseline(
        suite: &EvalSuite,
        manifest: &EvalDatasetManifest,
        run: &EvalRun,
        verdict: &EvalVerdict,
        git_commit: &str,
        approved_by: &str,
    ) -> EvalBaseline {
        EvalBaseline {
            baseline_id: format!("eval-baseline-{}", WriteId::new_v7()),
            suite_id: suite.eval_suite_id.to_string(),
            eval_run_id: run.eval_run_id.to_string(),
            git_commit: git_commit.to_owned(),
            manifest_ref: manifest.eval_dataset_manifest_id.to_string(),
            family_scores: verdict.family_scores.clone(),
            overall_status: verdict.status,
            approved_at: OffsetDateTime::now_utc(),
            approved_by: approved_by.to_owned(),
        }
    }
}

pub struct EvalComparisonService;

impl EvalComparisonService {
    pub fn compare(
        suite: &EvalSuite,
        baseline: &EvalBaseline,
        candidate_run: &EvalRun,
        candidate_git_commit: &str,
    ) -> EvalCandidateComparison {
        let baseline_scores = baseline_score_map(baseline);
        let candidate_scores = run_score_map(candidate_run);
        let mut families = baseline_scores.keys().copied().collect::<BTreeSet<_>>();
        families.extend(candidate_scores.keys().copied());
        let family_deltas = families
            .into_iter()
            .map(|family| {
                let baseline_score = baseline_scores.get(&family).copied().unwrap_or(0.0);
                let candidate_score = candidate_scores.get(&family).copied().unwrap_or(0.0);
                let delta = candidate_score - baseline_score;
                EvalFamilyDelta {
                    family,
                    baseline_score,
                    candidate_score,
                    delta,
                    severity: delta_severity(family, delta),
                }
            })
            .collect::<Vec<_>>();
        let newly_failed_cases = candidate_run
            .case_results
            .iter()
            .filter(|result| {
                result.status != EvalCaseStatus::Passed
                    && baseline_scores.get(&result.family).copied().unwrap_or(0.0) >= 100.0
            })
            .map(|result| result.eval_case_id.to_string())
            .collect::<Vec<_>>();
        let newly_passing_cases = candidate_run
            .case_results
            .iter()
            .filter(|result| {
                result.status == EvalCaseStatus::Passed
                    && baseline_scores.get(&result.family).copied().unwrap_or(0.0) < 100.0
            })
            .map(|result| result.eval_case_id.to_string())
            .collect::<Vec<_>>();
        let verdict = comparison_verdict(&family_deltas, candidate_run.status);
        EvalCandidateComparison {
            comparison_id: format!("eval-comparison-{}", WriteId::new_v7()),
            suite_id: suite.eval_suite_id.to_string(),
            baseline_id: baseline.baseline_id.clone(),
            candidate_run_id: candidate_run.eval_run_id.to_string(),
            candidate_git_commit: candidate_git_commit.to_owned(),
            family_deltas,
            newly_failed_cases,
            newly_passing_cases,
            flaky_cases: Vec::new(),
            verdict,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn run_with_failed_family(run: &EvalRun, family: EvalFamily) -> EvalRun {
        let mut clone = run.clone();
        clone.eval_run_id = EvalRunId::new_v7();
        clone.status = EvalRunStatus::Failed;
        for result in clone
            .case_results
            .iter_mut()
            .filter(|result| result.family == family)
        {
            result.status = EvalCaseStatus::Failed;
            result
                .errors
                .push("intentional integration regression fixture".to_owned());
            if let Some(measurement) = result.measurements.first_mut() {
                measurement.passed = false;
                "intentional integration regression fixture".clone_into(&mut measurement.observed);
            }
        }
        clone.finished_at = Some(OffsetDateTime::now_utc());
        clone
    }
}

pub struct EvalGateProfileService;

impl EvalGateProfileService {
    pub fn built_in_profiles() -> Vec<EvalRegressionGateProfile> {
        vec![
            profile(
                "fast-deterministic",
                "Fast Deterministic",
                "Fast deterministic regression gate for governed changes.",
                vec!["core-smoke"],
                vec![
                    EvalFamily::Understand,
                    EvalFamily::Hallucination,
                    EvalFamily::Negative,
                    EvalFamily::Done,
                    EvalFamily::Context,
                    EvalFamily::Trace,
                    EvalFamily::Bench,
                ],
                vec![
                    EvalFamily::Understand,
                    EvalFamily::Hallucination,
                    EvalFamily::Negative,
                    EvalFamily::Done,
                    EvalFamily::Bench,
                ],
                true,
                0,
            ),
            profile(
                "architecture-standard",
                "Architecture Standard",
                "Broader deterministic gate for larger architectural changes.",
                vec!["core-smoke"],
                runnable_k0_families().to_vec(),
                runnable_k0_families().to_vec(),
                false,
                0,
            ),
            profile(
                "provider-integration",
                "Provider Integration",
                "Gate before real external provider adapters; provider family remains a placeholder until implemented.",
                vec!["core-smoke"],
                vec![
                    EvalFamily::Tool,
                    EvalFamily::Hallucination,
                    EvalFamily::Negative,
                    EvalFamily::Context,
                    EvalFamily::Trace,
                    EvalFamily::Bench,
                ],
                vec![
                    EvalFamily::Tool,
                    EvalFamily::Hallucination,
                    EvalFamily::Negative,
                    EvalFamily::Bench,
                ],
                false,
                0,
            ),
            profile(
                "production-release",
                "Production Release",
                "Gate before production daemon or service cutover.",
                vec!["core-smoke"],
                vec![
                    EvalFamily::Done,
                    EvalFamily::Trace,
                    EvalFamily::Bench,
                    EvalFamily::Context,
                    EvalFamily::Negative,
                    EvalFamily::Memory,
                    EvalFamily::Forget,
                ],
                vec![
                    EvalFamily::Done,
                    EvalFamily::Trace,
                    EvalFamily::Bench,
                    EvalFamily::Context,
                    EvalFamily::Negative,
                    EvalFamily::Memory,
                    EvalFamily::Forget,
                ],
                false,
                0,
            ),
        ]
    }

    pub fn find(profile_id: &str) -> Option<EvalRegressionGateProfile> {
        Self::built_in_profiles()
            .into_iter()
            .find(|profile| profile.profile_id == profile_id)
    }

    pub fn validate(profile: &EvalRegressionGateProfile) -> Result<(), EngineError> {
        if profile.profile_id.trim().is_empty() || profile.required_families.is_empty() {
            return Err(EngineError::WriteRejected(
                "eval gate profile requires id and required families".to_owned(),
            ));
        }
        if profile
            .min_family_scores
            .iter()
            .any(|threshold| !(0.0..=100.0).contains(&threshold.min_score))
        {
            return Err(EngineError::WriteRejected(
                "eval gate profile threshold must be between 0 and 100".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct EvalRegressionGateService;

impl EvalRegressionGateService {
    #[allow(clippy::too_many_lines)]
    pub fn evaluate_comparison(
        profile: &EvalRegressionGateProfile,
        comparison: &EvalCandidateComparison,
        integrity: &BenchmarkIntegrityReceipt,
    ) -> EvalGateDecision {
        let mut blocking_reasons = Vec::new();
        let mut warnings = Vec::new();
        let mut required_followups = Vec::new();
        if profile.require_benchmark_integrity && (!integrity.valid || integrity.blocked_run) {
            return gate_decision(
                profile,
                Some(comparison.comparison_id.clone()),
                comparison.candidate_run_id.clone(),
                EvalGateDecisionKind::RequireBenchmarkRepair,
                vec!["benchmark integrity receipt failed".to_owned()],
                warnings,
                vec!["repair or refreeze benchmark manifest before gating".to_owned()],
            );
        }
        let families = comparison
            .family_deltas
            .iter()
            .map(|delta| delta.family)
            .collect::<BTreeSet<_>>();
        for family in &profile.required_families {
            if !families.contains(family) {
                required_followups.push(format!(
                    "missing required eval family {}",
                    family_slug(*family)
                ));
            }
        }
        if !required_followups.is_empty() {
            return gate_decision(
                profile,
                Some(comparison.comparison_id.clone()),
                comparison.candidate_run_id.clone(),
                EvalGateDecisionKind::RequireMoreCoverage,
                Vec::new(),
                warnings,
                required_followups,
            );
        }
        for threshold in &profile.min_family_scores {
            let score = comparison
                .family_deltas
                .iter()
                .find(|delta| delta.family == threshold.family)
                .map_or(0.0, |delta| delta.candidate_score);
            if score < threshold.min_score {
                let reason = format!(
                    "{} score {score:.1} below required {:.1}",
                    family_slug(threshold.family),
                    threshold.min_score
                );
                match threshold.severity_if_below {
                    EvalRegressionSeverity::Info | EvalRegressionSeverity::Warning => {
                        warnings.push(reason);
                    }
                    EvalRegressionSeverity::Blocking | EvalRegressionSeverity::Critical => {
                        blocking_reasons.push(reason);
                    }
                }
            }
        }
        let new_failures = u64_count(comparison.newly_failed_cases.len());
        if new_failures > profile.max_new_failures {
            blocking_reasons.push(format!(
                "new eval failures {new_failures} exceed limit {}",
                profile.max_new_failures
            ));
        }
        if comparison.verdict == EvalComparisonVerdict::Inconclusive && !profile.allow_inconclusive
        {
            blocking_reasons.push("eval comparison is inconclusive".to_owned());
        }
        for delta in &comparison.family_deltas {
            if delta.delta < 0.0 {
                let reason = format!(
                    "{} regressed by {:.1}",
                    family_slug(delta.family),
                    delta.delta
                );
                match delta.severity {
                    EvalRegressionSeverity::Info => {}
                    EvalRegressionSeverity::Warning => warnings.push(reason),
                    EvalRegressionSeverity::Blocking | EvalRegressionSeverity::Critical => {
                        blocking_reasons.push(reason);
                    }
                }
            }
        }
        let decision = if !blocking_reasons.is_empty() {
            EvalGateDecisionKind::Block
        } else if !warnings.is_empty() {
            EvalGateDecisionKind::AllowWithWarnings
        } else {
            EvalGateDecisionKind::Allow
        };
        gate_decision(
            profile,
            Some(comparison.comparison_id.clone()),
            comparison.candidate_run_id.clone(),
            decision,
            blocking_reasons,
            warnings,
            required_followups,
        )
    }

    pub fn evaluate_run(
        profile: &EvalRegressionGateProfile,
        run: &EvalRun,
        integrity: &BenchmarkIntegrityReceipt,
    ) -> EvalGateDecision {
        if profile.require_benchmark_integrity && (!integrity.valid || integrity.blocked_run) {
            return gate_decision(
                profile,
                None,
                run.eval_run_id.to_string(),
                EvalGateDecisionKind::RequireBenchmarkRepair,
                vec!["benchmark integrity receipt failed".to_owned()],
                Vec::new(),
                vec!["repair or refreeze benchmark manifest before gating".to_owned()],
            );
        }
        let scores = run_score_map(run);
        let mut blocking_reasons = Vec::new();
        let mut warnings = Vec::new();
        let mut required_followups = Vec::new();
        for family in &profile.required_families {
            if !scores.contains_key(family) {
                required_followups.push(format!(
                    "missing required eval family {}",
                    family_slug(*family)
                ));
            }
        }
        if !required_followups.is_empty() {
            return gate_decision(
                profile,
                None,
                run.eval_run_id.to_string(),
                EvalGateDecisionKind::RequireMoreCoverage,
                Vec::new(),
                warnings,
                required_followups,
            );
        }
        for threshold in &profile.min_family_scores {
            let score = scores.get(&threshold.family).copied().unwrap_or(0.0);
            if score < threshold.min_score {
                let reason = format!(
                    "{} score {score:.1} below required {:.1}",
                    family_slug(threshold.family),
                    threshold.min_score
                );
                match threshold.severity_if_below {
                    EvalRegressionSeverity::Info | EvalRegressionSeverity::Warning => {
                        warnings.push(reason);
                    }
                    EvalRegressionSeverity::Blocking | EvalRegressionSeverity::Critical => {
                        blocking_reasons.push(reason);
                    }
                }
            }
        }
        let decision = if !blocking_reasons.is_empty() {
            EvalGateDecisionKind::Block
        } else if !warnings.is_empty() {
            EvalGateDecisionKind::AllowWithWarnings
        } else {
            EvalGateDecisionKind::Allow
        };
        gate_decision(
            profile,
            None,
            run.eval_run_id.to_string(),
            decision,
            blocking_reasons,
            warnings,
            Vec::new(),
        )
    }

    pub fn incident_lockdown_blocks_baseline_mutation(incident_lockdown_active: bool) -> bool {
        incident_lockdown_active
    }

    pub fn incident_lockdown_blocks_suite_mutation(incident_lockdown_active: bool) -> bool {
        incident_lockdown_active
    }
}

pub struct EvalTrendService;

impl EvalTrendService {
    pub fn trend(suite: &EvalSuite, runs: &[EvalRun]) -> EvalTrendReport {
        let recent_run_refs = runs
            .iter()
            .map(|run| run.eval_run_id.to_string())
            .collect::<Vec<_>>();
        let families = runs
            .iter()
            .flat_map(|run| run.case_results.iter().map(|result| result.family))
            .collect::<BTreeSet<_>>();
        let family_trends = families
            .into_iter()
            .map(|family| {
                let scores = runs
                    .iter()
                    .map(|run| run_score_map(run).get(&family).copied().unwrap_or(0.0))
                    .collect::<Vec<_>>();
                EvalFamilyTrend {
                    family,
                    direction: trend_direction(&scores),
                    scores,
                }
            })
            .collect::<Vec<_>>();
        let (flaky_cases, persistent_failures) = case_stability(runs);
        EvalTrendReport {
            trend_report_id: format!("eval-trend-{}", WriteId::new_v7()),
            suite_id: suite.eval_suite_id.to_string(),
            recent_run_refs,
            family_trends,
            flaky_cases,
            persistent_failures,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct EvalFixtureStabilityService;

impl EvalFixtureStabilityService {
    pub fn report(suite: &EvalSuite, runs: &[EvalRun]) -> EvalFixtureStabilityReport {
        let repeated_run_refs = runs
            .iter()
            .map(|run| run.eval_run_id.to_string())
            .collect::<Vec<_>>();
        let mut by_case: BTreeMap<String, Vec<EvalCaseStatus>> = BTreeMap::new();
        for run in runs {
            for result in &run.case_results {
                by_case
                    .entry(result.eval_case_id.to_string())
                    .or_default()
                    .push(result.status);
            }
        }
        let mut stable_cases = Vec::new();
        let mut flaky_cases = Vec::new();
        let mut blocked_cases = Vec::new();
        for (case_id, statuses) in by_case {
            let first_status = statuses.first().copied();
            if statuses.iter().any(|status| {
                matches!(
                    status,
                    EvalCaseStatus::Blocked | EvalCaseStatus::NotYetImplemented
                )
            }) {
                blocked_cases.push(case_id);
            } else if statuses.iter().any(|status| Some(*status) != first_status) {
                flaky_cases.push(case_id);
            } else if statuses
                .iter()
                .all(|status| *status == EvalCaseStatus::Passed)
            {
                stable_cases.push(case_id);
            }
        }
        EvalFixtureStabilityReport {
            report_id: format!("eval-fixture-stability-{}", WriteId::new_v7()),
            suite_id: suite.eval_suite_id.to_string(),
            repeated_run_refs,
            stable_cases,
            flaky_cases,
            blocked_cases,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct EvalDoctorIntegration;

impl EvalDoctorIntegration {
    pub fn status(
        baseline: Option<&EvalBaseline>,
        gate: Option<&EvalGateDecision>,
        coverage: &EvalCoverageMatrix,
        trend: Option<&EvalTrendReport>,
        stability: Option<&EvalFixtureStabilityReport>,
        integrity: &BenchmarkIntegrityReceipt,
    ) -> serde_json::Value {
        let missing_required_families = coverage
            .family_coverage
            .iter()
            .filter(|coverage| {
                !placeholder_family(coverage.family)
                    && matches!(
                        coverage.coverage_status,
                        EvalCoverageStatus::Insufficient | EvalCoverageStatus::NotImplemented
                    )
            })
            .map(|coverage| family_slug(coverage.family))
            .collect::<Vec<_>>();
        serde_json::json!({
            "component": "eval_doctor_status",
            "active_baseline": baseline.map(|baseline| baseline.baseline_id.clone()),
            "last_eval_gate_decision": gate.map(|gate| gate.decision),
            "coverage": {
                "matrix_id": coverage.matrix_id,
                "families": coverage.family_coverage.len(),
                "uncovered_risks": coverage.uncovered_risks
            },
            "required_families_missing": missing_required_families,
            "benchmark_integrity_warnings": if integrity.valid { Vec::<String>::new() } else { vec!["benchmark integrity failed".to_owned()] },
            "flaky_cases": stability.map(|stability| stability.flaky_cases.clone()).unwrap_or_default(),
            "persistent_failures": trend.map(|trend| trend.persistent_failures.clone()).unwrap_or_default()
        })
    }
}

pub struct EvalMemoryWriter;

impl EvalMemoryWriter {
    pub async fn write_observation<T: Serialize>(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        tool_name: &str,
        observation: &str,
        payload: &T,
    ) -> Result<WriteReceiptRef, EngineError> {
        let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
            context: CommandContext {
                write_id: WriteId::new_v7(),
                agent_id: eliot_types::AgentId::new_v7(),
                session_id: None,
                project_id,
                task_id,
                scope: "eval-suites-harness".to_owned(),
                authority: "local-eval-harness".to_owned(),
                visibility: Visibility::Internal,
                taint: TaintClass::Unknown,
                lifecycle_status: LifecycleStatus::Active,
            },
            tool_name: tool_name.to_owned(),
            observation: observation.to_owned(),
            payload: serde_json::to_value(payload)?,
        });
        let envelope = admission.admit(&command)?;
        let receipt = handle.submit(envelope).await?;
        Ok(WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        })
    }
}

pub fn harness_experiment_record(run: &EvalRun, verdict: &EvalVerdict) -> HarnessExperimentRecord {
    HarnessExperimentRecord {
        harness_experiment_record_id: HarnessExperimentRecordId::new_v7(),
        eval_run_id: run.eval_run_id,
        profile_id: run.profile.profile_id.clone(),
        verdict_id: Some(verdict.eval_verdict_id),
        notes: vec!["core harness run is deterministic and report-only".to_owned()],
        no_mutation_confirmed: run.profile.no_mutation
            && !verdict.mutates_current_truth
            && !verdict.mutates_memory_lifecycle
            && !verdict.mutates_skills
            && !verdict.mutates_policy
            && !verdict.mutates_action_permissions
            && !verdict.mutates_completion_state,
        project_id: Some(run.project_id),
        candidate_ref: String::new(),
        change_class: MetaCandidateChangeClass::AdmissionRule,
        changed_variables: Vec::new(),
        evaluator_snapshot_ref: run.profile.profile_id.clone(),
        baseline_policy_hash: String::new(),
        candidate_policy_hash: String::new(),
        fixed_replay_set_ref: String::new(),
        holdout_set_ref: String::new(),
        replay_run_refs: Vec::new(),
        holdout_run_refs: Vec::new(),
        primary_metric_refs: Vec::new(),
        counter_metric_refs: Vec::new(),
        reproducibility_hash: String::new(),
        uncertainty: "legacy record predates the current holdout disposition".to_owned(),
        decision: MetaExperimentDecision::InsufficientEvidence,
        authorized_command_ref: None,
        rollback_target_ref: String::new(),
        rollback_command_ref: String::new(),
        authoritative_metric_evidence: Vec::new(),
        authoritative_isolation_rejection: None,
        authoritative_policy_candidate: None,
        disposition_receipt: None,
        created_at: OffsetDateTime::now_utc(),
    }
}

pub fn runnable_k0_families() -> &'static [EvalFamily; 13] {
    &[
        EvalFamily::Understand,
        EvalFamily::Hallucination,
        EvalFamily::Negative,
        EvalFamily::Done,
        EvalFamily::Context,
        EvalFamily::Compaction,
        EvalFamily::Tool,
        EvalFamily::Memory,
        EvalFamily::Forget,
        EvalFamily::Dream,
        EvalFamily::Skill,
        EvalFamily::Trace,
        EvalFamily::Bench,
    ]
}

pub fn family_slug(family: EvalFamily) -> &'static str {
    match family {
        EvalFamily::Understand => "understand",
        EvalFamily::Hallucination => "hallucination",
        EvalFamily::Negative => "negative",
        EvalFamily::Done => "done",
        EvalFamily::Context => "context",
        EvalFamily::Compaction => "compaction",
        EvalFamily::Tool => "tool",
        EvalFamily::Memory => "memory",
        EvalFamily::Forget => "forget",
        EvalFamily::Dream => "dream",
        EvalFamily::Skill => "skill",
        EvalFamily::Trace => "trace",
        EvalFamily::Bench => "bench",
        EvalFamily::Ale => "ale",
        EvalFamily::Provider => "provider",
        EvalFamily::Future => "future",
    }
}

fn default_case(
    project_id: ProjectId,
    task_id: Option<TaskId>,
    family: EvalFamily,
    name: &str,
) -> EvalCase {
    let slug = family_slug(family);
    let expectations = family_expectations(family);
    let criteria = expectations
        .iter()
        .enumerate()
        .map(|(index, expectation)| {
            let measurement_id = format!("{slug}-m{index}");
            EvalCriterion {
                criterion_id: format!("{slug}-c{index}"),
                description: expectation.description.to_owned(),
                required: true,
                measurement_id,
            }
        })
        .collect::<Vec<_>>();
    let measurement_specs = expectations
        .iter()
        .enumerate()
        .map(|(index, expectation)| EvalMeasurementSpec {
            measurement_id: format!("{slug}-m{index}"),
            description: expectation.description.to_owned(),
            kind: expectation.kind,
            expected_ref: expectation.expected_ref.map(str::to_owned),
        })
        .collect::<Vec<_>>();
    let mut expected_evidence_refs = expectations
        .iter()
        .filter_map(|expectation| match expectation.kind {
            EvalMeasurementKind::MustExcludeEvidence
            | EvalMeasurementKind::MustBlockAction
            | EvalMeasurementKind::NotYetImplemented => None,
            _ => expectation.expected_ref.map(str::to_owned),
        })
        .collect::<Vec<_>>();
    expected_evidence_refs.push(format!("fixture:{slug}"));
    EvalCase {
        eval_case_id: EvalCaseId::new_v7(),
        project_id,
        task_id,
        family,
        name: name.to_owned(),
        description: format!("deterministic eval case for {slug}"),
        fixture_ref: format!("fixture:k0:{slug}"),
        holdout: true,
        criteria,
        measurement_specs,
        budget: EvalBudget {
            max_runtime_ms: 500,
            max_input_tokens: 2_000,
            max_output_tokens: 800,
            max_tool_calls: 4,
        },
        expected_evidence_refs,
        forbidden_effects: vec![
            "promote".to_owned(),
            "apply".to_owned(),
            "truth".to_owned(),
            "policy".to_owned(),
            "permission".to_owned(),
            "patch".to_owned(),
            "finish".to_owned(),
            "purge".to_owned(),
            "skill".to_owned(),
            "candidate".to_owned(),
        ],
        created_at: OffsetDateTime::now_utc(),
    }
}

#[derive(Clone)]
struct FamilyExpectation {
    description: &'static str,
    kind: EvalMeasurementKind,
    expected_ref: Option<&'static str>,
}

#[allow(clippy::too_many_lines)]
fn family_expectations(family: EvalFamily) -> Vec<FamilyExpectation> {
    match family {
        EvalFamily::Understand => vec![
            include("L3 packet includes exact evidence atom", "l3:exact-atom"),
            include("causal bridge connects goal to code", "proof:causal-bridge"),
            block("missing causal bridge is rejected", "finish"),
        ],
        EvalFamily::Hallucination => vec![include(
            "current repository truth wins over stale memory",
            "truth:current-source",
        )],
        EvalFamily::Negative => vec![block(
            "repeated failed procedure is blocked or requires probe",
            "apply",
        )],
        EvalFamily::Done => vec![block("incomplete work item blocks DONE_VERIFIED", "finish")],
        EvalFamily::Context => vec![
            include("load-bearing atom is included", "context:load-bearing"),
            exclude("irrelevant context is excluded", "context:irrelevant"),
            include("influence report is present", "context:influence-report"),
        ],
        EvalFamily::Compaction => vec![
            include("resume restores handles", "compaction:restored-handles"),
            block("resume cannot create unverified DONE", "finish"),
        ],
        EvalFamily::Tool => vec![
            include(
                "tainted adapter observation stays candidate",
                "tool:candidate-only",
            ),
            block("tool observation cannot authorize truth mutation", "truth"),
        ],
        EvalFamily::Memory => vec![
            include("suppression transition is explicit", "memory:suppressed"),
            include("superseding memory is explicit", "memory:superseding"),
            include("L3 uses superseding view", "memory:l3-superseding"),
        ],
        EvalFamily::Forget => vec![
            block("purge is denied", "purge"),
            include("archive or suppress requires evidence", "forget:evidence"),
        ],
        EvalFamily::Dream => vec![
            preserve_taint("dream candidate remains tainted"),
            block("dream output cannot mutate current truth", "truth"),
            exclude(
                "dream candidate is excluded from normal L3",
                "dream:normal-l3",
            ),
        ],
        EvalFamily::Skill => vec![
            include("active applicable skill is selected", "skill:active"),
            exclude(
                "candidate distractor skill is excluded",
                "skill:candidate-distractor",
            ),
            block("anti-scope skill is rejected", "skill"),
        ],
        EvalFamily::Trace => vec![include(
            "missing ContextPacket blocks replay",
            "trace:missing-context-packet",
        )],
        EvalFamily::Bench => vec![checksum("checksum mismatch is detected")],
        EvalFamily::Ale | EvalFamily::Provider | EvalFamily::Future => vec![FamilyExpectation {
            description: "schema placeholder only",
            kind: EvalMeasurementKind::NotYetImplemented,
            expected_ref: None,
        }],
    }
}

fn include(description: &'static str, expected_ref: &'static str) -> FamilyExpectation {
    FamilyExpectation {
        description,
        kind: EvalMeasurementKind::MustIncludeEvidence,
        expected_ref: Some(expected_ref),
    }
}

fn exclude(description: &'static str, expected_ref: &'static str) -> FamilyExpectation {
    FamilyExpectation {
        description,
        kind: EvalMeasurementKind::MustExcludeEvidence,
        expected_ref: Some(expected_ref),
    }
}

fn block(description: &'static str, action: &'static str) -> FamilyExpectation {
    FamilyExpectation {
        description,
        kind: EvalMeasurementKind::MustBlockAction,
        expected_ref: Some(action),
    }
}

fn preserve_taint(description: &'static str) -> FamilyExpectation {
    FamilyExpectation {
        description,
        kind: EvalMeasurementKind::MustPreserveTaint,
        expected_ref: Some("taint:unknown"),
    }
}

fn checksum(description: &'static str) -> FamilyExpectation {
    FamilyExpectation {
        description,
        kind: EvalMeasurementKind::MustDetectChecksumMismatch,
        expected_ref: Some("benchmark:checksum-mismatch"),
    }
}

fn all_eval_families() -> &'static [EvalFamily; 16] {
    &[
        EvalFamily::Understand,
        EvalFamily::Hallucination,
        EvalFamily::Negative,
        EvalFamily::Done,
        EvalFamily::Context,
        EvalFamily::Compaction,
        EvalFamily::Tool,
        EvalFamily::Memory,
        EvalFamily::Forget,
        EvalFamily::Dream,
        EvalFamily::Skill,
        EvalFamily::Trace,
        EvalFamily::Bench,
        EvalFamily::Ale,
        EvalFamily::Provider,
        EvalFamily::Future,
    ]
}

fn placeholder_family(family: EvalFamily) -> bool {
    matches!(
        family,
        EvalFamily::Ale | EvalFamily::Provider | EvalFamily::Future
    )
}

#[allow(clippy::too_many_lines)]
fn component_coverage(cases: &[EvalCase]) -> Vec<EvalComponentCoverage> {
    let specs = vec![
        (
            "MemoryCore",
            vec![EvalFamily::Memory, EvalFamily::Context],
            vec!["weak truth promoted", "stale memory selected"],
            vec![],
        ),
        (
            "CurrentTruth",
            vec![EvalFamily::Hallucination, EvalFamily::Negative],
            vec!["unsupported truth used", "known bad path repeated"],
            vec![],
        ),
        (
            "ContextCompiler",
            vec![EvalFamily::Context, EvalFamily::Compaction],
            vec!["load-bearing atom dropped", "compaction lost handle"],
            vec![],
        ),
        (
            "UnderstandingProof",
            vec![EvalFamily::Understand, EvalFamily::Trace],
            vec!["missing causal bridge", "missing evidence ref"],
            vec![],
        ),
        (
            "CognitiveGate",
            vec![EvalFamily::Negative, EvalFamily::Done],
            vec!["unsafe task allowed", "unverified done accepted"],
            vec![],
        ),
        (
            "CodeCortex",
            vec![EvalFamily::Understand, EvalFamily::Trace],
            vec!["ungrounded code task", "missing code evidence"],
            vec![],
        ),
        (
            "WorkLease",
            vec![EvalFamily::Tool, EvalFamily::Done],
            vec!["unleased work mutation", "unfinished work closed"],
            vec![],
        ),
        (
            "ActionLease",
            vec![EvalFamily::Tool, EvalFamily::Negative],
            vec!["action without lease", "raw tool bypass"],
            vec![],
        ),
        (
            "PatchRunner",
            vec![EvalFamily::Tool, EvalFamily::Done],
            vec!["patch without verifier", "failed verifier ignored"],
            vec![],
        ),
        (
            "VerifierHarness",
            vec![EvalFamily::Done, EvalFamily::Bench],
            vec!["missing verifier", "benchmark mismatch ignored"],
            vec![],
        ),
        (
            "CompletionGate",
            vec![EvalFamily::Done, EvalFamily::Trace],
            vec!["DONE without proof", "missing trace contract"],
            vec![],
        ),
        (
            "CodexHooks",
            vec![EvalFamily::Tool, EvalFamily::Trace],
            vec!["hook bypass", "missing hook trace"],
            vec![],
        ),
        (
            "WorktreeLease",
            vec![EvalFamily::Tool, EvalFamily::Negative],
            vec!["out-of-scope diff", "raw git exposure"],
            vec![],
        ),
        (
            "BlackboardMailbox",
            vec![EvalFamily::Dream, EvalFamily::Trace],
            vec!["candidate promoted to truth", "message without ack"],
            vec![],
        ),
        (
            "RuntimeDaemon",
            vec![EvalFamily::Trace, EvalFamily::Done],
            vec!["daemon health ignored", "shutdown trace missing"],
            vec![],
        ),
        (
            "AdapterRuntime",
            vec![EvalFamily::Tool, EvalFamily::Negative],
            vec!["raw adapter execution", "taint not preserved"],
            vec![],
        ),
        (
            "BackupRecoveryIncident",
            vec![EvalFamily::Negative, EvalFamily::Bench],
            vec!["incident lockdown bypass", "restore integrity ignored"],
            vec![],
        ),
        (
            "MemoryLifecycle",
            vec![EvalFamily::Memory, EvalFamily::Forget],
            vec!["suppressed memory selected", "forget without evidence"],
            vec![],
        ),
        (
            "SkillLifecycle",
            vec![EvalFamily::Skill, EvalFamily::Negative],
            vec!["inapplicable skill activated", "failed skill reused"],
            vec![],
        ),
        (
            "SkillCurator",
            vec![EvalFamily::Skill, EvalFamily::Dream],
            vec!["unsafe skill promotion", "candidate patch leaked"],
            vec![],
        ),
        (
            "SleepReplay",
            vec![EvalFamily::Dream, EvalFamily::Trace],
            vec!["sleep mutates truth", "replay lacks trace"],
            vec![],
        ),
        (
            "EvalHarness",
            vec![EvalFamily::Bench, EvalFamily::Done],
            vec!["fixture checksum drift", "eval verdict grants authority"],
            vec!["real provider eval coverage is intentionally deferred"],
        ),
    ];
    specs
        .into_iter()
        .map(
            |(component, families, covered, uncovered)| EvalComponentCoverage {
                component: component.to_owned(),
                eval_case_refs: case_refs_for_families(cases, &families),
                covered_failure_modes: covered.into_iter().map(str::to_owned).collect(),
                uncovered_failure_modes: uncovered.into_iter().map(str::to_owned).collect(),
            },
        )
        .collect()
}

fn risk_coverage(cases: &[EvalCase]) -> Vec<EvalRiskCoverage> {
    vec![
        risk(
            "risk-current-truth-hallucination",
            "Unsupported or hallucinated truth is used as verified fact.",
            EvalRegressionSeverity::Critical,
            &[EvalFamily::Hallucination, EvalFamily::Negative],
            cases,
            EvalCoverageStatus::Sufficient,
        ),
        risk(
            "risk-done-without-proof",
            "Completion is accepted without verifier-backed proof.",
            EvalRegressionSeverity::Critical,
            &[EvalFamily::Done, EvalFamily::Trace],
            cases,
            EvalCoverageStatus::Sufficient,
        ),
        risk(
            "risk-context-loss",
            "Compaction or L3 packet construction drops load-bearing context.",
            EvalRegressionSeverity::Blocking,
            &[EvalFamily::Context, EvalFamily::Compaction],
            cases,
            EvalCoverageStatus::Sufficient,
        ),
        risk(
            "risk-memory-lifecycle-leak",
            "Suppressed, superseded, or forgotten memory influences normal recall.",
            EvalRegressionSeverity::Blocking,
            &[EvalFamily::Memory, EvalFamily::Forget],
            cases,
            EvalCoverageStatus::Sufficient,
        ),
        risk(
            "risk-provider-real-eval",
            "Real external provider evals are not implemented in the integration suite.",
            EvalRegressionSeverity::Warning,
            &[EvalFamily::Provider],
            cases,
            EvalCoverageStatus::PlaceholderOnly,
        ),
        risk(
            "risk-ale-real-eval",
            "ALE eval coverage is schema-only.",
            EvalRegressionSeverity::Warning,
            &[EvalFamily::Ale],
            cases,
            EvalCoverageStatus::PlaceholderOnly,
        ),
        risk(
            "risk-future-suite-expansion",
            "Deferred eval families remain placeholders until their runbooks define cases.",
            EvalRegressionSeverity::Info,
            &[EvalFamily::Future],
            cases,
            EvalCoverageStatus::PlaceholderOnly,
        ),
    ]
}

fn risk(
    risk_id: &str,
    description: &str,
    severity: EvalRegressionSeverity,
    families: &[EvalFamily],
    cases: &[EvalCase],
    fallback_status: EvalCoverageStatus,
) -> EvalRiskCoverage {
    let eval_case_refs = case_refs_for_families(cases, families);
    let status = if eval_case_refs.is_empty() {
        fallback_status
    } else {
        EvalCoverageStatus::Sufficient
    };
    EvalRiskCoverage {
        risk_id: risk_id.to_owned(),
        description: description.to_owned(),
        severity,
        eval_case_refs,
        status,
    }
}

fn case_refs_for_families(cases: &[EvalCase], families: &[EvalFamily]) -> Vec<String> {
    cases
        .iter()
        .filter(|case| families.contains(&case.family))
        .map(|case| case.fixture_ref.clone())
        .collect()
}

fn baseline_score_map(baseline: &EvalBaseline) -> BTreeMap<EvalFamily, f64> {
    baseline
        .family_scores
        .iter()
        .map(|score| (score.family, f64::from(score.score_percent)))
        .collect()
}

fn run_score_map(run: &EvalRun) -> BTreeMap<EvalFamily, f64> {
    let mut by_family: BTreeMap<EvalFamily, Vec<&EvalCaseResult>> = BTreeMap::new();
    for result in &run.case_results {
        by_family.entry(result.family).or_default().push(result);
    }
    by_family
        .into_iter()
        .map(|(family, results)| {
            let total = u32::try_from(results.len()).unwrap_or(u32::MAX);
            let passed = u32::try_from(
                results
                    .iter()
                    .filter(|result| result.status == EvalCaseStatus::Passed)
                    .count(),
            )
            .unwrap_or(u32::MAX);
            let score = if total == 0 {
                0.0
            } else {
                (f64::from(passed) / f64::from(total)) * 100.0
            };
            (family, score)
        })
        .collect()
}

fn delta_severity(family: EvalFamily, delta: f64) -> EvalRegressionSeverity {
    if delta >= 0.0 {
        EvalRegressionSeverity::Info
    } else if matches!(
        family,
        EvalFamily::Understand
            | EvalFamily::Hallucination
            | EvalFamily::Negative
            | EvalFamily::Done
            | EvalFamily::Bench
    ) {
        EvalRegressionSeverity::Critical
    } else if matches!(
        family,
        EvalFamily::Tool | EvalFamily::Memory | EvalFamily::Forget | EvalFamily::Trace
    ) {
        EvalRegressionSeverity::Blocking
    } else {
        EvalRegressionSeverity::Warning
    }
}

fn comparison_verdict(
    deltas: &[EvalFamilyDelta],
    candidate_status: EvalRunStatus,
) -> EvalComparisonVerdict {
    if !matches!(
        candidate_status,
        EvalRunStatus::Completed | EvalRunStatus::Failed
    ) {
        return EvalComparisonVerdict::Inconclusive;
    }
    if deltas
        .iter()
        .any(|delta| delta.severity == EvalRegressionSeverity::Critical)
    {
        EvalComparisonVerdict::RegressedCritical
    } else if deltas
        .iter()
        .any(|delta| delta.severity == EvalRegressionSeverity::Blocking)
    {
        EvalComparisonVerdict::RegressedBlocking
    } else if deltas
        .iter()
        .any(|delta| delta.severity == EvalRegressionSeverity::Warning)
    {
        EvalComparisonVerdict::RegressedWarning
    } else if deltas.iter().any(|delta| delta.delta > 0.0) {
        EvalComparisonVerdict::Improved
    } else {
        EvalComparisonVerdict::Equivalent
    }
}

#[allow(clippy::too_many_arguments)]
fn profile(
    profile_id: &str,
    name: &str,
    description: &str,
    suite_ids: Vec<&str>,
    required_families: Vec<EvalFamily>,
    blocking_families: Vec<EvalFamily>,
    allow_inconclusive: bool,
    max_new_failures: u64,
) -> EvalRegressionGateProfile {
    let min_family_scores = required_families
        .iter()
        .map(|family| EvalFamilyThreshold {
            family: *family,
            min_score: 100.0,
            severity_if_below: if blocking_families.contains(family) {
                EvalRegressionSeverity::Critical
            } else {
                EvalRegressionSeverity::Warning
            },
        })
        .collect();
    EvalRegressionGateProfile {
        profile_id: profile_id.to_owned(),
        name: name.to_owned(),
        description: description.to_owned(),
        suite_ids: suite_ids.into_iter().map(str::to_owned).collect(),
        required_families,
        blocking_families,
        min_family_scores,
        allow_inconclusive,
        max_new_failures,
        require_benchmark_integrity: true,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn gate_decision(
    profile: &EvalRegressionGateProfile,
    comparison_ref: Option<String>,
    eval_run_ref: String,
    decision: EvalGateDecisionKind,
    blocking_reasons: Vec<String>,
    warnings: Vec<String>,
    required_followups: Vec<String>,
) -> EvalGateDecision {
    EvalGateDecision {
        decision_id: format!("eval-gate-{}", WriteId::new_v7()),
        profile_id: profile.profile_id.clone(),
        comparison_ref,
        eval_run_ref,
        decision,
        blocking_reasons,
        warnings,
        required_followups,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn trend_direction(scores: &[f64]) -> EvalTrendDirection {
    match (scores.first(), scores.last()) {
        (Some(first), Some(last)) if scores.len() >= 2 && last > first => {
            EvalTrendDirection::Improving
        }
        (Some(first), Some(last)) if scores.len() >= 2 && last < first => {
            EvalTrendDirection::Degrading
        }
        (Some(_), Some(_)) if scores.len() >= 2 => EvalTrendDirection::Stable,
        _ => EvalTrendDirection::InsufficientData,
    }
}

fn case_stability(runs: &[EvalRun]) -> (Vec<String>, Vec<String>) {
    let mut by_case: BTreeMap<String, Vec<EvalCaseStatus>> = BTreeMap::new();
    for run in runs {
        for result in &run.case_results {
            by_case
                .entry(result.eval_case_id.to_string())
                .or_default()
                .push(result.status);
        }
    }
    let mut flaky_cases = Vec::new();
    let mut persistent_failures = Vec::new();
    for (case_id, statuses) in by_case {
        if let Some(first) = statuses.first() {
            if statuses.iter().any(|status| status != first) {
                flaky_cases.push(case_id);
            } else if statuses
                .iter()
                .all(|status| *status != EvalCaseStatus::Passed)
            {
                persistent_failures.push(case_id);
            }
        }
    }
    (flaky_cases, persistent_failures)
}

fn sealed_replay_passed(run: &ReplayRun) -> bool {
    run.status == ReplayRunStatus::Completed
        && !run.sealed_input_hash.trim().is_empty()
        && !run.reproducibility_hash.trim().is_empty()
        && !run.case_results.is_empty()
        && run
            .case_results
            .iter()
            .all(|result| result.status == ReplayCaseStatus::Passed)
        && run.run_profile.deterministic
        && run.run_profile.no_external_network
        && run.run_profile.no_mutation
}

fn checksum_serialized<T: Serialize>(value: &T) -> Result<String, EngineError> {
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
}

fn deterministic_meta_uuid(domain: &str, identity: &str) -> Uuid {
    let digest = blake3::hash(format!("{domain}:{identity}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn deterministic_meta_timestamp(
    domain: &str,
    identity: &str,
) -> Result<OffsetDateTime, EngineError> {
    let digest = blake3::hash(format!("{domain}:{identity}").as_bytes());
    let offset = u32::from_be_bytes(digest.as_bytes()[..4].try_into().map_err(|_| {
        EngineError::WriteRejected("deterministic meta timestamp digest is incomplete".to_owned())
    })?);
    OffsetDateTime::from_unix_timestamp(1_700_000_000_i64 + i64::from(offset % 100_000_000))
        .map_err(|error| EngineError::WriteRejected(error.to_string()))
}

fn derive_canonical_meta_assessment(
    input: &CanonicalMetaExperimentInput,
) -> Result<CanonicalMetaDerivedAssessment, EngineError> {
    let (fence, attempted_fence_hash, isolation_reasons) = canonical_meta_isolation(input)?;
    let fixed_baseline_score = replay_pass_basis_points(&input.fixed_baseline.run);
    let fixed_candidate_score = replay_pass_basis_points(&input.fixed_candidate.run);
    let holdout_baseline_score = replay_pass_basis_points(&input.holdout_baseline.run);
    let holdout_candidate_score = replay_pass_basis_points(&input.holdout_candidate.run);
    let aggregate_baseline = average_basis_points(fixed_baseline_score, holdout_baseline_score);
    let aggregate_candidate = average_basis_points(fixed_candidate_score, holdout_candidate_score);
    let counter_regressions = replay_counter_regressions(
        [&input.fixed_baseline, &input.holdout_baseline],
        [&input.fixed_candidate, &input.holdout_candidate],
    );
    let result_pair_hashes = meta_replay_result_pair_hashes(input)?;
    let metric_evidence = vec![
        canonical_meta_metric(
            "sealed_pass_basis_points",
            input,
            &result_pair_hashes,
            i64::from(aggregate_baseline),
            i64::from(aggregate_candidate),
            0,
            true,
        )?,
        canonical_meta_metric(
            "counter_regressions",
            input,
            &result_pair_hashes,
            0,
            i64::from(counter_regressions),
            u64::from(input.threshold.maximum_counter_regressions),
            false,
        )?,
    ];
    let gates = [
        fixed_candidate_score >= input.threshold.minimum_pass_basis_points,
        holdout_candidate_score >= input.threshold.minimum_pass_basis_points,
        aggregate_candidate >= input.threshold.minimum_pass_basis_points
            && aggregate_candidate >= aggregate_baseline,
        counter_regressions <= input.threshold.maximum_counter_regressions,
    ];
    let mut blocking_reasons = isolation_reasons.clone();
    for (passed, reason) in gates.into_iter().zip([
        "fixed sealed replay missed the derived threshold",
        "holdout sealed replay missed the derived threshold",
        "sealed replay primary metric regressed",
        "sealed replay counter-regression bound failed",
    ]) {
        if !passed {
            blocking_reasons.push(reason.to_owned());
        }
    }
    let eligible_for_promotion = isolation_reasons.is_empty() && gates.into_iter().all(|gate| gate);
    let reproducibility_hash = checksum_serialized(&serde_json::json!({
        "fence": fence,
        "metric_evidence": metric_evidence,
        "fixed_baseline": input.fixed_baseline.run.reproducibility_hash,
        "fixed_candidate": input.fixed_candidate.run.reproducibility_hash,
        "holdout_baseline": input.holdout_baseline.run.reproducibility_hash,
        "holdout_candidate": input.holdout_candidate.run.reproducibility_hash,
        "candidate_policy_hash": input.candidate_policy_hash,
    }))?;
    Ok(CanonicalMetaDerivedAssessment {
        fence,
        attempted_fence_hash,
        isolation_reasons,
        metric_evidence,
        gates,
        blocking_reasons,
        eligible_for_promotion,
        reproducibility_hash,
    })
}

fn canonical_meta_isolation(
    input: &CanonicalMetaExperimentInput,
) -> Result<(MetaIsolationFence, String, Vec<String>), EngineError> {
    let fence = derive_meta_isolation_fence(input)?;
    let derived_fence_hash = checksum_serialized(&fence)?;
    let attempted_fence_hash = input
        .attempted_fence
        .as_ref()
        .map(checksum_serialized)
        .transpose()?
        .unwrap_or_else(|| derived_fence_hash.clone());
    let mut reasons = Vec::new();
    if attempted_fence_hash != derived_fence_hash {
        reasons.push(
            "meta-isolation rejected a mutation to evaluator, replay sets, or thresholds"
                .to_owned(),
        );
    }
    for variable in &input.changed_variables {
        let normalized = variable.to_ascii_lowercase();
        if ["evaluator", "replay_set", "holdout_set", "threshold"]
            .iter()
            .any(|protected| normalized.contains(protected))
        {
            reasons.push(format!(
                "meta-isolation rejected protected variable {variable}"
            ));
        }
    }
    Ok((fence, attempted_fence_hash, reasons))
}

fn build_canonical_meta_assessment(
    input: CanonicalMetaExperimentInput,
    derived: CanonicalMetaDerivedAssessment,
) -> Result<CanonicalMetaExperimentAssessment, EngineError> {
    let decision = if derived.eligible_for_promotion {
        MetaExperimentDecision::KeptExperimental
    } else {
        MetaExperimentDecision::Rejected
    };
    let primary_metric_ref = derived
        .metric_evidence
        .first()
        .map(|metric| metric.evidence_hash.clone())
        .ok_or_else(|| EngineError::WriteRejected("primary meta metric is absent".to_owned()))?;
    let counter_metric_ref = derived
        .metric_evidence
        .get(1)
        .map(|metric| metric.evidence_hash.clone())
        .ok_or_else(|| EngineError::WriteRejected("counter meta metric is absent".to_owned()))?;
    let no_mutation_confirmed = canonical_meta_no_mutation_confirmed(&input);
    let experiment_identity = derived.reproducibility_hash.clone();
    let experiment_id = HarnessExperimentRecordId::from_uuid(deterministic_meta_uuid(
        "canonical-meta-experiment",
        &experiment_identity,
    ));
    let created_at =
        deterministic_meta_timestamp("canonical-meta-experiment", &experiment_identity)?;
    let experiment = HarnessExperimentRecord {
        harness_experiment_record_id: experiment_id,
        eval_run_id: input.eval_run_id,
        profile_id: input.profile_id,
        verdict_id: input.verdict_id,
        notes: if derived.blocking_reasons.is_empty() {
            vec!["canonical meta experiment remains candidate-only".to_owned()]
        } else {
            derived.blocking_reasons.clone()
        },
        no_mutation_confirmed,
        project_id: Some(input.project_id),
        candidate_ref: input.candidate_ref.clone(),
        change_class: input.change_class,
        changed_variables: input.changed_variables,
        evaluator_snapshot_ref: derived.fence.evaluator_hash.clone(),
        baseline_policy_hash: input.baseline_policy_hash,
        candidate_policy_hash: input.candidate_policy_hash,
        fixed_replay_set_ref: input.fixed_set.record_id,
        holdout_set_ref: input.holdout_set.record_id,
        replay_run_refs: vec![input.fixed_candidate.execution_id.clone()],
        holdout_run_refs: vec![input.holdout_candidate.execution_id.clone()],
        primary_metric_refs: vec![primary_metric_ref],
        counter_metric_refs: vec![counter_metric_ref],
        reproducibility_hash: derived.reproducibility_hash,
        uncertainty: "metrics are derived only from sealed canonical replay results".to_owned(),
        decision,
        authorized_command_ref: None,
        rollback_target_ref: String::new(),
        rollback_command_ref: String::new(),
        authoritative_metric_evidence: Vec::new(),
        authoritative_isolation_rejection: None,
        authoritative_policy_candidate: None,
        disposition_receipt: None,
        created_at,
    };
    let isolation_rejection =
        (!derived.isolation_reasons.is_empty()).then(|| MetaIsolationRejectionRecord {
            rejection_id: format!("meta-isolation-rejection:{experiment_identity}"),
            project_id: input.project_id,
            source_experiment_ref: experiment_id.to_string(),
            candidate_ref: input.candidate_ref,
            derived_fence: derived.fence,
            attempted_fence_hash: derived.attempted_fence_hash,
            reasons: derived.isolation_reasons,
            decision: MetaExperimentDecision::Rejected,
            created_at,
        });
    Ok(CanonicalMetaExperimentAssessment {
        records: CanonicalMetaExperimentRecordSet {
            experiment,
            metric_evidence: derived.metric_evidence,
            isolation_rejection,
        },
        eligible_for_promotion: derived.eligible_for_promotion,
        gate_results: meta_gate_results(derived.gates),
        blocking_reasons: derived.blocking_reasons,
    })
}

fn validate_canonical_meta_input(input: &CanonicalMetaExperimentInput) -> Result<(), EngineError> {
    if input.profile_id.trim().is_empty()
        || input.candidate_ref.trim().is_empty()
        || input.changed_variables.is_empty()
        || input.baseline_policy_hash.trim().is_empty()
        || input.candidate_policy_hash.trim().is_empty()
        || input.baseline_policy_hash == input.candidate_policy_hash
        || (input.changed_variables.len() > 1
            && input
                .coupled_change_rationale
                .as_deref()
                .is_none_or(|rationale| rationale.trim().is_empty()))
    {
        return Err(EngineError::WriteRejected(
            "canonical meta experiment identity or change evidence is incomplete".to_owned(),
        ));
    }
    validate_replay_threshold_policy(&input.threshold)?;
    if input.fixed_set.role != ReplaySetRole::Fixed
        || input.fixed_set.set.holdout
        || input.holdout_set.role != ReplaySetRole::Holdout
        || !input.holdout_set.set.holdout
        || input.fixed_set.set.project_id != input.project_id
        || input.holdout_set.set.project_id != input.project_id
        || input.fixed_set.sealed_hash == input.holdout_set.sealed_hash
        || input.fixed_set.evaluator_hash != input.holdout_set.evaluator_hash
        || input.fixed_set.evaluator_version != input.threshold.evaluator_version
        || input.holdout_set.evaluator_version != input.threshold.evaluator_version
    {
        return Err(EngineError::WriteRejected(
            "canonical meta experiment requires distinct fixed and holdout sealed sets".to_owned(),
        ));
    }
    validate_meta_sealed_set(&input.fixed_set)?;
    validate_meta_sealed_set(&input.holdout_set)?;
    for (execution, set) in [
        (&input.fixed_baseline, &input.fixed_set),
        (&input.fixed_candidate, &input.fixed_set),
        (&input.holdout_baseline, &input.holdout_set),
        (&input.holdout_candidate, &input.holdout_set),
    ] {
        validate_meta_replay_execution(execution, set, input.project_id)?;
    }
    if input.fixed_candidate.run.candidate_ref.as_deref() != Some(input.candidate_ref.as_str())
        || input.holdout_candidate.run.candidate_ref.as_deref()
            != Some(input.candidate_ref.as_str())
        || input.fixed_candidate.run.baseline_ref.as_deref()
            != Some(input.baseline_policy_hash.as_str())
        || input.holdout_candidate.run.baseline_ref.as_deref()
            != Some(input.baseline_policy_hash.as_str())
        || input.fixed_baseline.run.candidate_ref.as_deref()
            != Some(input.baseline_policy_hash.as_str())
        || input.holdout_baseline.run.candidate_ref.as_deref()
            != Some(input.baseline_policy_hash.as_str())
        || replay_case_ids(&input.fixed_baseline.run) != replay_case_ids(&input.fixed_candidate.run)
        || replay_case_ids(&input.holdout_baseline.run)
            != replay_case_ids(&input.holdout_candidate.run)
    {
        return Err(EngineError::WriteRejected(
            "canonical meta replay versions or memberships do not match".to_owned(),
        ));
    }
    Ok(())
}

fn validate_meta_sealed_set(set: &SealedReplaySetRecord) -> Result<(), EngineError> {
    let sealed_hash = checksum_serialized(&serde_json::json!({
        "set": set.set,
        "role": set.role,
        "version": set.version,
        "evaluator_hash": set.evaluator_hash,
        "profile_hash": set.profile_hash,
        "context_hash": set.context_hash,
        "case_hashes": set.case_hashes,
        "snapshot_hashes": set.snapshot_hashes,
    }))?;
    let evaluator_hash = checksum_serialized(&serde_json::json!({
        "engine": "eliot-replay-evaluator",
        "version": set.evaluator_version,
    }))?;
    let context_hash = checksum_serialized(&serde_json::json!({
        "context_version": set.context_version,
    }))?;
    if !set.set.fixed
        || set.version == 0
        || set.case_hashes.len() < 2
        || set.set.cases.len() != set.case_hashes.len()
        || set.case_hashes.len() != set.snapshot_hashes.len()
        || set.sealed_hash != sealed_hash
        || set.record_id != format!("replay-set:{sealed_hash}")
        || set.evaluator_hash != evaluator_hash
        || set.context_hash != context_hash
    {
        return Err(EngineError::WriteRejected(
            "canonical meta replay set failed its sealed hash fence".to_owned(),
        ));
    }
    Ok(())
}

fn validate_meta_replay_execution(
    execution: &CanonicalReplayExecutionRecord,
    set: &SealedReplaySetRecord,
    project_id: ProjectId,
) -> Result<(), EngineError> {
    crate::replay::ReplayRunnerService::validate_canonical_execution_identity(execution)?;
    let result_projection = execution
        .run
        .case_results
        .iter()
        .map(|result| {
            serde_json::json!({
                "replay_case_id": result.replay_case_id,
                "status": result.status,
                "measurements": result.measurements,
                "produced_refs": result.produced_refs,
                "errors": result.errors,
                "duration_ms": result.duration_ms,
            })
        })
        .collect::<Vec<_>>();
    let reproducibility_hash = checksum_serialized(&serde_json::json!({
        "sealed_input_hash": execution.run.sealed_input_hash,
        "baseline_ref": execution.run.baseline_ref,
        "candidate_ref": execution.run.candidate_ref,
        "case_results": result_projection,
    }))?;
    if execution.sealed_set_ref != set.record_id
        || execution.sealed_set_hash != set.sealed_hash
        || execution.evaluator_hash != set.evaluator_hash
        || execution.profile_hash != set.profile_hash
        || execution.context_hash != set.context_hash
        || execution.run.project_id != project_id
        || execution.run.replay_set_id != set.set.replay_set_id
        || execution.run.status != ReplayRunStatus::Completed
        || execution.audit.replay_run_id != execution.run.replay_run_id
        || !execution.audit.authority_mutation_blocked
        || !execution.audit.taint_preserved
        || !execution.run.run_profile.deterministic
        || !execution.run.run_profile.no_external_network
        || !execution.run.run_profile.no_mutation
        || execution.run.case_results.is_empty()
        || execution.run.reproducibility_hash != reproducibility_hash
        || execution.execution_id != format!("sealed-replay:{reproducibility_hash}")
    {
        return Err(EngineError::WriteRejected(
            "canonical meta metric source is not an intact sealed replay execution".to_owned(),
        ));
    }
    Ok(())
}

fn replay_case_ids(run: &ReplayRun) -> BTreeSet<eliot_types::ReplayCaseId> {
    run.case_results
        .iter()
        .map(|result| result.replay_case_id)
        .collect()
}

fn derive_meta_isolation_fence(
    input: &CanonicalMetaExperimentInput,
) -> Result<MetaIsolationFence, EngineError> {
    Ok(MetaIsolationFence {
        evaluator_version: input.fixed_set.evaluator_version.clone(),
        evaluator_hash: input.fixed_set.evaluator_hash.clone(),
        threshold_version: input.threshold.schema_version.clone(),
        threshold_hash: checksum_serialized(&input.threshold)?,
        fixed_replay_set_hash: input.fixed_set.sealed_hash.clone(),
        holdout_replay_set_hash: input.holdout_set.sealed_hash.clone(),
    })
}

fn replay_pass_basis_points(run: &ReplayRun) -> u16 {
    let passed = run
        .case_results
        .iter()
        .filter(|result| result.status == ReplayCaseStatus::Passed)
        .count();
    let total = run.case_results.len();
    if total == 0 {
        return 0;
    }
    u16::try_from((passed.saturating_mul(10_000)) / total).unwrap_or(10_000)
}

fn average_basis_points(left: u16, right: u16) -> u16 {
    let sum = u32::from(left) + u32::from(right);
    u16::try_from(sum / 2).unwrap_or(10_000)
}

fn replay_counter_regressions(
    baselines: [&CanonicalReplayExecutionRecord; 2],
    candidates: [&CanonicalReplayExecutionRecord; 2],
) -> u16 {
    let count = baselines
        .into_iter()
        .zip(candidates)
        .flat_map(|(baseline, candidate)| {
            let candidate_results = candidate
                .run
                .case_results
                .iter()
                .map(|result| (result.replay_case_id, result.status.clone()))
                .collect::<BTreeMap<_, _>>();
            baseline.run.case_results.iter().filter(move |result| {
                result.status == ReplayCaseStatus::Passed
                    && candidate_results.get(&result.replay_case_id)
                        != Some(&ReplayCaseStatus::Passed)
            })
        })
        .count();
    u16::try_from(count).unwrap_or(u16::MAX)
}

fn meta_replay_result_pair_hashes(
    input: &CanonicalMetaExperimentInput,
) -> Result<[String; 2], EngineError> {
    Ok([
        checksum_serialized(&serde_json::json!({
            "baseline": input.fixed_baseline.run.reproducibility_hash,
            "candidate": input.fixed_candidate.run.reproducibility_hash,
        }))?,
        checksum_serialized(&serde_json::json!({
            "baseline": input.holdout_baseline.run.reproducibility_hash,
            "candidate": input.holdout_candidate.run.reproducibility_hash,
        }))?,
    ])
}

#[allow(clippy::too_many_arguments)]
fn canonical_meta_metric(
    metric_name: &str,
    input: &CanonicalMetaExperimentInput,
    result_pair_hashes: &[String; 2],
    baseline_value: i64,
    candidate_value: i64,
    allowed_regression: u64,
    higher_is_better: bool,
) -> Result<CanonicalMetaMetricEvidence, EngineError> {
    let evidence_hash = checksum_serialized(&serde_json::json!({
        "metric_name": metric_name,
        "fixed_baseline": input.fixed_baseline.execution_id,
        "fixed_candidate": input.fixed_candidate.execution_id,
        "fixed_result_hash": result_pair_hashes[0],
        "holdout_baseline": input.holdout_baseline.execution_id,
        "holdout_candidate": input.holdout_candidate.execution_id,
        "holdout_result_hash": result_pair_hashes[1],
        "baseline_value": baseline_value,
        "candidate_value": candidate_value,
        "allowed_regression": allowed_regression,
        "higher_is_better": higher_is_better,
    }))?;
    Ok(CanonicalMetaMetricEvidence {
        metric_name: metric_name.to_owned(),
        fixed_replay_run_ref: input.fixed_candidate.execution_id.clone(),
        fixed_result_hash: result_pair_hashes[0].clone(),
        holdout_replay_run_ref: input.holdout_candidate.execution_id.clone(),
        holdout_result_hash: result_pair_hashes[1].clone(),
        baseline_value,
        candidate_value,
        allowed_regression,
        higher_is_better,
        evidence_hash,
    })
}

fn canonical_meta_no_mutation_confirmed(input: &CanonicalMetaExperimentInput) -> bool {
    [
        &input.fixed_baseline,
        &input.fixed_candidate,
        &input.holdout_baseline,
        &input.holdout_candidate,
    ]
    .into_iter()
    .all(|execution| {
        execution.audit.authority_mutation_blocked
            && execution.run.run_profile.no_mutation
            && execution.run.run_profile.no_external_network
    })
}

fn validate_replay_threshold_policy(policy: &ReplayThresholdPolicyV1) -> Result<(), EngineError> {
    if policy.schema_version != "1"
        || policy.evaluator_version.trim().is_empty()
        || policy.minimum_pass_basis_points > 10_000
    {
        return Err(EngineError::WriteRejected(
            "only replay threshold policy schema version 1 is supported".to_owned(),
        ));
    }
    Ok(())
}

fn validate_meta_policy_payload(
    payload: &ExperimentalMetaPolicyPayload,
) -> Result<(), EngineError> {
    match payload {
        ExperimentalMetaPolicyPayload::ReplayThresholdV1 { policy } => {
            validate_replay_threshold_policy(policy)
        }
        ExperimentalMetaPolicyPayload::Unsupported { .. } => Err(EngineError::WriteRejected(
            "unsupported experimental meta policy kind is blocked".to_owned(),
        )),
    }
}

fn validate_meta_policy_candidate(
    candidate: &ExperimentalMetaPolicyCandidate,
) -> Result<(), EngineError> {
    validate_meta_policy_payload(&candidate.baseline)?;
    validate_meta_policy_payload(&candidate.candidate)?;
    if candidate.source_experiment_ref.trim().is_empty()
        || candidate.baseline_hash != checksum_serialized(&candidate.baseline)?
        || candidate.candidate_hash != checksum_serialized(&candidate.candidate)?
        || candidate.baseline_hash == candidate.candidate_hash
    {
        return Err(EngineError::WriteRejected(
            "experimental policy candidate failed its exact hash fence".to_owned(),
        ));
    }
    Ok(())
}

fn validate_meta_policy_authorization(
    authorization: &MetaPolicyAuthorization,
    exact_action_hash: &str,
) -> Result<(), EngineError> {
    if authorization.operator_command_ref.trim().is_empty()
        || authorization.expected_action_hash != exact_action_hash
        || authorization.exact_action_hash != exact_action_hash
    {
        return Err(EngineError::WriteRejected(
            "meta policy authorization does not match the exact action hash".to_owned(),
        ));
    }
    Ok(())
}

fn meta_gate_results(results: [bool; 4]) -> Vec<MetaExperimentGateResult> {
    [
        MetaExperimentGate::FixedReplay,
        MetaExperimentGate::Holdout,
        MetaExperimentGate::PrimaryMetrics,
        MetaExperimentGate::CounterMetrics,
    ]
    .into_iter()
    .zip(results)
    .map(|(gate, passed)| MetaExperimentGateResult { gate, passed })
    .collect()
}

fn meta_evidence_complete(input: &MetaExperimentInput) -> bool {
    let coupled_change_documented = input.changed_variables.len() <= 1
        || input
            .coupled_change_rationale
            .as_deref()
            .is_some_and(|rationale| !rationale.trim().is_empty());
    let expected_fixed_set_ref = format!("replay-set:{}", input.fixed_replay_run.replay_set_id);
    let expected_holdout_set_ref = format!("replay-set:{}", input.holdout_replay_run.replay_set_id);
    let replay_versions_match = input.fixed_replay_run.project_id == input.project_id
        && input.holdout_replay_run.project_id == input.project_id
        && input.fixed_replay_run.candidate_ref.as_deref() == Some(input.candidate_ref.as_str())
        && input.holdout_replay_run.candidate_ref.as_deref() == Some(input.candidate_ref.as_str())
        && input.fixed_replay_run.baseline_ref.as_deref()
            == Some(input.baseline_policy_hash.as_str())
        && input.holdout_replay_run.baseline_ref.as_deref()
            == Some(input.baseline_policy_hash.as_str());
    let metric_names = input
        .primary_metrics
        .iter()
        .chain(&input.counter_metrics)
        .map(|metric| metric.metric_name.as_str())
        .collect::<BTreeSet<_>>();
    let metric_count = input.primary_metrics.len() + input.counter_metrics.len();
    !input.candidate_ref.trim().is_empty()
        && !input.profile_id.trim().is_empty()
        && !input.changed_variables.is_empty()
        && coupled_change_documented
        && !input.baseline_policy_hash.trim().is_empty()
        && !input.candidate_policy_hash.trim().is_empty()
        && input.baseline_policy_hash != input.candidate_policy_hash
        && input.fixed_replay_set_ref == expected_fixed_set_ref
        && input.holdout_set_ref == expected_holdout_set_ref
        && input.fixed_replay_set_ref != input.holdout_set_ref
        && replay_versions_match
        && !input.primary_metrics.is_empty()
        && !input.counter_metrics.is_empty()
        && metric_names.len() == metric_count
        && input
            .primary_metrics
            .iter()
            .chain(&input.counter_metrics)
            .all(|metric| !metric.metric_name.trim().is_empty() && !metric.evidence_refs.is_empty())
}

fn build_meta_experiment_record(
    input: MetaExperimentInput,
    blocking_reasons: Vec<String>,
    reproducibility_hash: String,
    decision: MetaExperimentDecision,
    no_mutation_confirmed: bool,
) -> HarnessExperimentRecord {
    let primary_metric_refs = meta_metric_refs(&input.primary_metrics);
    let counter_metric_refs = meta_metric_refs(&input.counter_metrics);
    HarnessExperimentRecord {
        harness_experiment_record_id: HarnessExperimentRecordId::new_v7(),
        eval_run_id: input.eval_run_id,
        profile_id: input.profile_id,
        verdict_id: input.verdict_id,
        notes: if blocking_reasons.is_empty() {
            vec!["experiment passed but remains candidate-only pending authorization".to_owned()]
        } else {
            blocking_reasons
        },
        no_mutation_confirmed,
        project_id: Some(input.project_id),
        candidate_ref: input.candidate_ref,
        change_class: input.change_class,
        changed_variables: input.changed_variables,
        evaluator_snapshot_ref: input.isolation.evaluator_hash_before,
        baseline_policy_hash: input.baseline_policy_hash,
        candidate_policy_hash: input.candidate_policy_hash,
        fixed_replay_set_ref: input.fixed_replay_set_ref,
        holdout_set_ref: input.holdout_set_ref,
        replay_run_refs: vec![format!(
            "replay-run:{}",
            input.fixed_replay_run.replay_run_id
        )],
        holdout_run_refs: vec![format!(
            "replay-run:{}",
            input.holdout_replay_run.replay_run_id
        )],
        primary_metric_refs,
        counter_metric_refs,
        reproducibility_hash,
        uncertainty: "integer metrics cover sealed declared observations; external behavior still requires live dogfood".to_owned(),
        decision,
        authorized_command_ref: None,
        rollback_target_ref: String::new(),
        rollback_command_ref: String::new(),
        authoritative_metric_evidence: Vec::new(),
        authoritative_isolation_rejection: None,
        authoritative_policy_candidate: None,
        disposition_receipt: None,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn meta_metric_refs(metrics: &[MetaMetricObservation]) -> Vec<String> {
    metrics
        .iter()
        .flat_map(|metric| {
            std::iter::once(metric.evidence_ref()).chain(metric.evidence_refs.iter().cloned())
        })
        .collect()
}

fn meta_reproducibility_hash(input: &MetaExperimentInput) -> Result<String, EngineError> {
    let value = serde_json::json!({
        "project_id": input.project_id,
        "profile_id": input.profile_id,
        "candidate_ref": input.candidate_ref,
        "change_class": input.change_class,
        "changed_variables": input.changed_variables,
        "coupled_change_rationale": input.coupled_change_rationale,
        "baseline_policy_hash": input.baseline_policy_hash,
        "candidate_policy_hash": input.candidate_policy_hash,
        "fixed_replay_set_ref": input.fixed_replay_set_ref,
        "holdout_set_ref": input.holdout_set_ref,
        "fixed_replay_input_hash": input.fixed_replay_run.sealed_input_hash,
        "fixed_replay_result_hash": input.fixed_replay_run.reproducibility_hash,
        "holdout_replay_input_hash": input.holdout_replay_run.sealed_input_hash,
        "holdout_replay_result_hash": input.holdout_replay_run.reproducibility_hash,
        "primary_metrics": input.primary_metrics,
        "counter_metrics": input.counter_metrics,
        "isolation": input.isolation,
    });
    Ok(checksum_text(&String::from_utf8_lossy(
        &serde_json::to_vec(&value)?,
    )))
}

fn checksum_text(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn u64_count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn u32_count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn u8_count(value: u32) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}
