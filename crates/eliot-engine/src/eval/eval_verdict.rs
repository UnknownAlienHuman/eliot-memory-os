//! Report-only evaluation verdict projection.
//!
//! Architecture anchors: `A5.5` (Verifier and Evaluation Contract) and
//! `A14.6` (evaluation). Implementation anchors: `I6.7` (evaluation contract)
//! and `I18.47` (evaluator, benchmark, and credit-assignment integrity).
//!
//! This child maps an already-observed `EvalRun` into scores, failure clusters,
//! and an explicit non-authoritative verdict. It cannot mutate current truth,
//! memory lifecycle, policy, action permissions, or completion state.

use std::collections::BTreeMap;

use eliot_types::{
    EvalCaseResult, EvalCaseStatus, EvalFailureCluster, EvalFailureClusterId, EvalFamily,
    EvalFamilyScore, EvalRun, EvalRunId, EvalRunStatus, EvalVerdict, EvalVerdictId,
    EvalVerdictStatus,
};
use time::OffsetDateTime;

use super::{u8_count, u32_count};

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
