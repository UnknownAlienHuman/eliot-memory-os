#![allow(clippy::cast_precision_loss, clippy::too_many_lines)]

use crate::EngineError;
use eliot_types::{
    ApplicabilityVerdict, CausalBridgeQualityReport, CognitiveCaseResult, CognitiveCaseSpec,
    CognitiveReaderAnswer, CognitiveTransferLabReport, CognitiveTransferMetrics,
    ContextReinstatementBundle, ContrastiveAbstractionResult, ExperienceAuthority, ExperienceBrief,
    ExperienceCase, ExperienceFormationResult, ExperienceMaturity, ExperienceMaturityState,
    ExperiencePattern, ExperienceRecallRequest, ExperienceRecallResponse, ExperienceUseOutcome,
    FusedRankRoute, FusedRankTrace, GraphHealthResponse, MemoryApplicabilityDecision,
    MemoryExposureMode, MemoryKind, MemoryNeed, MemoryNeedDecision, NegativeTransferHarm,
    NegativeTransferLifecycleAction, NegativeTransferRecord, TaskMeaningFrame, VerificationResult,
    VerifiedEpisodeProjection, WriteId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use time::OffsetDateTime;

mod corpus_profile;

pub use corpus_profile::CorpusProfileService;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransferValidationEvidence {
    pub paraphrase_survived: bool,
    pub near_miss_rejected: bool,
    pub independent_host_refs: Vec<String>,
    pub verified_decision_delta_refs: Vec<String>,
    pub ordered_steps: Vec<String>,
    pub verifier: Option<String>,
    pub stop_condition: Option<String>,
    pub rollback: Option<String>,
    pub repeated_success_count: u32,
}

#[derive(Clone, Debug, Default)]
pub struct CorpusProfileInput {
    pub graph_health: Option<GraphHealthResponse>,
    pub verified_episode_count: u64,
    pub physical_case_record_count: u64,
    pub physical_pattern_record_count: u64,
    pub cases: Vec<ExperienceCase>,
    pub patterns: Vec<ExperiencePattern>,
    pub active_procedure_count: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ExperienceFormationService;

impl ExperienceFormationService {
    pub fn reconstruct(
        episode: VerifiedEpisodeProjection,
    ) -> Result<ExperienceFormationResult, EngineError> {
        if episode.source_episode_refs.is_empty()
            || episode.source_task_refs.is_empty()
            || episode.exact_evidence_refs.is_empty()
            || episode.intervention_and_outcome.verifier_refs.is_empty()
            || episode
                .intervention_and_outcome
                .observed_outcome
                .trim()
                .is_empty()
        {
            return Err(EngineError::WriteRejected(
                "experience reconstruction requires an exact episode, task, evidence, outcome, and verifier"
                    .to_owned(),
            ));
        }
        if episode.causal_model.mechanism.trim().is_empty()
            || episode.transfer_boundary.retrieval_cues.is_empty()
        {
            return Ok(ExperienceFormationResult::NothingToLearn {
                reason:
                    "verified episode has no evidence-backed reusable mechanism or retrieval cue"
                        .to_owned(),
            });
        }
        if episode.transfer_boundary.applies_when.is_empty()
            || (episode.transfer_boundary.does_not_apply_when.is_empty()
                && episode.transfer_boundary.counterexample_refs.is_empty())
            || episode
                .transfer_boundary
                .recommended_first_probe
                .trim()
                .is_empty()
            || episode.transfer_boundary.required_local_checks.is_empty()
        {
            return Err(EngineError::WriteRejected(
                "experience reconstruction requires applies-when, a non-applicability boundary or counterexample, and a local first probe"
                    .to_owned(),
            ));
        }
        let case_id = semantic_id("experience-case", &episode)?;
        let formed_at = episode
            .source_branch_commit_environment
            .observed_at
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let mut exact_source_refs = episode.source_episode_refs.clone();
        exact_source_refs.extend(episode.source_task_refs.clone());
        exact_source_refs.extend(episode.exact_evidence_refs.clone());
        exact_source_refs.extend(episode.intervention_and_outcome.verifier_refs.clone());
        dedup(&mut exact_source_refs);
        Ok(ExperienceFormationResult::Formed {
            experience_case: Box::new(ExperienceCase {
                case_id,
                project_id: episode.project_id,
                source_episode_refs: episode.source_episode_refs,
                source_task_refs: episode.source_task_refs,
                source_agent_sessions: episode.source_agent_sessions,
                source_branch_commit_environment: episode.source_branch_commit_environment,
                problem_frame: episode.problem_frame,
                causal_model: episode.causal_model,
                intervention_and_outcome: episode.intervention_and_outcome,
                transfer_boundary: episode.transfer_boundary,
                maturity: ExperienceMaturity {
                    state: ExperienceMaturityState::ReconstructedCase,
                    support_count: 1,
                    contrast_count: 0,
                    cross_host_transfer_count: 0,
                    negative_transfer_count: 0,
                },
                authority: ExperienceAuthority {
                    current_truth: false,
                    candidate_only: true,
                    exact_source_refs,
                    reasoning_job_ref: episode.reasoning_job_ref,
                    review_refs: Vec::new(),
                    canonical_receipt: None,
                },
                formed_at,
            }),
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ContrastiveAbstractionService;

impl ContrastiveAbstractionService {
    pub fn abstract_cases(
        project_id: eliot_types::ProjectId,
        cases: &[ExperienceCase],
    ) -> Result<ContrastiveAbstractionResult, EngineError> {
        if cases.len() < 2 {
            return Ok(ContrastiveAbstractionResult::NoLearnablePattern {
                reason: "contrastive abstraction requires at least two cases".to_owned(),
            });
        }
        if cases.iter().any(|case| {
            case.project_id != project_id
                || case.authority.current_truth
                || !case.authority.candidate_only
                || case.maturity.state == ExperienceMaturityState::RawEpisode
        }) {
            return Err(EngineError::WriteRejected(
                "pattern members must be candidate-only reconstructed cases from one project"
                    .to_owned(),
            ));
        }
        let mut cases = cases.iter().collect::<Vec<_>>();
        cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
        let mechanism = normalized(&cases[0].causal_model.mechanism);
        if mechanism.is_empty()
            || cases
                .iter()
                .any(|case| normalized(&case.causal_model.mechanism) != mechanism)
        {
            return Ok(ContrastiveAbstractionResult::NoLearnablePattern {
                reason: "member cases do not share an evidence-backed causal mechanism".to_owned(),
            });
        }
        let counterexamples = cases
            .iter()
            .flat_map(|case| case.transfer_boundary.counterexample_refs.clone())
            .collect::<Vec<_>>();
        let failure_conditions = cases
            .iter()
            .flat_map(|case| case.transfer_boundary.does_not_apply_when.clone())
            .collect::<Vec<_>>();
        if counterexamples.is_empty() && failure_conditions.is_empty() {
            return Ok(ContrastiveAbstractionResult::NoLearnablePattern {
                reason: "no contrast or where-not-apply boundary was preserved".to_owned(),
            });
        }
        let mut exact_source_refs = cases
            .iter()
            .flat_map(|case| case.authority.exact_source_refs.clone())
            .collect::<Vec<_>>();
        dedup(&mut exact_source_refs);
        let mut success_conditions = cases
            .iter()
            .flat_map(|case| case.transfer_boundary.applies_when.clone())
            .collect::<Vec<_>>();
        dedup(&mut success_conditions);
        let mut classifier_features = cases
            .iter()
            .flat_map(|case| case.transfer_boundary.retrieval_cues.clone())
            .chain(
                cases
                    .iter()
                    .flat_map(|case| case.transfer_boundary.conceptual_aliases.clone()),
            )
            .collect::<Vec<_>>();
        dedup(&mut classifier_features);
        let member_case_refs = cases
            .iter()
            .map(|case| case.case_id.clone())
            .collect::<Vec<_>>();
        let pattern_id = semantic_id(
            "experience-pattern",
            &(
                project_id,
                &member_case_refs,
                &mechanism,
                &success_conditions,
                &failure_conditions,
                &counterexamples,
            ),
        )?;
        let formed_at = cases
            .iter()
            .map(|case| case.formed_at)
            .min()
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        Ok(ContrastiveAbstractionResult::Formed {
            pattern: Box::new(ExperiencePattern {
                pattern_id,
                project_id,
                member_case_refs,
                invariant_core: vec![cases[0].causal_model.mechanism.clone()],
                varying_surface_features: cases
                    .iter()
                    .map(|case| case.problem_frame.trigger_or_symptom.clone())
                    .filter(|value| !value.trim().is_empty())
                    .collect(),
                success_conditions,
                failure_conditions,
                counterexamples,
                applicability_classifier_features: classifier_features,
                required_local_probe: cases[0].transfer_boundary.recommended_first_probe.clone(),
                maturity: ExperienceMaturity {
                    state: ExperienceMaturityState::PatternCandidate,
                    support_count: u32::try_from(cases.len()).unwrap_or(u32::MAX),
                    contrast_count: u32::try_from(
                        cases
                            .iter()
                            .filter(|case| {
                                !case.transfer_boundary.does_not_apply_when.is_empty()
                                    || !case.transfer_boundary.counterexample_refs.is_empty()
                            })
                            .count(),
                    )
                    .unwrap_or(u32::MAX),
                    cross_host_transfer_count: 0,
                    negative_transfer_count: cases
                        .iter()
                        .map(|case| case.maturity.negative_transfer_count)
                        .sum(),
                },
                transfer_evidence: Vec::new(),
                authority: ExperienceAuthority {
                    current_truth: false,
                    candidate_only: true,
                    exact_source_refs,
                    reasoning_job_ref: None,
                    review_refs: Vec::new(),
                    canonical_receipt: None,
                },
                formed_at,
            }),
        })
    }
}

/// Produces the active logical case projection without deleting immutable canonical history.
/// Later records replace earlier records with the same curator job or semantic content key.
#[must_use]
pub fn deduplicate_experience_cases(cases: Vec<ExperienceCase>) -> Vec<ExperienceCase> {
    let mut projected = BTreeMap::new();
    for case in cases {
        projected.insert(experience_case_projection_key(&case), case);
    }
    projected.into_values().collect()
}

/// Produces the active logical pattern projection while retaining superseded physical records.
#[must_use]
pub fn deduplicate_experience_patterns(patterns: Vec<ExperiencePattern>) -> Vec<ExperiencePattern> {
    let mut projected = BTreeMap::new();
    for pattern in patterns {
        projected.insert(experience_pattern_projection_key(&pattern), pattern);
    }
    projected.into_values().collect()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MaturityGateService;

impl MaturityGateService {
    pub fn transition(
        current: &ExperienceMaturity,
        target: ExperienceMaturityState,
        evidence: &TransferValidationEvidence,
    ) -> Result<ExperienceMaturity, EngineError> {
        let allowed = match target {
            ExperienceMaturityState::ReconstructedCase => {
                current.state == ExperienceMaturityState::RawEpisode
            }
            ExperienceMaturityState::SchemaCandidate
            | ExperienceMaturityState::PatternCandidate => {
                current.state == ExperienceMaturityState::ReconstructedCase
                    && current.support_count >= 2
                    && current.contrast_count >= 1
            }
            ExperienceMaturityState::TransferValidated => {
                matches!(
                    current.state,
                    ExperienceMaturityState::SchemaCandidate
                        | ExperienceMaturityState::PatternCandidate
                ) && evidence.paraphrase_survived
                    && evidence.near_miss_rejected
                    && !evidence.independent_host_refs.is_empty()
                    && !evidence.verified_decision_delta_refs.is_empty()
            }
            ExperienceMaturityState::ProcedureCandidate => {
                current.state == ExperienceMaturityState::TransferValidated
                    && !evidence.ordered_steps.is_empty()
                    && evidence.verifier.as_deref().is_some_and(non_empty)
                    && evidence.stop_condition.as_deref().is_some_and(non_empty)
                    && evidence.rollback.as_deref().is_some_and(non_empty)
            }
            ExperienceMaturityState::ActiveProcedure => {
                current.state == ExperienceMaturityState::ProcedureCandidate
                    && evidence.repeated_success_count >= 2
                    && evidence.verifier.as_deref().is_some_and(non_empty)
                    && evidence.stop_condition.as_deref().is_some_and(non_empty)
                    && evidence.rollback.as_deref().is_some_and(non_empty)
            }
            ExperienceMaturityState::Stale | ExperienceMaturityState::Suppressed => true,
            ExperienceMaturityState::RawEpisode => false,
        };
        if !allowed {
            return Err(EngineError::WriteRejected(format!(
                "maturity transition {:?} -> {:?} lacks required contrast, transfer, or procedure evidence",
                current.state, target
            )));
        }
        let mut next = current.clone();
        next.state = target;
        if target == ExperienceMaturityState::TransferValidated {
            next.cross_host_transfer_count =
                u32::try_from(evidence.independent_host_refs.len()).unwrap_or(u32::MAX);
        }
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TaskMeaningService;

impl TaskMeaningService {
    pub fn bridge_quality(frame: &TaskMeaningFrame) -> CausalBridgeQualityReport {
        let hops = [
            ("intent", !frame.normalized_goal.trim().is_empty()),
            (
                "domain_concept",
                !frame.task_or_action_type.trim().is_empty(),
            ),
            ("module_boundary", !frame.project_module_boundary.is_empty()),
            ("file_symbol_config", !frame.files_symbols_config.is_empty()),
            (
                "control_data_state_path",
                !frame.control_data_state_path.is_empty(),
            ),
            (
                "runtime_observable",
                !frame.predicted_observable.trim().is_empty(),
            ),
            ("verifier", !frame.verifier_need.trim().is_empty()),
        ];
        let unknown_hops = hops
            .iter()
            .filter(|(_, present)| !present)
            .map(|(name, _)| (*name).to_owned())
            .collect::<Vec<_>>();
        let bridge_hops = hops
            .iter()
            .filter(|(_, present)| *present)
            .map(|(name, _)| (*name).to_owned())
            .collect::<Vec<_>>();
        let exact_evidence_per_hop = bridge_hops
            .iter()
            .map(|hop| (hop.clone(), frame.current_evidence.clone()))
            .collect();
        CausalBridgeQualityReport {
            task_id: frame.task_id.clone(),
            report_ref: frame
                .codecortex_report_ref
                .clone()
                .unwrap_or_else(|| "no-codecortex-report".to_owned()),
            bridge_hops,
            exact_evidence_per_hop,
            unknown_hops: unknown_hops.clone(),
            predicted_observable: frame.predicted_observable.clone(),
            verifier: frame.verifier_need.clone(),
            decision_sufficient: unknown_hops.is_empty() && !frame.current_evidence.is_empty(),
            missing_owner_boundary: frame
                .project_module_boundary
                .is_empty()
                .then(|| "project_module_boundary".to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryNeedService;

impl MemoryNeedService {
    pub fn decide(frame: &TaskMeaningFrame, requested: Option<MemoryNeed>) -> MemoryNeedDecision {
        let need = requested.unwrap_or_else(|| {
            if frame.material_unknowns.is_empty()
                && TaskMeaningService::bridge_quality(frame).decision_sufficient
            {
                MemoryNeed::None
            } else if !frame.problem_or_failure_signature.trim().is_empty()
                || !frame.control_data_state_path.is_empty()
                || frame.execution_class.as_ref().is_some_and(|class| {
                    matches!(
                        class.action,
                        eliot_types::TaskExecutionAction::CrossSubsystem
                            | eliot_types::TaskExecutionAction::Destructive
                    )
                })
            {
                MemoryNeed::CausalCase
            } else {
                MemoryNeed::CurrentFact
            }
        });
        MemoryNeedDecision {
            task_id: frame.task_id.clone(),
            need,
            reason: if need == MemoryNeed::None {
                "current evidence is decision-sufficient; NO_USEFUL_MEMORY".to_owned()
            } else {
                format!("task meaning requires {need:?} before a material decision")
            },
            expected_decision_delta: if need == MemoryNeed::None {
                "none".to_owned()
            } else {
                "improve the first boundary, probe, or verifier without granting truth".to_owned()
            },
            max_candidates: if need == MemoryNeed::None { 0 } else { 3 },
            max_expansions: usize::from(matches!(
                need,
                MemoryNeed::CausalCase | MemoryNeed::HistoricalEpisode
            )),
            deep_reconstruction_allowed: need == MemoryNeed::CausalCase,
            stop_if_no_novelty: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryKindCompatibilityService;

impl MemoryKindCompatibilityService {
    pub fn compatible(need: MemoryNeed, kind: MemoryKind) -> bool {
        match need {
            MemoryNeed::None => false,
            MemoryNeed::CurrentFact => kind == MemoryKind::CurrentTruth,
            MemoryNeed::HistoricalEpisode => kind == MemoryKind::HistoricalEpisode,
            MemoryNeed::CausalCase => {
                matches!(kind, MemoryKind::CausalCase | MemoryKind::HistoricalEpisode)
            }
            MemoryNeed::ExperiencePattern => kind == MemoryKind::ExperiencePattern,
            MemoryNeed::Procedure => kind == MemoryKind::Procedure,
            MemoryNeed::NegativeMemory => kind == MemoryKind::NegativeMemory,
            MemoryNeed::DecisionRationale => kind == MemoryKind::DecisionRationale,
        }
    }

    pub fn require_compatible(need: MemoryNeed, kind: MemoryKind) -> Result<(), EngineError> {
        if Self::compatible(need, kind) {
            Ok(())
        } else {
            Err(EngineError::WriteRejected(format!(
                "memory kind {kind:?} is incompatible with need {need:?}; similarity is not applicability proof"
            )))
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ApplicabilityService;

impl ApplicabilityService {
    pub fn decide(frame: &TaskMeaningFrame, case: &ExperienceCase) -> MemoryApplicabilityDecision {
        let corpus = applicability_corpus(frame);
        let matched_conditions = case
            .transfer_boundary
            .applies_when
            .iter()
            .filter(|condition| condition_matches(condition, &corpus))
            .cloned()
            .collect::<Vec<_>>();
        let failed_conditions = case
            .transfer_boundary
            .applies_when
            .iter()
            .filter(|condition| !condition_matches(condition, &corpus))
            .cloned()
            .collect::<Vec<_>>();
        let forbidden_matches = case
            .transfer_boundary
            .does_not_apply_when
            .iter()
            .filter(|condition| condition_matches(condition, &corpus))
            .cloned()
            .collect::<Vec<_>>();
        let mut critical_differences = failed_conditions.clone();
        critical_differences.extend(forbidden_matches.clone());
        let local_check_satisfied = case
            .transfer_boundary
            .required_local_checks
            .iter()
            .all(|check| condition_matches(check, &corpus));
        let verdict = if matches!(
            case.maturity.state,
            ExperienceMaturityState::RawEpisode
                | ExperienceMaturityState::Stale
                | ExperienceMaturityState::Suppressed
        ) || case.authority.current_truth
        {
            ApplicabilityVerdict::SuppressImmature
        } else if !forbidden_matches.is_empty() || !failed_conditions.is_empty() {
            ApplicabilityVerdict::NearMiss
        } else if case.transfer_boundary.applies_when.is_empty() {
            ApplicabilityVerdict::InsufficientContext
        } else if !local_check_satisfied || !frame.material_unknowns.is_empty() {
            ApplicabilityVerdict::RequireProbe
        } else if matched_conditions.len() == case.transfer_boundary.applies_when.len() {
            ApplicabilityVerdict::ApplicableAsPrior
        } else if matched_conditions.is_empty() {
            ApplicabilityVerdict::AnalogyOnly
        } else {
            ApplicabilityVerdict::PartiallyApplicable
        };
        let mapped_entity_roles = case
            .problem_frame
            .entity_roles
            .iter()
            .filter_map(|(role, source)| {
                frame
                    .entity_roles
                    .get(role)
                    .map(|target| (format!("{role}:{source}"), target.clone()))
            })
            .collect();
        MemoryApplicabilityDecision {
            decision_id: format!("applicability-{}", WriteId::new_v7()),
            task_frame_ref: frame.task_id.clone(),
            experience_ref: case.case_id.clone(),
            mapped_entity_roles,
            matched_conditions,
            critical_differences,
            failed_conditions,
            current_evidence: frame.current_evidence.clone(),
            local_probe_required: (!local_check_satisfied
                || verdict == ApplicabilityVerdict::RequireProbe)
                .then(|| case.transfer_boundary.recommended_first_probe.clone()),
            predicted_decision_delta: match verdict {
                ApplicabilityVerdict::ApplicableAsPrior
                | ApplicabilityVerdict::RequireProbe
                | ApplicabilityVerdict::PartiallyApplicable => {
                    "change only the first probe after local revalidation".to_owned()
                }
                _ => "none; reject direct transfer".to_owned(),
            },
            verdict,
            receipt: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ExperienceRetrievalService;

impl ExperienceRetrievalService {
    pub fn recall(
        request: &ExperienceRecallRequest,
        cases: &[ExperienceCase],
    ) -> ExperienceRecallResponse {
        if request.need.need == MemoryNeed::None
            || matches!(
                request.exposure_policy.mode,
                MemoryExposureMode::CurrentTruthOnly | MemoryExposureMode::MemoryFreeControl
            )
        {
            return ExperienceRecallResponse {
                project_id: request.project_id,
                decision: request.need.clone(),
                fused_rank_traces: Vec::new(),
                applicability: Vec::new(),
                experience_priors: Vec::new(),
                no_useful_memory: true,
                reason: "NO_USEFUL_MEMORY: memory not needed or exposure policy excludes it"
                    .to_owned(),
            };
        }
        if !MemoryKindCompatibilityService::compatible(request.need.need, MemoryKind::CausalCase) {
            return ExperienceRecallResponse {
                project_id: request.project_id,
                decision: request.need.clone(),
                fused_rank_traces: Vec::new(),
                applicability: Vec::new(),
                experience_priors: Vec::new(),
                no_useful_memory: true,
                reason: format!(
                    "NO_USEFUL_MEMORY: causal case corpus is incompatible with {:?}",
                    request.need.need
                ),
            };
        }
        let mut ranked = cases
            .iter()
            .filter(|case| case.project_id == request.project_id)
            .filter(|case| {
                !request
                    .exposure_policy
                    .excluded_handles
                    .contains(&case.case_id)
            })
            .filter(|case| exposure_allows(request.exposure_policy.mode, case.maturity.state))
            .map(|case| (case, fused_rank(&request.task_frame, case)))
            .filter(|(_, trace)| trace.total_score > 0)
            .collect::<Vec<_>>();
        ranked.sort_by_key(|(_, trace)| std::cmp::Reverse(trace.total_score));
        ranked.truncate(request.need.max_candidates.min(3));
        let mut traces = Vec::new();
        let mut applicability = Vec::new();
        let mut briefs = Vec::new();
        for (case, mut trace) in ranked {
            let decision = ApplicabilityService::decide(&request.task_frame, case);
            trace.admitted_for_applicability_review = true;
            if matches!(
                decision.verdict,
                ApplicabilityVerdict::ApplicableAsPrior
                    | ApplicabilityVerdict::PartiallyApplicable
                    | ApplicabilityVerdict::RequireProbe
            ) {
                briefs.push(brief(case, &decision));
            }
            traces.push(trace);
            applicability.push(decision);
        }
        let no_useful_memory = briefs.is_empty();
        ExperienceRecallResponse {
            project_id: request.project_id,
            decision: request.need.clone(),
            fused_rank_traces: traces,
            applicability,
            experience_priors: briefs,
            no_useful_memory,
            reason: if no_useful_memory {
                "NO_USEFUL_MEMORY: candidates were absent, immature, or inapplicable".to_owned()
            } else {
                "experience priors require local revalidation and grant no truth or authority"
                    .to_owned()
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ContextReinstatementService;

impl ContextReinstatementService {
    pub fn bundle(case: &ExperienceCase) -> ContextReinstatementBundle {
        let mut action_outcome_chain = case.intervention_and_outcome.attempted_actions.clone();
        action_outcome_chain.push(
            case.intervention_and_outcome
                .decisive_action_or_non_action
                .clone(),
        );
        action_outcome_chain.push(case.intervention_and_outcome.observed_outcome.clone());
        ContextReinstatementBundle {
            bundle_id: format!("context-reinstatement-{}", WriteId::new_v7()),
            experience_ref: case.case_id.clone(),
            original_goal: case.problem_frame.goal_pattern.clone(),
            original_problem_state: case.problem_frame.trigger_or_symptom.clone(),
            source_time_session_branch_environment: case.source_branch_commit_environment.clone(),
            preceding_and_following_events: case.causal_model.causal_chain.clone(),
            exact_evidence_refs: case.authority.exact_source_refs.clone(),
            action_outcome_chain,
            verifier_refs: case.intervention_and_outcome.verifier_refs.clone(),
            known_context_loss: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NegativeTransferService;

impl NegativeTransferService {
    pub fn record(
        experiment_ref: String,
        memory_handles: Vec<String>,
        task_ref: String,
        harm: NegativeTransferHarm,
        root_cause_stage: String,
        source_has_reconstructable_episode: bool,
    ) -> NegativeTransferRecord {
        let lifecycle_action = if harm.wrong_generalization && source_has_reconstructable_episode {
            NegativeTransferLifecycleAction::Reconstruct
        } else if harm.wrong_generalization {
            NegativeTransferLifecycleAction::SuppressForGuidance
        } else if harm.extra_tool_calls > 0 {
            NegativeTransferLifecycleAction::Demote
        } else {
            NegativeTransferLifecycleAction::KeepHistorical
        };
        let mut handles = memory_handles.clone();
        handles.sort();
        let mut hasher = blake3::Hasher::new();
        for value in [
            experiment_ref.as_str(),
            task_ref.as_str(),
            root_cause_stage.as_str(),
            harm.rejected_proof.as_str(),
        ] {
            hasher.update(value.as_bytes());
            hasher.update(&[0]);
        }
        hasher.update(&harm.extra_tool_calls.to_le_bytes());
        hasher.update(&[u8::from(harm.wrong_generalization)]);
        for handle in handles {
            hasher.update(handle.as_bytes());
            hasher.update(&[0]);
        }
        NegativeTransferRecord {
            record_id: format!("negative-transfer-{}", hasher.finalize().to_hex()),
            experiment_ref,
            memory_handles,
            task_ref,
            harm,
            root_cause_stage,
            lifecycle_action,
            use_outcome: ExperienceUseOutcome::UsedAndHarmed,
            revalidation_required: vec![
                "reconstruct an exact source episode and verifier".to_owned(),
                "pass memory-kind compatibility and applicability review".to_owned(),
                "require a current local probe before reuse".to_owned(),
            ],
            receipt: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CognitiveTransferLabService;

impl CognitiveTransferLabService {
    pub fn evaluate(
        run_id: String,
        cases: &[CognitiveCaseSpec],
        answers: &[CognitiveReaderAnswer],
    ) -> CognitiveTransferLabReport {
        let mut results = Vec::new();
        for spec in cases {
            let Some(answer) = answers.iter().find(|answer| answer.case_id == spec.case_id) else {
                results.push(CognitiveCaseResult {
                    case_id: spec.case_id.clone(),
                    encoding_pass: false,
                    retrieval_pass: false,
                    applicability_pass: false,
                    near_miss_pass: false,
                    verifier_pass: false,
                    forbidden_conclusion_pass: false,
                    recovered_concept_fraction: 0.0,
                    behavioral_delta_verified: false,
                    verifier_result: VerificationResult::Failed,
                    evidence_refs: vec!["reader_answer_missing".to_owned()],
                });
                continue;
            };
            let recovered = spec
                .hidden_essence
                .required_concepts
                .iter()
                .filter(|concept| contains_normalized(&answer.recovered_concepts, concept))
                .count();
            let concept_fraction =
                fraction_usize(recovered, spec.hidden_essence.required_concepts.len());
            let mechanism_pass =
                normalized(&answer.mechanism) == normalized(&spec.hidden_essence.mechanism);
            let retrieval_pass = spec
                .expected_retrieval
                .iter()
                .all(|expected| answer.retrieved_refs.contains(expected));
            let applicability_pass =
                answer.applicability_verdict == spec.expected_applicability_verdict;
            let near_miss_expected = matches!(
                spec.expected_applicability_verdict,
                ApplicabilityVerdict::NearMiss
                    | ApplicabilityVerdict::Contradicted
                    | ApplicabilityVerdict::RequireProbe
            );
            let forbidden_conclusion_pass = spec
                .hidden_essence
                .forbidden_conclusions
                .iter()
                .all(|conclusion| contains_normalized(&answer.forbidden_conclusions, conclusion));
            let verifier_pass =
                normalized(&answer.verifier) == normalized(&spec.hidden_essence.verifier);
            results.push(CognitiveCaseResult {
                case_id: spec.case_id.clone(),
                encoding_pass: (concept_fraction - 1.0).abs() < f64::EPSILON && mechanism_pass,
                retrieval_pass,
                applicability_pass,
                near_miss_pass: !near_miss_expected || applicability_pass,
                verifier_pass,
                forbidden_conclusion_pass,
                recovered_concept_fraction: concept_fraction,
                behavioral_delta_verified: retrieval_pass
                    && applicability_pass
                    && verifier_pass
                    && normalized(&answer.first_probe_or_action)
                        == normalized(&spec.hidden_essence.first_probe_or_action),
                verifier_result: if retrieval_pass && applicability_pass && verifier_pass {
                    VerificationResult::Passed
                } else {
                    VerificationResult::Failed
                },
                evidence_refs: answer.retrieved_refs.clone(),
            });
        }
        let count = results.len();
        let metrics = CognitiveTransferMetrics {
            encoding_gist_fidelity: ratio(&results, |result| result.encoding_pass),
            mechanism_fidelity: ratio(&results, |result| result.encoding_pass),
            required_concept_coverage: if count == 0 {
                0.0
            } else {
                results
                    .iter()
                    .map(|result| result.recovered_concept_fraction)
                    .sum::<f64>()
                    / count as f64
            },
            structural_recall_at_k: ratio(&results, |result| result.retrieval_pass),
            lexical_independence: ratio(&results, |result| {
                result.retrieval_pass
                    && cases
                        .iter()
                        .find(|spec| spec.case_id == result.case_id)
                        .is_some_and(|spec| spec.lexical_overlap_limit < 50)
            }),
            applicability_precision: ratio(&results, |result| result.applicability_pass),
            near_miss_rejection_rate: ratio(&results, |result| result.near_miss_pass),
            negative_transfer_rate: 1.0
                - ratio(&results, |result| {
                    result.applicability_pass && result.forbidden_conclusion_pass
                }),
            current_truth_contamination_rate: 0.0,
            correct_first_boundary: ratio(&results, |result| result.behavioral_delta_verified),
            predicted_observable_accuracy: ratio(&results, |result| result.verifier_pass),
            verifier_selection_accuracy: ratio(&results, |result| result.verifier_pass),
            no_useful_memory_accuracy: ratio(&results, |result| result.applicability_pass),
            cross_host_consistency: ratio(&results, |result| result.behavioral_delta_verified),
        };
        CognitiveTransferLabReport {
            run_id,
            results,
            metrics,
            extra_latency_ms: answers.iter().map(|answer| answer.latency_ms).sum(),
            extra_model_calls: 0,
            false_suppression_count: 0,
            useful_memory_omission_count: 0,
            over_reconstruction_count: 0,
            operator_review_count: 0,
            receipt: None,
        }
    }
}

fn fused_rank(frame: &TaskMeaningFrame, case: &ExperienceCase) -> FusedRankTrace {
    let mut routes = Vec::new();
    score_route(
        &mut routes,
        "task_action_type",
        &case.problem_frame.task_or_action_type,
        &frame.task_or_action_type,
        8,
    );
    score_route(
        &mut routes,
        "failure_signature",
        &case.problem_frame.trigger_or_symptom,
        &frame.problem_or_failure_signature,
        8,
    );
    score_route(
        &mut routes,
        "desired_state_transition",
        &case.problem_frame.desired_state_transition,
        &frame.desired_state_transition,
        10,
    );
    for cue in &case.transfer_boundary.retrieval_cues {
        score_route(&mut routes, "retrieval_cue", cue, &frame.normalized_goal, 6);
    }
    for alias in &case.transfer_boundary.conceptual_aliases {
        score_route(
            &mut routes,
            "conceptual_alias",
            alias,
            &frame.normalized_goal,
            5,
        );
    }
    for invariant in &case.problem_frame.relevant_invariants {
        for current in &frame.invariants {
            score_route(&mut routes, "invariant", invariant, current, 7);
        }
    }
    for source in case.problem_frame.entity_roles.values() {
        for current in frame.entity_roles.values() {
            score_route(&mut routes, "entity_role", source, current, 9);
        }
    }
    let total_score = routes.iter().map(|route| route.score).sum();
    FusedRankTrace {
        task_frame_ref: frame.task_id.clone(),
        candidate_ref: case.case_id.clone(),
        routes,
        total_score,
        admitted_for_applicability_review: false,
    }
}

fn brief(case: &ExperienceCase, decision: &MemoryApplicabilityDecision) -> ExperienceBrief {
    ExperienceBrief {
        memory_kind: MemoryKind::CausalCase,
        essence: format!(
            "{} -> {}",
            case.problem_frame.trigger_or_symptom, case.intervention_and_outcome.observed_outcome
        ),
        underlying_mechanism: case.causal_model.mechanism.clone(),
        why_it_may_apply: decision.matched_conditions.clone(),
        why_it_may_not_apply: case.transfer_boundary.does_not_apply_when.clone(),
        current_mismatches: decision.critical_differences.clone(),
        required_local_check: case
            .transfer_boundary
            .required_local_checks
            .first()
            .cloned()
            .unwrap_or_else(|| "verify current local state".to_owned()),
        recommended_first_probe: case.transfer_boundary.recommended_first_probe.clone(),
        forbidden_direct_inference: case.transfer_boundary.forbidden_direct_inference.clone(),
        maturity_and_authority: format!(
            "{:?}; candidate_only={}; current_truth=false",
            case.maturity.state, case.authority.candidate_only
        ),
        exact_source_handles: case.authority.exact_source_refs.clone(),
        optional_reinstatement_handle: Some(format!("reinstatement:{}", case.case_id)),
    }
}

fn exposure_allows(mode: MemoryExposureMode, maturity: ExperienceMaturityState) -> bool {
    match mode {
        MemoryExposureMode::CurrentTruthOnly | MemoryExposureMode::MemoryFreeControl => false,
        MemoryExposureMode::MatureExperienceOnly => matches!(
            maturity,
            ExperienceMaturityState::TransferValidated
                | ExperienceMaturityState::ProcedureCandidate
                | ExperienceMaturityState::ActiveProcedure
        ),
        MemoryExposureMode::IncludeCaseCandidates => !matches!(
            maturity,
            ExperienceMaturityState::RawEpisode
                | ExperienceMaturityState::Stale
                | ExperienceMaturityState::Suppressed
        ),
        MemoryExposureMode::FullAudit => true,
    }
}

fn score_route(
    routes: &mut Vec<FusedRankRoute>,
    route: &str,
    source: &str,
    target: &str,
    weight: u32,
) {
    let source_tokens = tokens(source);
    let target_tokens = tokens(target);
    if source_tokens.is_empty() || target_tokens.is_empty() {
        return;
    }
    let overlap = source_tokens.intersection(&target_tokens).count();
    if overlap == 0 {
        return;
    }
    let score = weight.saturating_mul(u32::try_from(overlap).unwrap_or(u32::MAX));
    routes.push(FusedRankRoute {
        route: route.to_owned(),
        cue: source.to_owned(),
        score,
    });
}

fn applicability_corpus(frame: &TaskMeaningFrame) -> String {
    let mut values = vec![
        frame.task_or_action_type.clone(),
        frame.problem_or_failure_signature.clone(),
    ];
    values.extend(frame.entity_roles.keys().cloned());
    values.extend(frame.entity_roles.values().cloned());
    values.extend(frame.project_module_boundary.clone());
    values.extend(frame.files_symbols_config.clone());
    values.extend(frame.control_data_state_path.clone());
    values.extend(frame.constraints.clone());
    values.extend(frame.invariants.clone());
    values.extend(frame.current_evidence.clone());
    values.extend(frame.material_unknowns.clone());
    normalized(&values.join(" "))
}

fn condition_matches(condition: &str, corpus: &str) -> bool {
    let condition_tokens = tokens(condition);
    if condition_tokens.is_empty() {
        return false;
    }
    let corpus_tokens = tokens(corpus);
    let overlap = condition_tokens.intersection(&corpus_tokens).count();
    overlap * 4 >= condition_tokens.len() * 3
}

fn contains_normalized(values: &[String], expected: &str) -> bool {
    let expected = normalized(expected);
    values.iter().any(|value| normalized(value) == expected)
}

fn semantic_id(prefix: &str, value: &impl Serialize) -> Result<String, EngineError> {
    let encoded = serde_json::to_vec(value)?;
    Ok(format!("{prefix}-{}", blake3::hash(&encoded).to_hex()))
}

fn experience_case_projection_key(case: &ExperienceCase) -> String {
    if let Some(reasoning_job_ref) = case
        .authority
        .reasoning_job_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        return format!("job/{}/{}", case.project_id, normalized(reasoning_job_ref));
    }
    semantic_projection_hash(
        "case",
        &[
            case.project_id.to_string(),
            normalized(&case.problem_frame.goal_pattern),
            normalized(&case.problem_frame.task_or_action_type),
            normalized(&case.causal_model.mechanism),
            normalized(&case.intervention_and_outcome.observed_outcome),
            normalized(&case.transfer_boundary.recommended_first_probe),
        ],
    )
}

fn experience_pattern_projection_key(pattern: &ExperiencePattern) -> String {
    let mut material = vec![pattern.project_id.to_string()];
    material.extend(pattern.invariant_core.iter().map(|value| normalized(value)));
    material.sort();
    semantic_projection_hash("pattern", &material)
}

fn semantic_projection_hash(prefix: &str, material: &[String]) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in material {
        hasher.update(value.as_bytes());
        hasher.update(&[0]);
    }
    format!("{prefix}/{}", hasher.finalize().to_hex())
}

fn tokens(value: &str) -> HashSet<String> {
    normalized(value)
        .split_whitespace()
        .filter(|token| token.len() > 2)
        .filter(|token| {
            !matches!(
                *token,
                "the" | "and" | "for" | "with" | "from" | "that" | "this" | "into"
            )
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn normalized(value: &str) -> String {
    eliot_types::normalize_unicode_lowercase(value)
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn dedup(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn fraction_usize(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn ratio(results: &[CognitiveCaseResult], predicate: impl Fn(&CognitiveCaseResult) -> bool) -> f64 {
    if results.is_empty() {
        0.0
    } else {
        results.iter().filter(|result| predicate(result)).count() as f64 / results.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_types::{
        ExperienceCausalModel, ExperienceInterventionOutcome, ExperienceProblemFrame,
        ExperienceTransferBoundary, MemoryExposurePolicy, ProjectId, SourceBranchCommitEnvironment,
    };

    fn episode() -> VerifiedEpisodeProjection {
        VerifiedEpisodeProjection {
            project_id: ProjectId::new_v7(),
            source_episode_refs: vec!["episode:one".to_owned()],
            source_task_refs: vec!["task:one".to_owned()],
            source_agent_sessions: Vec::new(),
            source_branch_commit_environment: SourceBranchCommitEnvironment::default(),
            problem_frame: ExperienceProblemFrame {
                goal_pattern: "repair stale runtime identity".to_owned(),
                task_or_action_type: "diagnose runtime".to_owned(),
                trigger_or_symptom: "runtime generation mismatch".to_owned(),
                desired_state_transition: "stale to current runtime".to_owned(),
                relevant_invariants: vec!["generation must match".to_owned()],
                ..ExperienceProblemFrame::default()
            },
            causal_model: ExperienceCausalModel {
                mechanism: "stale auth identity points at an obsolete runtime".to_owned(),
                causal_chain: vec!["old publication".to_owned(), "reconnect".to_owned()],
                expected_observables: vec!["generation changes".to_owned()],
                falsification_cues: vec!["generation already matches".to_owned()],
            },
            intervention_and_outcome: ExperienceInterventionOutcome {
                attempted_actions: vec!["read current publication".to_owned()],
                decisive_action_or_non_action: "reconnect once".to_owned(),
                observed_outcome: "current runtime recovered".to_owned(),
                verifier_refs: vec!["verify:runtime-status".to_owned()],
            },
            transfer_boundary: ExperienceTransferBoundary {
                retrieval_cues: vec!["stale runtime".to_owned()],
                conceptual_aliases: vec!["identity mismatch".to_owned()],
                applies_when: vec!["runtime generation mismatch".to_owned()],
                does_not_apply_when: vec!["runtime generation already matches".to_owned()],
                counterexample_refs: Vec::new(),
                required_local_checks: vec!["runtime generation mismatch".to_owned()],
                recommended_first_probe: "read current runtime generation".to_owned(),
                forbidden_direct_inference: vec!["do not restart blindly".to_owned()],
            },
            exact_evidence_refs: vec!["evidence:publication".to_owned()],
            reasoning_job_ref: None,
        }
    }

    #[allow(clippy::expect_used)]
    fn formed_case() -> ExperienceCase {
        match ExperienceFormationService::reconstruct(episode()).expect("formation") {
            ExperienceFormationResult::Formed { experience_case } => *experience_case,
            ExperienceFormationResult::NothingToLearn { reason } => panic!("{reason}"),
        }
    }

    #[test]
    fn one_episode_remains_candidate_case_without_truth_authority() {
        let case = formed_case();
        assert_eq!(
            case.maturity.state,
            ExperienceMaturityState::ReconstructedCase
        );
        assert!(!case.authority.current_truth);
        assert!(case.authority.candidate_only);
    }

    #[test]
    fn transfer_validation_requires_paraphrase_near_miss_host_and_delta() {
        let current = ExperienceMaturity {
            state: ExperienceMaturityState::PatternCandidate,
            support_count: 2,
            contrast_count: 1,
            cross_host_transfer_count: 0,
            negative_transfer_count: 0,
        };
        assert!(
            MaturityGateService::transition(
                &current,
                ExperienceMaturityState::TransferValidated,
                &TransferValidationEvidence::default()
            )
            .is_err()
        );
    }

    #[test]
    fn near_miss_is_rejected_before_brief_rendering() {
        let case = formed_case();
        let frame = TaskMeaningFrame {
            task_id: "near-miss".to_owned(),
            user_goal: "inspect a healthy runtime".to_owned(),
            normalized_goal: "inspect healthy runtime".to_owned(),
            task_or_action_type: "diagnose runtime".to_owned(),
            desired_state_transition: "none".to_owned(),
            problem_or_failure_signature: "runtime generation already matches".to_owned(),
            current_evidence: vec!["runtime generation already matches".to_owned()],
            ..TaskMeaningFrame::default()
        };
        let decision = ApplicabilityService::decide(&frame, &case);
        assert_eq!(decision.verdict, ApplicabilityVerdict::NearMiss);
        let request = ExperienceRecallRequest {
            project_id: case.project_id,
            task_frame: frame.clone(),
            need: MemoryNeedService::decide(&frame, Some(MemoryNeed::CausalCase)),
            exposure_policy: MemoryExposurePolicy {
                mode: MemoryExposureMode::IncludeCaseCandidates,
                ..MemoryExposurePolicy::default()
            },
        };
        let response = ExperienceRetrievalService::recall(&request, &[case]);
        assert!(response.no_useful_memory);
        assert!(response.experience_priors.is_empty());
    }
}
