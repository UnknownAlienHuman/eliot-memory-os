//! Semantic-experience, applicability, and transfer-lab contracts.

use crate::{AgentSessionId, ProjectId, VerificationResult, WriteReceiptRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    CurrentTruth,
    Claim,
    HistoricalEpisode,
    CausalCase,
    ExperiencePattern,
    Procedure,
    NegativeMemory,
    DecisionRationale,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExperienceMaturityState {
    RawEpisode,
    ReconstructedCase,
    SchemaCandidate,
    PatternCandidate,
    TransferValidated,
    ProcedureCandidate,
    ActiveProcedure,
    Stale,
    Suppressed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceBranchCommitEnvironment {
    pub branch: String,
    pub commit: String,
    pub environment: Vec<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub observed_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceProblemFrame {
    pub goal_pattern: String,
    pub task_or_action_type: String,
    pub trigger_or_symptom: String,
    pub entity_roles: BTreeMap<String, String>,
    pub desired_state_transition: String,
    pub constraints: Vec<String>,
    pub relevant_invariants: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceCausalModel {
    pub mechanism: String,
    pub causal_chain: Vec<String>,
    pub expected_observables: Vec<String>,
    pub falsification_cues: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceInterventionOutcome {
    pub attempted_actions: Vec<String>,
    pub decisive_action_or_non_action: String,
    pub observed_outcome: String,
    pub verifier_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceTransferBoundary {
    pub retrieval_cues: Vec<String>,
    pub conceptual_aliases: Vec<String>,
    pub applies_when: Vec<String>,
    pub does_not_apply_when: Vec<String>,
    pub counterexample_refs: Vec<String>,
    pub required_local_checks: Vec<String>,
    pub recommended_first_probe: String,
    pub forbidden_direct_inference: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceMaturity {
    pub state: ExperienceMaturityState,
    pub support_count: u32,
    pub contrast_count: u32,
    pub cross_host_transfer_count: u32,
    pub negative_transfer_count: u32,
}

impl Default for ExperienceMaturity {
    fn default() -> Self {
        Self {
            state: ExperienceMaturityState::RawEpisode,
            support_count: 0,
            contrast_count: 0,
            cross_host_transfer_count: 0,
            negative_transfer_count: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceAuthority {
    pub current_truth: bool,
    pub candidate_only: bool,
    pub exact_source_refs: Vec<String>,
    pub reasoning_job_ref: Option<String>,
    pub review_refs: Vec<String>,
    pub canonical_receipt: Option<WriteReceiptRef>,
}

impl Default for ExperienceAuthority {
    fn default() -> Self {
        Self {
            current_truth: false,
            candidate_only: true,
            exact_source_refs: Vec::new(),
            reasoning_job_ref: None,
            review_refs: Vec::new(),
            canonical_receipt: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceCase {
    pub case_id: String,
    pub project_id: ProjectId,
    pub source_episode_refs: Vec<String>,
    pub source_task_refs: Vec<String>,
    pub source_agent_sessions: Vec<AgentSessionId>,
    pub source_branch_commit_environment: SourceBranchCommitEnvironment,
    pub problem_frame: ExperienceProblemFrame,
    pub causal_model: ExperienceCausalModel,
    pub intervention_and_outcome: ExperienceInterventionOutcome,
    pub transfer_boundary: ExperienceTransferBoundary,
    pub maturity: ExperienceMaturity,
    pub authority: ExperienceAuthority,
    #[serde(with = "time::serde::rfc3339")]
    pub formed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperiencePattern {
    pub pattern_id: String,
    pub project_id: ProjectId,
    pub member_case_refs: Vec<String>,
    pub invariant_core: Vec<String>,
    pub varying_surface_features: Vec<String>,
    pub success_conditions: Vec<String>,
    pub failure_conditions: Vec<String>,
    pub counterexamples: Vec<String>,
    pub applicability_classifier_features: Vec<String>,
    pub required_local_probe: String,
    pub maturity: ExperienceMaturity,
    pub transfer_evidence: Vec<String>,
    pub authority: ExperienceAuthority,
    #[serde(with = "time::serde::rfc3339")]
    pub formed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedEpisodeProjection {
    pub project_id: ProjectId,
    pub source_episode_refs: Vec<String>,
    pub source_task_refs: Vec<String>,
    pub source_agent_sessions: Vec<AgentSessionId>,
    pub source_branch_commit_environment: SourceBranchCommitEnvironment,
    pub problem_frame: ExperienceProblemFrame,
    pub causal_model: ExperienceCausalModel,
    pub intervention_and_outcome: ExperienceInterventionOutcome,
    pub transfer_boundary: ExperienceTransferBoundary,
    pub exact_evidence_refs: Vec<String>,
    pub reasoning_job_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ExperienceFormationResult {
    Formed {
        experience_case: Box<ExperienceCase>,
    },
    NothingToLearn {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ContrastiveAbstractionResult {
    Formed { pattern: Box<ExperiencePattern> },
    NoLearnablePattern { reason: String },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskMeaningFrame {
    pub task_id: String,
    pub user_goal: String,
    pub normalized_goal: String,
    pub task_or_action_type: String,
    pub desired_state_transition: String,
    pub problem_or_failure_signature: String,
    pub entity_roles: BTreeMap<String, String>,
    pub project_module_boundary: Vec<String>,
    pub files_symbols_config: Vec<String>,
    pub control_data_state_path: Vec<String>,
    pub constraints: Vec<String>,
    pub invariants: Vec<String>,
    pub current_evidence: Vec<String>,
    pub material_unknowns: Vec<String>,
    pub expected_artifact: String,
    pub predicted_observable: String,
    pub verifier_need: String,
    pub abstraction_level_needed: String,
    pub codecortex_report_ref: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CausalBridgeQualityReport {
    pub task_id: String,
    pub report_ref: String,
    pub bridge_hops: Vec<String>,
    pub exact_evidence_per_hop: BTreeMap<String, Vec<String>>,
    pub unknown_hops: Vec<String>,
    pub predicted_observable: String,
    pub verifier: String,
    pub decision_sufficient: bool,
    pub missing_owner_boundary: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryNeed {
    None,
    CurrentFact,
    HistoricalEpisode,
    CausalCase,
    ExperiencePattern,
    Procedure,
    NegativeMemory,
    DecisionRationale,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryNeedDecision {
    pub task_id: String,
    pub need: MemoryNeed,
    pub reason: String,
    pub expected_decision_delta: String,
    pub max_candidates: usize,
    pub max_expansions: usize,
    pub deep_reconstruction_allowed: bool,
    pub stop_if_no_novelty: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicabilityVerdict {
    ApplicableAsPrior,
    PartiallyApplicable,
    AnalogyOnly,
    RequireProbe,
    NearMiss,
    Contradicted,
    InsufficientContext,
    SuppressImmature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryApplicabilityDecision {
    pub decision_id: String,
    pub task_frame_ref: String,
    pub experience_ref: String,
    pub mapped_entity_roles: BTreeMap<String, String>,
    pub matched_conditions: Vec<String>,
    pub critical_differences: Vec<String>,
    pub failed_conditions: Vec<String>,
    pub current_evidence: Vec<String>,
    pub local_probe_required: Option<String>,
    pub predicted_decision_delta: String,
    pub verdict: ApplicabilityVerdict,
    pub receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FusedRankRoute {
    pub route: String,
    pub cue: String,
    pub score: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FusedRankTrace {
    pub task_frame_ref: String,
    pub candidate_ref: String,
    pub routes: Vec<FusedRankRoute>,
    pub total_score: u32,
    pub admitted_for_applicability_review: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextReinstatementBundle {
    pub bundle_id: String,
    pub experience_ref: String,
    pub original_goal: String,
    pub original_problem_state: String,
    pub source_time_session_branch_environment: SourceBranchCommitEnvironment,
    pub preceding_and_following_events: Vec<String>,
    pub exact_evidence_refs: Vec<String>,
    pub action_outcome_chain: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub known_context_loss: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceBrief {
    pub memory_kind: MemoryKind,
    pub essence: String,
    pub underlying_mechanism: String,
    pub why_it_may_apply: Vec<String>,
    pub why_it_may_not_apply: Vec<String>,
    pub current_mismatches: Vec<String>,
    pub required_local_check: String,
    pub recommended_first_probe: String,
    pub forbidden_direct_inference: Vec<String>,
    pub maturity_and_authority: String,
    pub exact_source_handles: Vec<String>,
    pub optional_reinstatement_handle: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceRecallRequest {
    pub project_id: ProjectId,
    pub task_frame: TaskMeaningFrame,
    pub need: MemoryNeedDecision,
    pub exposure_policy: MemoryExposurePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperienceRecallResponse {
    pub project_id: ProjectId,
    pub decision: MemoryNeedDecision,
    pub fused_rank_traces: Vec<FusedRankTrace>,
    pub applicability: Vec<MemoryApplicabilityDecision>,
    pub experience_priors: Vec<ExperienceBrief>,
    pub no_useful_memory: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MemoryCorpusProfile {
    pub counts_by_kind: BTreeMap<String, u64>,
    pub counts_by_epistemic_status: BTreeMap<String, u64>,
    pub counts_by_lifecycle: BTreeMap<String, u64>,
    pub counts_by_maturity: BTreeMap<String, u64>,
    pub verified_episode_count: u64,
    pub reconstructed_case_count: u64,
    pub contrastive_case_group_count: u64,
    pub physical_case_record_count: u64,
    pub physical_pattern_record_count: u64,
    pub superseded_or_duplicate_case_record_count: u64,
    pub superseded_or_duplicate_pattern_record_count: u64,
    pub transfer_validated_count: u64,
    pub active_procedure_count: u64,
    pub weak_claim_fraction: f64,
    pub exact_evidence_coverage: f64,
    pub applies_when_coverage: f64,
    pub does_not_apply_when_coverage: f64,
    pub counterexample_coverage: f64,
    pub verifier_link_coverage: f64,
    pub cross_agent_source_diversity: u64,
    pub mechanism_family_distribution: BTreeMap<String, u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveFailureStage {
    DataSufficiency,
    Encoding,
    Representation,
    Maturity,
    TaskMeaning,
    MemoryKindRouting,
    CandidateGeneration,
    Applicability,
    ContextReinstatement,
    PacketRendering,
    AgentAssimilation,
    EvaluationDesign,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveFailureLocalizationReport {
    pub report_id: String,
    pub experiment_ref: String,
    pub influence_receipt: String,
    pub source_memory_handles: Vec<String>,
    pub source_memory_kinds: Vec<MemoryKind>,
    pub source_evidence_quality: String,
    pub source_scope_and_time: String,
    pub requested_memory_kind: MemoryKind,
    pub task_meaning_available: String,
    pub current_state_contamination: bool,
    pub candidate_generation: String,
    pub admission: String,
    pub applicability: String,
    pub context_reinstatement: String,
    pub packet_rendering: String,
    pub agent_use: String,
    pub verifier_result: String,
    pub primary_failure_stage: CognitiveFailureStage,
    pub contributing_failures: Vec<CognitiveFailureStage>,
    pub exact_evidence_refs: Vec<String>,
    pub owner_boundary: String,
    pub required_correction: String,
    pub receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperienceUseOutcome {
    UsedAndHelped,
    UsedButNoDelta,
    UsedAndHarmed,
    SuppressedCorrectly,
    OmittedButNeeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NegativeTransferLifecycleAction {
    KeepHistorical,
    Demote,
    SuppressForGuidance,
    Reconstruct,
    RequireProbe,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NegativeTransferHarm {
    pub extra_tool_calls: u32,
    pub wrong_generalization: bool,
    pub rejected_proof: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NegativeTransferRecord {
    pub record_id: String,
    pub experiment_ref: String,
    pub memory_handles: Vec<String>,
    pub task_ref: String,
    pub harm: NegativeTransferHarm,
    pub root_cause_stage: String,
    pub lifecycle_action: NegativeTransferLifecycleAction,
    pub use_outcome: ExperienceUseOutcome,
    pub revalidation_required: Vec<String>,
    pub receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryExposureMode {
    CurrentTruthOnly,
    MemoryFreeControl,
    #[default]
    MatureExperienceOnly,
    IncludeCaseCandidates,
    FullAudit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryExposurePolicy {
    pub mode: MemoryExposureMode,
    pub allowed_kinds: Vec<MemoryKind>,
    pub excluded_handles: Vec<String>,
    pub packet_cache_partition: String,
    pub current_state_cross_session_memory_allowed: bool,
}

impl Default for MemoryExposurePolicy {
    fn default() -> Self {
        Self {
            mode: MemoryExposureMode::MatureExperienceOnly,
            allowed_kinds: vec![
                MemoryKind::CausalCase,
                MemoryKind::ExperiencePattern,
                MemoryKind::Procedure,
                MemoryKind::NegativeMemory,
            ],
            excluded_handles: Vec::new(),
            packet_cache_partition: "mature-experience".to_owned(),
            current_state_cross_session_memory_allowed: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningJobKind {
    ExperienceCaseReconstruction,
    ContrastiveExperienceAbstraction,
    TaskMeaningFrameDraft,
    RecallConditionInduction,
    EpisodicContextReconstruction,
    ExperienceApplicabilityReview,
    CounterexampleSearch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CandidateReasoningJobOutput {
    pub job_ref: String,
    pub kind: ReasoningJobKind,
    pub exact_input_handles: Vec<String>,
    pub candidate_only: bool,
    pub model: String,
    pub host: String,
    pub route: String,
    pub cost: String,
    pub output_ref: String,
    pub disagreement: Vec<String>,
    pub unresolved_residue: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveHiddenEssence {
    pub required_concepts: Vec<String>,
    pub mechanism: String,
    pub applicability_conditions: Vec<String>,
    pub non_applicability_conditions: Vec<String>,
    pub first_probe_or_action: String,
    pub predicted_observable: String,
    pub verifier: String,
    pub forbidden_conclusions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveCaseSpec {
    pub case_id: String,
    pub source_case_refs: Vec<String>,
    pub source_agent: String,
    pub target_agent: String,
    pub expected_memory_kind: MemoryKind,
    pub hidden_essence: CognitiveHiddenEssence,
    pub target_task_or_query: String,
    pub lexical_overlap_limit: u32,
    pub distractor_memory_refs: Vec<String>,
    pub expected_retrieval: Vec<String>,
    pub expected_applicability_verdict: ApplicabilityVerdict,
    pub expected_behavioral_delta: String,
    pub deterministic_checks: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveReaderAnswer {
    pub case_id: String,
    pub retrieved_refs: Vec<String>,
    pub memory_kind: MemoryKind,
    pub recovered_concepts: Vec<String>,
    pub mechanism: String,
    pub applicability_conditions: Vec<String>,
    pub non_applicability_conditions: Vec<String>,
    pub first_probe_or_action: String,
    pub predicted_observable: String,
    pub verifier: String,
    pub forbidden_conclusions: Vec<String>,
    pub applicability_verdict: ApplicabilityVerdict,
    pub tool_calls_to_useful_boundary: u32,
    pub tokens_to_useful_boundary: u64,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CognitiveCaseResult {
    pub case_id: String,
    pub encoding_pass: bool,
    pub retrieval_pass: bool,
    pub applicability_pass: bool,
    pub near_miss_pass: bool,
    pub verifier_pass: bool,
    pub forbidden_conclusion_pass: bool,
    pub recovered_concept_fraction: f64,
    pub behavioral_delta_verified: bool,
    pub verifier_result: VerificationResult,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CognitiveTransferMetrics {
    pub encoding_gist_fidelity: f64,
    pub mechanism_fidelity: f64,
    pub required_concept_coverage: f64,
    pub structural_recall_at_k: f64,
    pub lexical_independence: f64,
    pub applicability_precision: f64,
    pub near_miss_rejection_rate: f64,
    pub negative_transfer_rate: f64,
    pub current_truth_contamination_rate: f64,
    pub correct_first_boundary: f64,
    pub predicted_observable_accuracy: f64,
    pub verifier_selection_accuracy: f64,
    pub no_useful_memory_accuracy: f64,
    pub cross_host_consistency: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CognitiveTransferLabReport {
    pub run_id: String,
    pub results: Vec<CognitiveCaseResult>,
    pub metrics: CognitiveTransferMetrics,
    pub extra_latency_ms: u64,
    pub extra_model_calls: u32,
    pub false_suppression_count: u32,
    pub useful_memory_omission_count: u32,
    pub over_reconstruction_count: u32,
    pub operator_review_count: u32,
    pub receipt: Option<WriteReceiptRef>,
}
