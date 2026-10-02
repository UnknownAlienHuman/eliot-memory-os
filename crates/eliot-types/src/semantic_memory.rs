//! Semantic-experience, applicability, and transfer-lab contracts.

use crate::{AgentSessionId, ProjectId, VerificationResult, WriteReceiptRef};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use time::OffsetDateTime;

/// Deserialize a map while refusing a repeated key before insertion.
///
/// Derived map decoding keeps the last entry and silently drops earlier
/// ones, so a lexical duplicate would rewrite a count or role entry without
/// evidence. Every valid single-key encoding decodes exactly as before.
fn deserialize_strict_btree_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    struct StrictMapVisitor<K, V>(PhantomData<fn() -> BTreeMap<K, V>>);

    impl<'de, K, V> de::Visitor<'de> for StrictMapVisitor<K, V>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map with unique keys")
        }

        fn visit_map<A>(self, mut access: A) -> Result<BTreeMap<K, V>, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some(key) = access.next_key::<K>()? {
                if values.contains_key(&key) {
                    return Err(de::Error::custom("duplicate map key"));
                }
                let value = access.next_value::<V>()?;
                values.insert(key, value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(StrictMapVisitor(PhantomData))
}

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
#[serde(deny_unknown_fields)]
pub struct SourceBranchCommitEnvironment {
    pub branch: String,
    pub commit: String,
    pub environment: Vec<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub observed_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceProblemFrame {
    pub goal_pattern: String,
    pub task_or_action_type: String,
    pub trigger_or_symptom: String,
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
    pub entity_roles: BTreeMap<String, String>,
    pub desired_state_transition: String,
    pub constraints: Vec<String>,
    pub relevant_invariants: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceCausalModel {
    pub mechanism: String,
    pub causal_chain: Vec<String>,
    pub expected_observables: Vec<String>,
    pub falsification_cues: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceInterventionOutcome {
    pub attempted_actions: Vec<String>,
    pub decisive_action_or_non_action: String,
    pub observed_outcome: String,
    pub verifier_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExperienceFormationResult {
    Formed {
        experience_case: Box<ExperienceCase>,
    },
    NothingToLearn {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContrastiveAbstractionResult {
    Formed { pattern: Box<ExperiencePattern> },
    NoLearnablePattern { reason: String },
}

/// Current-task meaning frame.
///
/// Partial-candidate disposition, resolved against the actual callers on this
/// branch rather than assumed:
///
/// - A partial candidate is legitimate **and stays Rust-side**.
///   `crates/eliot-engine/src/context.rs::packet_task_meaning_frame` and
///   `crates/eliot-app/src/mcp_stdio/operator.rs::dispatch_operator_snapshot`
///   each build a frame from a real packet and fill the rest through
///   `..TaskMeaningFrame::default()`. `Default` is Rust application
///   construction; it is not a wire fallback, and it is never the producer of
///   a partial *document*.
/// - No production caller decodes a partial wire document. The wire decoders
///   are `crates/eliot-app/src/mcp_stdio/task_handlers.rs::dispatch_task_meaning`
///   (`TaskMeaningToolInput`), the same file's `dispatch_experience_recall`
///   (`ExperienceRecallToolInput`), the `ExperienceRecallRequest.task_frame`
///   member, and the `TaskCognitionView.task_meaning` read-back in
///   `cognition.rs`. Each of them reaches this type through a member set that
///   requires every field, so a document omitting `task_id`, `user_goal` or
///   `current_evidence` refuses at the decoder.
/// - Therefore no struct-wide `#[serde(default)]` is carried. Absence stays
///   explicit unknown (I5.16) rather than reading back as a default identity or
///   empty evidence that could satisfy a current-task boundary.
///
/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// by `deny_unknown_fields`; `entity_roles` refuses a repeated key before map
/// insertion.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskMeaningFrame {
    pub task_id: String,
    pub user_goal: String,
    pub normalized_goal: String,
    pub execution_class: Option<crate::TaskExecutionClass>,
    pub task_or_action_type: String,
    pub desired_state_transition: String,
    pub problem_or_failure_signature: String,
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
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
#[serde(deny_unknown_fields)]
pub struct CausalBridgeQualityReport {
    pub task_id: String,
    pub report_ref: String,
    pub bridge_hops: Vec<String>,
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct MemoryApplicabilityDecision {
    pub decision_id: String,
    pub task_frame_ref: String,
    pub experience_ref: String,
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
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
#[serde(deny_unknown_fields)]
pub struct FusedRankRoute {
    pub route: String,
    pub cue: String,
    pub score: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedRankTrace {
    pub task_frame_ref: String,
    pub candidate_ref: String,
    pub routes: Vec<FusedRankRoute>,
    pub total_score: u32,
    pub admitted_for_applicability_review: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ExperienceRecallRequest {
    pub project_id: ProjectId,
    pub task_frame: TaskMeaningFrame,
    pub need: MemoryNeedDecision,
    pub exposure_policy: MemoryExposurePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceRecallResponse {
    pub project_id: ProjectId,
    pub decision: MemoryNeedDecision,
    pub fused_rank_traces: Vec<FusedRankTrace>,
    pub applicability: Vec<MemoryApplicabilityDecision>,
    pub experience_priors: Vec<ExperienceBrief>,
    pub no_useful_memory: bool,
    pub reason: String,
    /// Content-addressed handle resolving to exactly [`Self::fused_rank_traces`].
    ///
    /// Delivery must propagate the rank traces behind this handle: a response
    /// carrying traces with a missing or mismatched handle fails
    /// [`Self::validate_delivery`].
    pub rank_trace_handle: String,
    /// Delivered priors; always equals `experience_priors.len()`.
    pub visible_count: u32,
    /// Ranked but undelivered candidates; always equals
    /// `fused_rank_traces.len() - visible_count`.
    pub suppressed_count: u32,
}

impl ExperienceRecallResponse {
    /// Derive the deterministic delivery handle for one rank-trace set.
    ///
    /// The handle is content-addressed (`rank-trace:<blake3>`) over the sorted
    /// per-trace identity, feature routes, scores, and admission flags, so it
    /// resolves to exactly the delivered trace set regardless of order.
    pub fn rank_trace_handle_for(traces: &[FusedRankTrace]) -> String {
        let mut material: Vec<String> = traces
            .iter()
            .map(|trace| {
                let mut routes: Vec<String> = trace
                    .routes
                    .iter()
                    .map(|route| format!("{}|{}|{}", route.route, route.cue, route.score))
                    .collect();
                routes.sort();
                format!(
                    "{}|{}|{}|{}|{}",
                    trace.task_frame_ref,
                    trace.candidate_ref,
                    trace.total_score,
                    trace.admitted_for_applicability_review,
                    routes.join(",")
                )
            })
            .collect();
        material.sort();
        let mut hasher = blake3::Hasher::new();
        for entry in &material {
            hasher.update(entry.as_bytes());
            hasher.update(&[0]);
        }
        format!("rank-trace:{}", hasher.finalize().to_hex())
    }

    /// Fail-closed delivery check for the bound rank-trace handle and counts.
    ///
    /// Rejects a delivery whose handle does not resolve to the carried traces,
    /// whose visible count disagrees with the delivered priors, or whose
    /// suppressed count disagrees with the ranked-but-undelivered remainder.
    pub fn validate_delivery(&self) -> Result<(), String> {
        let expected = Self::rank_trace_handle_for(&self.fused_rank_traces);
        if self.rank_trace_handle != expected {
            return Err(
                "rank_trace_handle does not resolve to the delivered fused_rank_traces".to_owned(),
            );
        }
        let visible = u32::try_from(self.experience_priors.len())
            .map_err(|_| "visible_count overflows u32".to_owned())?;
        if self.visible_count != visible {
            return Err("visible_count does not match the delivered experience_priors".to_owned());
        }
        let total = u32::try_from(self.fused_rank_traces.len())
            .map_err(|_| "suppressed_count overflows u32".to_owned())?;
        let suppressed = total
            .checked_sub(visible)
            .ok_or_else(|| "fused_rank_traces is smaller than the delivered priors".to_owned())?;
        if self.suppressed_count != suppressed {
            return Err(
                "suppressed_count does not match the ranked-but-undelivered remainder".to_owned(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCorpusProfile {
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
    pub counts_by_kind: BTreeMap<String, u64>,
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
    pub counts_by_epistemic_status: BTreeMap<String, u64>,
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
    pub counts_by_lifecycle: BTreeMap<String, u64>,
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
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
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct NegativeTransferHarm {
    pub extra_tool_calls: u32,
    pub wrong_generalization: bool,
    pub rejected_proof: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

#[cfg(test)]
mod decoder_boundary {
    use super::*;

    // Every fixture below is raw text, never a `serde_json::Value`: a `Value`
    // fixture collapses a lexical duplicate member while parsing, so it cannot
    // observe the facts the duplicate-key refusals exist to pin. Duplicate-key
    // documents are stored as strings for the same reason.
    const PROJECT: &str = "11111111-1111-4111-8111-111111111111";
    const SESSION: &str = "22222222-2222-4222-8222-222222222222";
    const RECEIPT: &str = "33333333-3333-4333-8333-333333333333";
    const WRITE: &str = "44444444-4444-4444-8444-444444444444";
    const FORMED_AT: &str = "2026-01-02T03:04:05Z";

    /// One producer's exact wire form for an `ExperienceCase`: the nested problem,
    /// causal, intervention and transfer owners, a `RAW_EPISODE` maturity in
    /// SCREAMING_SNAKE_CASE, an explicit zero negative-transfer count, and a
    /// candidate-only authority carrying a canonical receipt reference.
    const CASE: &str = r#"{
  "case_id": "case-fixture-001",
  "project_id": "11111111-1111-4111-8111-111111111111",
  "source_episode_refs": ["episode:fixture-1"],
  "source_task_refs": ["task-fixture-001"],
  "source_agent_sessions": ["22222222-2222-4222-8222-222222222222"],
  "source_branch_commit_environment": {
    "branch": "refs/heads/fixture",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "environment": ["linux-x64"],
    "observed_at": "2026-01-02T03:04:05Z"
  },
  "problem_frame": {
    "goal_pattern": "make the failing owner check pass",
    "task_or_action_type": "governed_task",
    "trigger_or_symptom": "the owner check exits non-zero",
    "entity_roles": {"subject": "owner-suite", "object": "owner-check"},
    "desired_state_transition": "the owner check exits zero",
    "constraints": ["no new dependency"],
    "relevant_invariants": ["invariant:fixture-1"]
  },
  "causal_model": {
    "mechanism": "the fixture was never registered",
    "causal_chain": ["the runner enumerates registered fixtures"],
    "expected_observables": ["one passing owner fixture"],
    "falsification_cues": ["the failure survives registration"]
  },
  "intervention_and_outcome": {
    "attempted_actions": ["register the fixture"],
    "decisive_action_or_non_action": "register the fixture",
    "observed_outcome": "the owner fixture passes",
    "verifier_refs": ["verifier:ci-fixture"]
  },
  "transfer_boundary": {
    "retrieval_cues": ["fixture registration"],
    "conceptual_aliases": ["test wiring"],
    "applies_when": ["the runner discovers tests dynamically"],
    "does_not_apply_when": ["the suite is generated at build time"],
    "counterexample_refs": ["case:counter-1"],
    "required_local_checks": ["run the owner package test"],
    "recommended_first_probe": "run the owner test once",
    "forbidden_direct_inference": ["the recorded effect was executed"]
  },
  "maturity": {
    "state": "TRANSFER_VALIDATED",
    "support_count": 3,
    "contrast_count": 1,
    "cross_host_transfer_count": 1,
    "negative_transfer_count": 0
  },
  "authority": {
    "current_truth": false,
    "candidate_only": true,
    "exact_source_refs": ["episode:fixture-1"],
    "reasoning_job_ref": "job:fixture-1",
    "review_refs": ["review:fixture-1"],
    "canonical_receipt": {
      "receipt_id": "33333333-3333-4333-8333-333333333333",
      "write_id": "44444444-4444-4444-8444-444444444444"
    }
  },
  "formed_at": "2026-01-02T03:04:05Z"
}"#;

    /// One producer's exact wire form for an `ExperiencePattern`, with a
    /// `PATTERN_CANDIDATE` maturity and explicit `null` optional members, so the
    /// distinction between absent-unknown and default-empty stays visible.
    const PATTERN: &str = r#"{
  "pattern_id": "pattern-fixture-001",
  "project_id": "11111111-1111-4111-8111-111111111111",
  "member_case_refs": ["case:fixture-001"],
  "invariant_core": ["the owner package must run"],
  "varying_surface_features": ["fixture identifiers"],
  "success_conditions": ["the owner package test passes"],
  "failure_conditions": ["the owner package test is never run"],
  "counterexamples": ["case:counter-1"],
  "applicability_classifier_features": ["package-local test wiring"],
  "required_local_probe": "run the owner package test",
  "transfer_evidence": ["transfer:fixture-1"],
  "maturity": {
    "state": "PATTERN_CANDIDATE",
    "support_count": 2,
    "contrast_count": 1,
    "cross_host_transfer_count": 0,
    "negative_transfer_count": 0
  },
  "authority": {
    "current_truth": false,
    "candidate_only": true,
    "exact_source_refs": ["case:fixture-001"],
    "reasoning_job_ref": null,
    "review_refs": [],
    "canonical_receipt": null
  },
  "formed_at": "2026-01-02T03:04:05Z"
}"#;

    /// One producer's exact wire form for a complete `TaskMeaningFrame`, as
    /// `dispatch_task_meaning` and `dispatch_experience_recall` receive it.
    const FRAME: &str = r#"{
  "task_id": "task-fixture-001",
  "user_goal": "close the semantic-memory decoder",
  "normalized_goal": "close the semantic-memory decoder",
  "execution_class": {
    "domain": "code",
    "action": "read_only",
    "artifact": "code",
    "subsystem_refs": ["crate:eliot-types"],
    "source": "explicit_contract"
  },
  "task_or_action_type": "governed_task",
  "desired_state_transition": "adversarial bytes refuse before typed output",
  "problem_or_failure_signature": "a duplicate member survives a value round trip",
  "entity_roles": {"subject": "eliot-types", "object": "semantic_memory"},
  "project_module_boundary": ["crate:eliot-types"],
  "files_symbols_config": ["crates/eliot-types/src/semantic_memory.rs"],
  "control_data_state_path": ["crate:eliot-types -> semantic_memory"],
  "constraints": ["one writer per file"],
  "invariants": ["accepted wire bytes stay accepted"],
  "current_evidence": ["commit:fixture"],
  "material_unknowns": [],
  "expected_artifact": "the closed decoder",
  "predicted_observable": "duplicate members are refused",
  "verifier_need": "package-local decoder proof",
  "abstraction_level_needed": "auto",
  "codecortex_report_ref": "codecortex:fixture"
}"#;

    /// `MemoryNeedDecision`, the recall request's owned `need` member.
    const NEED: &str = r#"{
  "task_id": "task-fixture-001",
  "need": "causal_case",
  "reason": "the current task has an unexplained failure",
  "expected_decision_delta": "name the mechanism",
  "max_candidates": 4,
  "max_expansions": 1,
  "deep_reconstruction_allowed": false,
  "stop_if_no_novelty": true
}"#;

    /// `MemoryExposurePolicy`, the recall request's owned policy member.
    const EXPOSURE: &str = r#"{
  "mode": "mature_experience_only",
  "allowed_kinds": ["causal_case", "experience_pattern"],
  "excluded_handles": [],
  "packet_cache_partition": "mature-experience",
  "current_state_cross_session_memory_allowed": false
}"#;

    /// Replace the first occurrence of `member` with a duplicate of itself, so
    /// the refused document is byte-for-byte identical to the accepted one
    /// except for the repeated member. The lexical fact cannot be built from a
    /// `serde_json::Value` without losing it.
    fn with_duplicate_member(document: &str, member: &str, duplicate: &str) -> String {
        let once = document.replacen(member, &format!("{member}\n  {duplicate}"), 1);
        if once == document {
            panic!("fixture member {member} must appear exactly once to duplicate it");
        }
        once
    }

    /// Remove one whole member line from a canonical document, so the result is
    /// still well formed JSON and the only difference from the accepted document
    /// is the absent member.
    fn without_member(document: &str, member: &str) -> String {
        let reduced = document.replacen(&format!("{member}\n"), "", 1);
        if reduced == document {
            panic!("fixture member {member} must appear exactly once to omit it");
        }
        reduced
    }

    /// The recall request as `dispatch_experience_recall` builds it: the current
    /// task frame is an owned member, so a partial frame cannot satisfy the
    /// current-task boundary.
    fn recall_request(task_frame: &str) -> String {
        recall_request_with(task_frame, NEED, EXPOSURE)
    }

    /// The same recall request with one substituted owned member, so the nested
    /// need, policy and frame owners are all closed by the same decoder.
    fn recall_request_with(task_frame: &str, need: &str, exposure_policy: &str) -> String {
        format!(
            "{{\"project_id\":\"{PROJECT}\",\"task_frame\":{task_frame},\"need\":{need},\"exposure_policy\":{exposure_policy}}}"
        )
    }

    // WORK_UNIT_CASE: 938/2 -- current accepted bytes, digests and enum spellings unchanged.
    //
    // Positive case. Every named type in this module decodes from its producer's
    // raw bytes, the `outcome` tag keeps its two snake_case spellings,
    // `ExperienceMaturityState` keeps its SCREAMING_SNAKE_CASE spelling against
    // every other enum's snake_case, and an explicit zero stays a zero.
    #[test]
    fn canonical_semantic_memory_documents_keep_their_current_wire_shape() {
        let case = match serde_json::from_str::<ExperienceCase>(CASE) {
            Ok(case) => case,
            Err(error) => panic!("the canonical case must decode: {error}"),
        };
        assert_eq!(case.case_id, "case-fixture-001");
        assert_eq!(case.project_id.to_string(), PROJECT);
        assert_eq!(case.source_agent_sessions[0].to_string(), SESSION);
        assert!(
            case.source_branch_commit_environment.observed_at.is_some(),
            "an explicit observed_at is retained"
        );
        assert_eq!(case.problem_frame.entity_roles["subject"], "owner-suite");
        assert_eq!(case.maturity.state, ExperienceMaturityState::TransferValidated);
        assert_eq!(case.maturity.negative_transfer_count, 0);
        assert!(!case.authority.current_truth, "a candidate is not current truth");
        assert!(case.authority.candidate_only);
        assert_eq!(
            case.authority
                .canonical_receipt
                .as_ref()
                .map(|receipt| (receipt.receipt_id.to_string(), receipt.write_id.to_string())),
            Some((RECEIPT.to_owned(), WRITE.to_owned()))
        );
        match serde_json::to_string(&case) {
            Ok(encoded) => assert!(
                encoded.contains(&format!(r#""formed_at":"{FORMED_AT}""#)),
                "the RFC3339 wire form of formed_at is unchanged"
            ),
            Err(error) => panic!("re-encoding the accepted case must succeed: {error}"),
        }

        let pattern = match serde_json::from_str::<ExperiencePattern>(PATTERN) {
            Ok(pattern) => pattern,
            Err(error) => panic!("the canonical pattern must decode: {error}"),
        };
        assert_eq!(pattern.pattern_id, "pattern-fixture-001");
        assert_eq!(pattern.maturity.state, ExperienceMaturityState::PatternCandidate);
        assert!(pattern.authority.reasoning_job_ref.is_none());
        assert!(pattern.authority.canonical_receipt.is_none());

        let formed = match serde_json::from_str::<ExperienceFormationResult>(&format!(
            "{{\"outcome\":\"formed\",\"experience_case\":{CASE}}}"
        )) {
            Ok(formed) => formed,
            Err(error) => panic!("the formed outcome must decode: {error}"),
        };
        let ExperienceFormationResult::Formed { experience_case } = &formed else {
            panic!("the formed outcome must decode into the formed variant");
        };
        assert_eq!(experience_case.case_id, "case-fixture-001");

        let learned_nothing = match serde_json::from_str::<ExperienceFormationResult>(
            r#"{"outcome":"nothing_to_learn","reason":"no contrasting pair"}"#,
        ) {
            Ok(result) => result,
            Err(error) => panic!("the nothing_to_learn outcome must decode: {error}"),
        };
        let ExperienceFormationResult::NothingToLearn { reason } = &learned_nothing else {
            panic!("nothing_to_learn must decode into its own variant");
        };
        assert_eq!(reason, "no contrasting pair");

        let abstracted =
            match serde_json::from_str::<ContrastiveAbstractionResult>(&format!(
                "{{\"outcome\":\"formed\",\"pattern\":{PATTERN}}}"
            )) {
                Ok(result) => result,
                Err(error) => panic!("the formed abstraction must decode: {error}"),
            };
        let ContrastiveAbstractionResult::Formed { pattern } = &abstracted else {
            panic!("the formed abstraction must decode into the formed variant");
        };
        assert_eq!(pattern.pattern_id, "pattern-fixture-001");

        let no_pattern = match serde_json::from_str::<ContrastiveAbstractionResult>(
            r#"{"outcome":"no_learnable_pattern","reason":"one case is not a contrast"}"#,
        ) {
            Ok(result) => result,
            Err(error) => panic!("no_learnable_pattern must decode: {error}"),
        };
        assert!(matches!(
            no_pattern,
            ContrastiveAbstractionResult::NoLearnablePattern { .. }
        ));

        let frame = match serde_json::from_str::<TaskMeaningFrame>(FRAME) {
            Ok(frame) => frame,
            Err(error) => panic!("the canonical task frame must decode: {error}"),
        };
        assert_eq!(frame.task_id, "task-fixture-001");
        assert_eq!(frame.entity_roles["object"], "semantic_memory");
        assert_eq!(
            frame.execution_class.as_ref().map(|class| class.domain),
            Some(crate::TaskExecutionDomain::Code)
        );
        assert_eq!(frame.codecortex_report_ref.as_deref(), Some("codecortex:fixture"));

        let request =
            match serde_json::from_str::<ExperienceRecallRequest>(&recall_request(FRAME)) {
                Ok(request) => request,
                Err(error) => panic!("the canonical recall request must decode: {error}"),
            };
        assert_eq!(request.task_frame.task_id, "task-fixture-001");
        assert_eq!(request.need.need, MemoryNeed::CausalCase);
        assert_eq!(request.exposure_policy.mode, MemoryExposureMode::MatureExperienceOnly);
        assert_eq!(
            request.exposure_policy.allowed_kinds,
            [MemoryKind::CausalCase, MemoryKind::ExperiencePattern]
        );

        // The wire spellings are pinned in both directions: the lowercase
        // maturity spelling must keep refusing, so a rename cannot silently
        // invalidate stored records.
        assert!(
            serde_json::from_str::<ExperienceCase>(&CASE.replace(
                "\"TRANSFER_VALIDATED\"",
                "\"transfer_validated\""
            ))
            .is_err(),
            "the SCREAMING_SNAKE_CASE maturity spelling is the accepted one"
        );
        assert!(
            serde_json::from_str::<ExperienceCase>(&CASE.replace(
                "\"TRANSFER_VALIDATED\"",
                "\"RawEpisode\""
            ))
            .is_err(),
            "a Rust variant spelling is not a wire spelling"
        );
        assert!(
            serde_json::from_str::<ExperienceRecallRequest>(&recall_request_with(
                FRAME,
                &NEED.replace(r#""causal_case""#, r#""CausalCase""#),
                EXPOSURE
            ))
            .is_err(),
            "the snake_case need spelling is the accepted one"
        );
        assert!(
            serde_json::from_str::<ExperienceRecallRequest>(&recall_request_with(
                FRAME,
                NEED,
                &EXPOSURE.replace(
                    r#""experience_pattern""#,
                    r#""ExperiencePattern""#
                )
            ))
            .is_err(),
            "the snake_case memory-kind spelling is the accepted one"
        );
    }

    // WORK_UNIT_CASE: 938/3 -- an unknown outer protected member refuses.
    //
    // Refusal case. An unknown protected member on an ordinary envelope, and on
    // the recall request that owns the task frame, must not ride along as
    // current semantic truth.
    #[test]
    fn unknown_outer_protected_members_are_refused() {
        assert!(
            serde_json::from_str::<ExperienceCase>(&CASE.replace(
                r#""case_id": "case-fixture-001","#,
                r#""case_id": "case-fixture-001", "applied": true,"#
            ))
            .is_err(),
            "an added applied-effect member must not decode as an experience case"
        );
        assert!(
            serde_json::from_str::<ExperiencePattern>(&PATTERN.replace(
                r#""pattern_id": "pattern-fixture-001","#,
                r#""pattern_id": "pattern-fixture-001", "erased": true,"#
            ))
            .is_err(),
            "an added erasure member must not decode as an experience pattern"
        );
        assert!(
            serde_json::from_str::<TaskMeaningFrame>(&FRAME.replace(
                r#""task_id": "task-fixture-001","#,
                r#""task_id": "task-fixture-001", "restored": true,"#
            ))
            .is_err(),
            "an added restore member must not decode as a task meaning frame"
        );
        assert!(
            serde_json::from_str::<ExperienceRecallRequest>(&recall_request(
                &FRAME.replace(
                    r#""task_id": "task-fixture-001","#,
                    r#""task_id": "task-fixture-001", "authorized": true,"#
                )
            ))
            .is_err(),
            "an added authorization member must not decode inside the recall request"
        );
    }

    // WORK_UNIT_CASE: 938/4 -- an unknown nested protected member refuses.
    //
    // Refusal case. Owned nested structures are closed too: an unknown member on
    // the problem frame, the environment owner, the authority, the exposure
    // policy and the nested execution class must refuse before typed output.
    #[test]
    fn unknown_nested_protected_members_are_refused() {
        assert!(
            serde_json::from_str::<ExperienceCase>(&CASE.replace(
                r#""entity_roles": {"subject": "owner-suite", "object": "owner-check"},"#,
                r#""entity_roles": {"subject": "owner-suite", "object": "owner-check", "operator": "owner"},"#
            ))
            .is_err(),
            "an unknown nested role member must not decode"
        );
        assert!(
            serde_json::from_str::<ExperienceCase>(&CASE.replace(
                r#""commit": "0123456789abcdef0123456789abcdef01234567","#,
                r#""commit": "0123456789abcdef0123456789abcdef01234567", "signed_by": "owner","#
            ))
            .is_err(),
            "an unknown member of the source environment owner must not decode"
        );
        assert!(
            serde_json::from_str::<ExperienceCase>(&CASE.replace(
                r#""candidate_only": true,"#,
                r#""candidate_only": true, "automatic_apply_allowed": true,"#
            ))
            .is_err(),
            "a decoded authority is not self-issued apply permission"
        );
        assert!(
            serde_json::from_str::<ExperienceCase>(&CASE.replace(
                r#""write_id": "44444444-4444-4444-8444-444444444444""#,
                r#""write_id": "44444444-4444-4444-8444-444444444444", "verified": true"#
            ))
            .is_err(),
            "an unknown member of the nested receipt reference must not decode"
        );
        assert!(
            serde_json::from_str::<ExperienceRecallRequest>(&recall_request_with(
                FRAME,
                NEED,
                &EXPOSURE.replace(
                    r#""mode": "mature_experience_only","#,
                    r#""mode": "mature_experience_only", "escalate": true,"#
                )
            ))
            .is_err(),
            "an unknown member of the nested exposure policy must not decode"
        );
        assert!(
            serde_json::from_str::<TaskMeaningFrame>(&FRAME.replace(
                r#""source": "explicit_contract""#,
                r#""source": "explicit_contract", "inferred": true"#
            ))
            .is_err(),
            "an unknown member of the nested execution class must not decode"
        );
    }

    // WORK_UNIT_CASE: 938/5 -- duplicate identity, discriminator and map members refuse.
    //
    // Refusal case. Each refused document is the accepted document plus one
    // repeated member, so the refusal is proven to come from the lexical
    // duplicate and not from a shape difference.
    #[test]
    fn duplicate_identity_discriminator_and_map_members_are_refused() {
        let duplicate_identity = with_duplicate_member(
            CASE,
            r#""case_id": "case-fixture-001","#,
            r#""case_id": "case-fixture-002","#,
        );
        assert!(
            serde_json::from_str::<ExperienceCase>(&duplicate_identity).is_err(),
            "a repeated case identity must refuse instead of keeping one value"
        );

        let duplicate_maturity = with_duplicate_member(
            CASE,
            r#""state": "TRANSFER_VALIDATED","#,
            r#""state": "RAW_EPISODE","#,
        );
        assert!(
            serde_json::from_str::<ExperienceCase>(&duplicate_maturity).is_err(),
            "a repeated maturity state must refuse instead of keeping one value"
        );

        let duplicate_map_key = with_duplicate_member(
            FRAME,
            r#""subject": "eliot-types","#,
            r#""subject": "operator","#,
        );
        assert!(
            serde_json::from_str::<TaskMeaningFrame>(&duplicate_map_key).is_err(),
            "a repeated entity-role key must refuse before map insertion"
        );
        assert!(
            serde_json::from_str::<ExperienceRecallRequest>(&recall_request(&duplicate_map_key))
                .is_err(),
            "a repeated entity-role key must refuse inside the recall request too"
        );

        // The raw-byte fixture is load bearing: the same bytes normalize through
        // `Value` without any refusal, which is why the boundary cannot be
        // proven from a normalized object.
        assert!(
            serde_json::from_str::<serde_json::Value>(&duplicate_map_key).is_ok(),
            "a value parse collapses the duplicate, so only raw bytes can pin it"
        );

        assert!(
            serde_json::from_str::<ExperienceFormationResult>(
                r#"{"outcome":"formed","outcome":"nothing_to_learn","reason":"retagged"}"#
            )
            .is_err(),
            "a repeated outcome discriminator must refuse"
        );
        assert!(
            serde_json::from_str::<ContrastiveAbstractionResult>(
                r#"{"outcome":"formed","outcome":"no_learnable_pattern","reason":"retagged"}"#
            )
            .is_err(),
            "a repeated outcome discriminator must refuse for both result enums"
        );
    }

    // WORK_UNIT_CASE: 938/6 -- unknown variants and mismatched tag payloads refuse.
    //
    // Refusal case. The `outcome` tag is not renamed and no variant is added: an
    // unknown tag, a payload that belongs to the other variant, and a payload
    // that is missing entirely all refuse.
    #[test]
    fn unknown_variants_and_mismatched_outcome_payloads_are_refused() {
        assert!(
            serde_json::from_str::<ExperienceFormationResult>(
                r#"{"outcome":"maybe_formed","reason":"proposed"}"#
            )
            .is_err(),
            "an unknown outcome tag must refuse"
        );
        assert!(
            serde_json::from_str::<ExperienceFormationResult>(&format!(
                r#"{{"outcome":"nothing_to_learn","experience_case":{CASE}}}"#
            ))
            .is_err(),
            "a formed payload under the nothing_to_learn tag must refuse"
        );
        assert!(
            serde_json::from_str::<ExperienceFormationResult>(
                r#"{"outcome":"formed","reason":"no case attached"}"#
            )
            .is_err(),
            "a nothing_to_learn payload under the formed tag must refuse"
        );
        assert!(
            serde_json::from_str::<ExperienceFormationResult>(r#"{"outcome":"formed"}"#).is_err(),
            "a formed outcome without its owned case must refuse"
        );
        assert!(
            serde_json::from_str::<ContrastiveAbstractionResult>(
                r#"{"outcome":"no_learnable_pattern","pattern":{"pattern_id":"pattern-fixture-001"}}"#
            )
            .is_err(),
            "a formed payload under the no_learnable_pattern tag must refuse"
        );
        assert!(
            serde_json::from_str::<ContrastiveAbstractionResult>(
                r#"{"outcome":"no_learnable_pattern"}"#
            )
            .is_err(),
            "an outcome without its reason must refuse"
        );
        assert!(
            serde_json::from_str::<ExperienceFormationResult>(
                r#"{"experience_case":{"case_id":"case-fixture-001"}}"#
            )
            .is_err(),
            "a missing outcome tag must not fall back to a variant"
        );
    }

    // WORK_UNIT_CASE: 938/7 -- a partial frame cannot satisfy a current-task boundary.
    //
    // Refusal case. `Default` is Rust application construction: a partial
    // candidate built in Rust is legitimate, and serializing it produces a
    // complete document. A document that *omits* a member refuses, so
    // default-empty identity or empty evidence never reaches a current-task
    // boundary through the wire.
    #[test]
    fn a_partial_task_meaning_frame_cannot_become_a_current_task_frame() {
        let candidate = TaskMeaningFrame {
            task_id: "task-fixture-001".to_owned(),
            user_goal: "close the semantic-memory decoder".to_owned(),
            ..TaskMeaningFrame::default()
        };
        assert_eq!(
            candidate.expected_artifact, "",
            "the Rust-side partial candidate leaves unknown members empty"
        );
        let complete = match serde_json::to_string(&candidate) {
            Ok(encoded) => encoded,
            Err(error) => panic!("a Rust-side partial candidate must serialize: {error}"),
        };
        assert!(complete.contains(r#""expected_artifact":"""#));
        match serde_json::from_str::<TaskMeaningFrame>(&complete) {
            Ok(round_tripped) => assert_eq!(round_tripped, candidate),
            Err(error) => panic!("a serialized complete frame must decode: {error}"),
        }

        // Each omission below removes one whole member line, so the result is
        // still well formed JSON and the only difference from the accepted
        // document is the absent member.
        for (member, missing) in [
            (r#""task_id": "task-fixture-001","#, "task identity"),
            (r#""user_goal": "close the semantic-memory decoder","#, "user goal"),
            (
                r#""current_evidence": ["commit:fixture"],"#,
                "current evidence",
            ),
        ] {
            let omitted = without_member(FRAME, member);
            assert!(
                serde_json::from_str::<TaskMeaningFrame>(&omitted).is_err(),
                "a frame missing its {missing} must refuse instead of defaulting"
            );
            assert!(
                serde_json::from_str::<ExperienceRecallRequest>(&recall_request(&omitted))
                    .is_err(),
                "a recall request whose current task frame is missing its {missing} must refuse"
            );
        }
    }
}
