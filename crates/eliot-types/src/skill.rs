use crate::{ProjectId, SkillId, TaskId, VerifierPlan, WriteReceiptRef};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkillCardV2 {
    pub skill_id: SkillId,
    pub name: String,
    pub purpose: String,
    pub level: SkillLevel,
    pub lifecycle_state: SkillLifecycleState,
    pub applies_when: Vec<SkillScopeRule>,
    pub does_not_apply_when: Vec<SkillScopeRule>,
    pub required_inputs: Vec<SkillInputRequirement>,
    pub ordered_steps: Vec<SkillStep>,
    pub required_tools_and_capabilities: Vec<SkillToolRequirement>,
    pub expected_outputs: Vec<SkillOutputSpec>,
    pub verification_plan: VerifierPlan,
    pub stop_conditions: Vec<String>,
    pub known_failure_modes: Vec<SkillFailureMode>,
    pub rollback_or_recovery: Option<String>,
    pub source_trace_refs: Vec<String>,
    pub replay_result_refs: Vec<String>,
    pub success_count: u64,
    pub failure_count: u64,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_verified_at: Option<OffsetDateTime>,
    pub version: String,
    pub owner: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLevel {
    Metadata,
    Procedure,
    Executable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLifecycleState {
    #[default]
    Candidate,
    Active,
    Stale,
    Archived,
    Quarantined,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillScopeRule {
    pub rule_id: String,
    pub description: String,
    pub positive_examples: Vec<String>,
    pub negative_examples: Vec<String>,
    pub required_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillInputRequirement {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub source: SkillInputSource,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillInputSource {
    UserPrompt,
    CurrentState,
    CodeCortexReport,
    WorkLease,
    ActionLease,
    VerifierPlan,
    MemoryHandle,
    BlackboardItem,
    MailboxMessage,
    Manual,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillStep {
    pub step_id: String,
    pub order: u32,
    pub instruction: String,
    pub expected_observation: Option<String>,
    pub required_tool_or_capability: Option<String>,
    pub stop_if_fails: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillToolRequirement {
    pub capability: String,
    pub required: bool,
    pub allowed_tools: Vec<String>,
    pub forbidden_tools: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillOutputSpec {
    pub name: String,
    pub description: String,
    pub evidence_required: bool,
    pub verifier_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillFailureMode {
    pub failure_id: String,
    pub description: String,
    pub detection_signal: String,
    pub mitigation: String,
    pub negative_memory_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillLifecycleRecord {
    pub record_id: String,
    pub skill_ref: SkillId,
    pub state: SkillLifecycleState,
    pub uses: u64,
    pub successes: u64,
    pub failures: u64,
    pub context_cost: Option<u64>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_verified: Option<OffsetDateTime>,
    pub where_applies: Vec<SkillScopeRule>,
    pub where_not_apply: Vec<SkillScopeRule>,
    pub promotion_evidence: Vec<String>,
    #[serde(default)]
    pub source_case_refs: Vec<String>,
    #[serde(default)]
    pub source_pattern_refs: Vec<String>,
    #[serde(default)]
    pub mechanism_refs: Vec<String>,
    #[serde(default)]
    pub local_check_refs: Vec<String>,
    #[serde(default)]
    pub transfer_evidence_refs: Vec<String>,
    #[serde(default)]
    pub holdout_evidence_refs: Vec<String>,
    #[serde(default)]
    pub negative_transfer_refs: Vec<String>,
    #[serde(default)]
    pub promotion_outcome: Option<ProcedurePromotionOutcome>,
    #[serde(default)]
    pub rollback_ref: Option<String>,
    pub demotion_reason: Option<String>,
    pub archive_or_restore_receipt: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcedurePromotionOutcome {
    Promoted,
    KeptTransferValidated,
    SplitNarrower,
    Demoted,
    Rejected,
    NotReadyForProcedure,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillNeedEstimate {
    pub estimate_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub candidate_skill: SkillId,
    pub necessity: f64,
    pub utility: f64,
    pub distractor_risk: f64,
    pub verdict: SkillNeedVerdict,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillNeedVerdict {
    Include,
    Exclude,
    RequireMoreContext,
    AuditOnly,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillDistractorFilter {
    pub filter_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub skills_considered: Vec<SkillId>,
    pub skills_included: Vec<SkillId>,
    pub distractors_removed: Vec<SkillId>,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkillExecutionProof {
    pub proof_id: String,
    pub skill_ref: SkillId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub steps_used: Vec<String>,
    pub skipped_steps: Vec<String>,
    pub outputs: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub outcome: SkillExecutionOutcome,
    pub failure_mode_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillExecutionOutcome {
    Succeeded,
    Failed,
    Partial,
    AbortedByStopCondition,
    NotApplicable,
    NegativeTransfer,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillInteractionMatrix {
    pub matrix_id: String,
    pub project_id: ProjectId,
    pub skills: Vec<SkillId>,
    pub conflicts: Vec<SkillConflict>,
    pub required_ordering: Vec<SkillOrderingRule>,
    pub mutual_exclusion: Vec<Vec<SkillId>>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillConflict {
    pub conflict_id: String,
    pub skill_a: SkillId,
    pub skill_b: SkillId,
    pub reason: String,
    pub resolution_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillOrderingRule {
    pub before: SkillId,
    pub after: SkillId,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkillInfluenceReport {
    pub report_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub packet_id: Option<String>,
    pub skills_considered: Vec<SkillId>,
    pub skills_included: Vec<SkillId>,
    pub skills_excluded: Vec<SkillId>,
    pub skills_executed: Vec<SkillId>,
    pub execution_proofs: Vec<String>,
    pub estimated_context_cost: u64,
    pub observed_decision_delta: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillActivationDecision {
    Allow,
    ExcludeNotApplicable,
    ExcludeMissingInputs,
    ExcludeMissingVerifier,
    ExcludeLifecycleState,
    ExcludeConflict,
    ExcludeNegativeMemory,
    AuditOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillActivationRecord {
    pub skill_ref: SkillId,
    pub decision: SkillActivationDecision,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProceduralSkillPacketView {
    pub included_skills: Vec<SkillId>,
    pub excluded_skills: Vec<SkillId>,
    pub activation_decisions: Vec<SkillActivationRecord>,
    pub distractors_removed: Vec<SkillId>,
    pub required_verifiers: Vec<String>,
    pub anti_scope_warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkillCuratorRun {
    pub run_id: String,
    pub project_id: ProjectId,
    pub project: String,
    pub status: SkillCuratorRunStatus,
    pub dry_run: bool,
    pub skills_scanned: Vec<SkillId>,
    pub usage_sources: Vec<String>,
    pub proposals: Vec<SkillCurationProposal>,
    pub rejected_actions: Vec<SkillCurationRejectedAction>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCuratorRunStatus {
    DryRunComplete,
    Complete,
    Partial,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkillCurationProposal {
    pub proposal_id: String,
    pub project_id: ProjectId,
    pub skill_ref: SkillId,
    pub skill_name: String,
    pub action: SkillCurationAction,
    pub reason: SkillCurationReason,
    pub expected_effect: SkillCurationExpectedEffect,
    pub risks: Vec<SkillCurationRisk>,
    pub rollback_plan: SkillCurationRollbackPlan,
    pub replay_requirement: SkillReplayRequirement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<SkillPatchProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge: Option<SkillMergeProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split: Option<SkillSplitProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<SkillArchiveProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<SkillQuarantineProposal>,
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_decision: Option<SkillCurationGateDecision>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCurationAction {
    Keep,
    Patch,
    Merge,
    Split,
    Archive,
    Quarantine,
    Promote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCurationReason {
    RepeatedSuccess,
    MissingWhereNotApply,
    LowUtilityHighCost,
    NegativeTransfer,
    OverbroadSkill,
    DuplicateSkill,
    ManualReview,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillCurationExpectedEffect {
    pub summary: String,
    pub utility_delta: f64,
    pub context_cost_delta_tokens: i64,
    pub risk_delta: f64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillCurationRisk {
    pub severity: String,
    pub description: String,
    pub mitigation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillCurationRollbackPlan {
    pub steps: Vec<String>,
    pub restores_previous_skill: bool,
    pub retained_audit_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillReplayRequirement {
    pub required: bool,
    pub reason: String,
    pub replay_marker: Option<String>,
    pub verifier_refs: Vec<String>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillPatchProposal {
    pub target_skill: SkillId,
    pub patch_summary: String,
    pub candidate_content_ref: String,
    pub narrows_scope: bool,
    pub broadens_scope: bool,
    pub removes_anti_scope: bool,
    pub weakens_verifier: bool,
    pub reviewer_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillMergeProposal {
    pub source_skills: Vec<SkillId>,
    pub merged_skill_name: String,
    pub duplicate_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillSplitProposal {
    pub source_skill: SkillId,
    pub split_names: Vec<String>,
    pub scope_boundaries: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillArchiveProposal {
    pub target_skill: SkillId,
    pub retained_for_audit: bool,
    pub memory_policy_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillQuarantineProposal {
    pub target_skill: SkillId,
    pub negative_transfer_refs: Vec<String>,
    pub memory_policy_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillCurationGateDecision {
    pub proposal_id: String,
    pub decision: SkillCurationDecisionKind,
    pub reasons: Vec<SkillCurationGateReason>,
    pub allowed_action: Option<SkillCurationAction>,
    pub reviewer_required: bool,
    pub replay_required: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCurationDecisionKind {
    Allow,
    AllowReadOnly,
    RequireReview,
    RequireReplay,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCurationGateReason {
    ActionAllowed,
    ReadOnlyReportAllowed,
    AutoPromotionDenied,
    MissingReplayForScopeBroadening,
    RemovingAntiScopeDenied,
    VerifierWeakeningDenied,
    MissingEvidence,
    IncidentLockdown,
    SafeArchiveAllowed,
    SafeQuarantineAllowed,
    SafePatchAllowed,
    DestructiveDeleteDenied,
    UnsupportedAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkillCurationReceipt {
    pub receipt_id: String,
    pub proposal_id: String,
    pub project_id: ProjectId,
    pub skill_ref: SkillId,
    pub action: SkillCurationAction,
    pub applied: bool,
    pub summary: String,
    pub rollback_plan: SkillCurationRollbackPlan,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillCurationRejectedAction {
    pub proposal_id: String,
    pub attempted_action: SkillCurationAction,
    pub reason: SkillCurationGateReason,
    #[serde(with = "time::serde::rfc3339")]
    pub rejected_at: OffsetDateTime,
}
