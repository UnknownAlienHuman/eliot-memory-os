use crate::{EpistemicStatus, ProjectId, TaskId, WriteReceiptRef};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLifecycleState {
    #[default]
    Active,
    Dormant,
    Suppressed,
    Archived,
    Quarantined,
    Forgotten,
    Restored,
    HardDeleted,
    // Legacy states remain readable while new transitions use the normalized
    // lifecycle above.
    Demoted,
    Superseded,
    CompressedInto,
    Poisoned,
    RetainedForAudit,
    ReactivationCandidate,
    Stale,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ForgettingPolicy {
    pub policy_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub reason: ForgettingReason,
    pub operator: ForgettingOperator,
    pub evidence_refs: Vec<String>,
    pub rollback_or_tombstone_ref: Option<String>,
    pub reactivation_condition: Option<ReactivationCondition>,
    #[serde(default)]
    pub expected_current_state: MemoryLifecycleState,
    #[serde(default = "observed_epistemic_status")]
    pub observed_epistemic_status: EpistemicStatus,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub precondition_refs: Vec<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub effective_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub expected_admission_effect: MemoryEcologyDecision,
    #[serde(default = "default_true")]
    pub reversible: bool,
    #[serde(default)]
    pub requires_admin_approval: bool,
    #[serde(default)]
    pub approval_ref: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgettingReason {
    Stale,
    Superseded,
    LowUtility,
    Poisoned,
    Privacy,
    Duplicate,
    WrongScope,
    NegativeTransfer,
    FalseActivation,
    ContextBloat,
    VerifierContradicted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgettingOperator {
    Compress,
    Demote,
    Suppress,
    Supersede,
    Archive,
    Forget,
    Restore,
    Purge,
    // Legacy operators remain readable during schema migration.
    MarkPoisoned,
    RetainAuditOnly,
}

impl ForgettingOperator {
    pub const fn all_l10() -> &'static [Self] {
        &[
            Self::Compress,
            Self::Demote,
            Self::Suppress,
            Self::Supersede,
            Self::Archive,
            Self::Forget,
            Self::Restore,
            Self::Purge,
        ]
    }

    pub const fn all_i0() -> &'static [Self] {
        &[
            Self::Suppress,
            Self::Demote,
            Self::Supersede,
            Self::Archive,
            Self::Compress,
            Self::MarkPoisoned,
            Self::RetainAuditOnly,
        ]
    }
}

pub type RevisionOperator = ForgettingOperator;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryEcologyDecision {
    #[default]
    KeepHot,
    KeepHandleOnly,
    Demote,
    Suppress,
    SplitPattern,
    RequireRevalidation,
    Archive,
    Quarantine,
    ForgetCandidate,
    PurgeRequiresAdmin,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReactivationCondition {
    pub condition_id: String,
    pub description: String,
    pub required_evidence_refs: Vec<String>,
    pub required_current_truth_change: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecisionDeltaRecord {
    pub decision_ref: String,
    pub changed_outcome: bool,
    pub utility_delta: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryVitalityScore {
    pub memory_ref: String,
    pub project_id: ProjectId,
    pub reuse_count: u64,
    pub decision_delta_history: Vec<DecisionDeltaRecord>,
    pub verification_success_count: u64,
    pub verification_failure_count: u64,
    pub stale_hits: u64,
    pub false_activation_count: u64,
    #[serde(default)]
    pub beneficial_use_count: u64,
    #[serde(default)]
    pub prevented_failure_count: u64,
    #[serde(default)]
    pub correct_verifier_selection_count: u64,
    #[serde(default)]
    pub negative_transfer_count: u64,
    #[serde(default)]
    pub contradiction_count: u64,
    #[serde(default)]
    pub context_cost_tokens: u64,
    #[serde(default)]
    pub maintenance_cost_units: u64,
    #[serde(default)]
    pub minority_importance_millis: i64,
    #[serde(default)]
    pub freshness_millis: i64,
    #[serde(default)]
    pub scope_fit_millis: i64,
    #[serde(default)]
    pub utility_millis: i64,
    #[serde(default)]
    pub harm_millis: i64,
    #[serde(default)]
    pub decision: MemoryEcologyDecision,
    // Compatibility projections for older lifecycle reports. Current decisions use the fixed
    // point fields above.
    pub recency_score: f64,
    pub scope_fit_score: f64,
    pub utility_score: f64,
    pub harm_score: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub computed_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryGravity {
    pub memory_ref: String,
    #[serde(default)]
    pub activation_pressure_millis: i64,
    #[serde(default)]
    pub decision: MemoryEcologyDecision,
    // Compatibility projection for I0 reports.
    pub activation_pressure: f64,
    pub why_it_keeps_appearing: Vec<String>,
    pub harm_or_utility: String,
    pub suppression_needed: bool,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub computed_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryStateTransition {
    pub transition_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub from_state: MemoryLifecycleState,
    pub to_state: MemoryLifecycleState,
    pub operator: ForgettingOperator,
    pub reason: ForgettingReason,
    pub policy_ref: String,
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub precondition_refs: Vec<String>,
    #[serde(default)]
    pub expected_admission_effect: MemoryEcologyDecision,
    #[serde(default)]
    pub reactivation_condition: Option<ReactivationCondition>,
    #[serde(default = "default_true")]
    pub reversible: bool,
    #[serde(default)]
    pub approval_ref: Option<String>,
    pub performed_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SupersessionReceipt {
    pub supersession_id: String,
    pub project_id: ProjectId,
    pub old_ref: String,
    pub new_ref: String,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SuppressionReceipt {
    pub suppression_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub reason: ForgettingReason,
    pub scope: Vec<String>,
    pub reactivation_condition: Option<ReactivationCondition>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DemotionReceipt {
    pub demotion_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub old_status: String,
    pub new_status: String,
    pub reason: ForgettingReason,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ArchiveReceipt {
    pub archive_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub reason: ForgettingReason,
    pub retained_for_audit: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MinorityPressureRecord {
    pub minority_record_id: String,
    pub project_id: ProjectId,
    pub minority_claim_ref: String,
    pub majority_claim_ref: Option<String>,
    pub why_minority_matters: String,
    pub discriminative_probe: Option<String>,
    #[serde(default)]
    pub status: MinorityPressureStatus,
    #[serde(default = "default_true")]
    pub pinned: bool,
    #[serde(default)]
    pub release_condition: Option<String>,
    #[serde(default)]
    pub resolved_by_ref: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub suppression_forbidden_until: Option<OffsetDateTime>,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinorityPressureStatus {
    #[default]
    Open,
    Resolved,
    Expired,
    AcceptedRisk,
}

pub type MemoryAuditSuspension = MinorityPressureRecord;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryTrajectoryCorrectness {
    pub trajectory_id: String,
    pub target_ref: String,
    pub transition_refs: Vec<String>,
    pub expected_admission_effect: MemoryEcologyDecision,
    pub observed_admission_effect: MemoryEcologyDecision,
    pub correct: bool,
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityMemoryIndex {
    pub index_id: String,
    pub project_id: ProjectId,
    pub host_id: String,
    pub task_family: String,
    pub capability: String,
    pub attempts: u64,
    pub verified_successes: u64,
    pub verified_failures: u64,
    pub negative_transfers: u64,
    pub median_latency_ms: u64,
    pub evidence_refs: Vec<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_verified_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryInfluenceReport {
    pub report_id: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub packet_id: Option<String>,
    pub included_refs: Vec<String>,
    pub suppressed_refs: Vec<String>,
    pub demoted_refs: Vec<String>,
    pub superseded_refs: Vec<String>,
    pub archived_refs: Vec<String>,
    pub minority_preserved_refs: Vec<String>,
    pub missing_context_regret_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<MemoryInfluenceOutcome>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInfluenceOutcome {
    pub changed_action_or_tool: String,
    pub verifier: String,
    pub avoided_path: String,
    pub downstream_outcome: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLifecycleDecision {
    Allow,
    RequireEvidence,
    RequireSupersedingRecord,
    ProtectMinorityEvidence,
    DenyPurgeInI0,
    DenyTruthMutation,
    DenyUnsafeSuppression,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryLifecyclePacketView {
    pub suppressed_refs: Vec<String>,
    pub demoted_refs: Vec<String>,
    pub superseded_refs: Vec<String>,
    pub archived_refs: Vec<String>,
    pub minority_preserved_refs: Vec<String>,
    pub lifecycle_warnings: Vec<String>,
}

impl Default for MemoryLifecyclePacketView {
    fn default() -> Self {
        Self {
            suppressed_refs: Vec::new(),
            demoted_refs: Vec::new(),
            superseded_refs: Vec::new(),
            archived_refs: Vec::new(),
            minority_preserved_refs: Vec::new(),
            lifecycle_warnings: vec!["memory lifecycle policy active".to_owned()],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryLifecycleStatusReport {
    pub component: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub state: MemoryLifecycleState,
    pub related_receipts: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryLifecycleProposalReport {
    pub component: String,
    pub policy: ForgettingPolicy,
    pub decision: MemoryLifecycleDecision,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryLifecycleApplyReport {
    pub component: String,
    pub decision: MemoryLifecycleDecision,
    pub transition: Option<MemoryStateTransition>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryLifecycleReport {
    pub component: String,
    pub statuses: Vec<MemoryLifecycleStatusReport>,
    pub proposals: Vec<MemoryLifecycleProposalReport>,
    pub influence: Option<MemoryInfluenceReport>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryPressureReport {
    pub duplicate_pressure: String,
    pub stale_activation_pressure: String,
    pub skill_distractor_pressure: String,
    pub open_lifecycle_proposals: usize,
    pub suppressed_recent_regret: usize,
}

const fn default_true() -> bool {
    true
}

const fn observed_epistemic_status() -> EpistemicStatus {
    EpistemicStatus::Observed
}
