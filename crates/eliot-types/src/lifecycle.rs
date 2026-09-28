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

/// Decoder: derived and closed. The kept `#[serde(default)]` fields are optional
/// effectiveness/approval data that decode as absent; every identity, reason,
/// operator, scope and admission-effect field stays required.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgettingPolicy {
    pub policy_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub reason: ForgettingReason,
    pub operator: ForgettingOperator,
    pub evidence_refs: Vec<String>,
    pub rollback_or_tombstone_ref: Option<String>,
    pub reactivation_condition: Option<ReactivationCondition>,
    pub expected_current_state: MemoryLifecycleState,
    pub observed_epistemic_status: EpistemicStatus,
    pub scope: Vec<String>,
    pub precondition_refs: Vec<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub effective_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub expected_admission_effect: MemoryEcologyDecision,
    pub reversible: bool,
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
#[serde(deny_unknown_fields)]
pub struct ReactivationCondition {
    pub condition_id: String,
    pub description: String,
    pub required_evidence_refs: Vec<String>,
    pub required_current_truth_change: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionDeltaRecord {
    pub decision_ref: String,
    pub changed_outcome: bool,
    pub utility_delta: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

/// Decoder: derived and closed. `decision` stays required on the wire: a missing
/// field must not decode into `KeepHot` admission. The zero `#[serde(default)]`
/// counters keep historical records readable and can only understate observed
/// benefit, never fabricate it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Decoder: derived and closed. `decision` stays required on the wire: a missing
/// field must not decode into `KeepHot` admission. The zero
/// `activation_pressure_millis` default keeps older records readable and can
/// only understate pressure, never fabricate it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryGravity {
    pub memory_ref: String,
    #[serde(default)]
    pub activation_pressure_millis: i64,
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
#[serde(deny_unknown_fields)]
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
    pub precondition_refs: Vec<String>,
    pub expected_admission_effect: MemoryEcologyDecision,
    #[serde(default)]
    pub reactivation_condition: Option<ReactivationCondition>,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ArchiveReceipt {
    pub archive_id: String,
    pub project_id: ProjectId,
    pub target_ref: String,
    pub reason: ForgettingReason,
    pub retained_for_audit: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Decoder: derived and closed. `status` and `pinned` are contract-required
/// protection state and must be present on the wire.
///
/// `pinned` was `#[serde(default = "default_true")]`, so an omitted key decoded
/// as `true` — and `pinned: true` is the *strongest* minority protection
/// `MinorityLifecycleService::minority_is_pinned` recognises (it additionally
/// requires `status == Open`, no `resolved_by_ref` and an unexpired
/// `suppression_forbidden_until`). A default of `true` therefore manufactured
/// protection from an absent field, which is the reverse of the ordinary
/// default-direction concern: it is the one default here that would have let a
/// truncated record claim a guard it never recorded. `status` defaulted to
/// `Open`, pairing with it to produce a fully-protected record from two absent
/// keys. Both are now required; omission fails with the derived typed
/// missing-field error (the existing owner, same pattern as the merged
/// #722/#3155 and #708/#3437 increments).
///
/// Compatibility: this record is persisted through `eliot-store`'s canonical
/// projection (`canonical_projection_views.rs`,
/// `minority_pressure: Vec<CanonicalRecord<MinorityPressureRecord>>`). The one
/// current producer, `mcp_stdio/operator.rs:3595`, sets `status: Open` and
/// `pinned: true` explicitly, and `Serialize` is untouched, so accepted and
/// emitted bytes are unchanged. The previously documented "older records"
/// tolerance is withdrawn: no named/versioned legacy decoder exists for this
/// record and none may be invented (W4), so such a record now fails loudly.
///
/// `release_condition`, `resolved_by_ref` and `write_receipt` keep explicit
/// `Option` presence: an absent key, an explicit `null` and a value stay three
/// distinguishable states, and none of them can resolve pressure or admit
/// suppression. `write_receipt` in particular also keeps
/// `skip_serializing_if`, because the store stamps it back after
/// serialization and the canonical bytes on disk omit the key when it is
/// `None`; dropping `default` there would make a store-written record
/// unreadable by its own type (the round-trip trap).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinorityPressureRecord {
    pub minority_record_id: String,
    pub project_id: ProjectId,
    pub minority_claim_ref: String,
    pub majority_claim_ref: Option<String>,
    pub why_minority_matters: String,
    pub discriminative_probe: Option<String>,
    pub status: MinorityPressureStatus,
    pub pinned: bool,
    pub release_condition: Option<String>,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct MemoryLifecycleProposalReport {
    pub component: String,
    pub policy: ForgettingPolicy,
    pub decision: MemoryLifecycleDecision,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLifecycleApplyReport {
    pub component: String,
    pub decision: MemoryLifecycleDecision,
    pub transition: Option<MemoryStateTransition>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLifecycleReport {
    pub component: String,
    pub statuses: Vec<MemoryLifecycleStatusReport>,
    pub proposals: Vec<MemoryLifecycleProposalReport>,
    pub influence: Option<MemoryInfluenceReport>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPressureReport {
    pub duplicate_pressure: String,
    pub stale_activation_pressure: String,
    pub skill_distractor_pressure: String,
    pub open_lifecycle_proposals: usize,
    pub suppressed_recent_regret: usize,
}
