use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_types::lifecycle::MemoryInfluenceOutcome;
use eliot_types::{
    AgentId, ArchiveReceipt, CommandContext, DemotionReceipt, ForgettingOperator, ForgettingPolicy,
    ForgettingReason, L0SuppressionTrace, LifecycleStatus, MemoryEcologyDecision, MemoryGravity,
    MemoryHandlePreview, MemoryInfluenceReport, MemoryLifecycleDecision, MemoryLifecyclePacketView,
    MemoryLifecycleState, MemoryLifecycleStatusReport, MemoryPressureReport, MemoryStateTransition,
    MemoryTrajectoryCorrectness, MemoryVitalityScore, MinorityPressureRecord,
    MinorityPressureStatus, NegativeMemoryDecision, NegativeMemoryDecisionReceipt,
    NegativeMemoryGateInput, ProjectId, ReactivationCondition, RecallL0Response, SemanticCommand,
    SupersessionReceipt, SuppressionReceipt, TaintClass, TaskId, ToolObservationRecordCommand,
    Visibility, WriteId, WriteReceiptRef,
};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use time::OffsetDateTime;

#[derive(Clone, Debug, Default)]
pub struct MemoryLifecycleService {
    states: BTreeMap<String, MemoryLifecycleState>,
    superseding_refs: BTreeMap<String, String>,
}

impl MemoryLifecycleService {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_state(
        mut self,
        target_ref: impl Into<String>,
        state: MemoryLifecycleState,
    ) -> Self {
        self.states.insert(target_ref.into(), state);
        self
    }

    #[must_use]
    pub fn with_supersession(
        mut self,
        old_ref: impl Into<String>,
        new_ref: impl Into<String>,
    ) -> Self {
        self.superseding_refs.insert(old_ref.into(), new_ref.into());
        self
    }

    pub fn state_for(&self, target_ref: &str) -> MemoryLifecycleState {
        self.states
            .get(target_ref)
            .copied()
            .unwrap_or(MemoryLifecycleState::Active)
    }

    pub fn status(&self, project_id: ProjectId, target_ref: &str) -> MemoryLifecycleStatusReport {
        MemoryLifecycleStatusReport {
            component: "memory_lifecycle_status".to_owned(),
            project_id,
            target_ref: target_ref.to_owned(),
            state: self.state_for(target_ref),
            related_receipts: self
                .superseding_refs
                .get(target_ref)
                .map(|superseding| vec![format!("superseded_by:{superseding}")])
                .unwrap_or_default(),
            generated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn transition_for_policy(
        &self,
        policy: &ForgettingPolicy,
        performed_by: &str,
    ) -> Result<MemoryStateTransition, MemoryLifecycleDecision> {
        self.transition_for_policy_at(policy, performed_by, &[], OffsetDateTime::now_utc())
    }

    pub fn transition_for_policy_at(
        &self,
        policy: &ForgettingPolicy,
        performed_by: &str,
        minority_records: &[MinorityPressureRecord],
        now: OffsetDateTime,
    ) -> Result<MemoryStateTransition, MemoryLifecycleDecision> {
        let from_state = self.state_for(&policy.target_ref);
        let decision = MemoryLifecycleGate::decide_at(policy, minority_records, from_state, now);
        if decision != MemoryLifecycleDecision::Allow {
            return Err(decision);
        }
        let to_state = state_for_operator(policy.operator);
        let transition_id = deterministic_id(
            "memory-transition",
            &[
                &policy.policy_id,
                &policy.target_ref,
                state_name(from_state),
                state_name(to_state),
                operator_name(policy.operator),
            ],
        );
        Ok(MemoryStateTransition {
            transition_id,
            project_id: policy.project_id,
            target_ref: policy.target_ref.clone(),
            from_state,
            to_state,
            operator: policy.operator,
            reason: policy.reason,
            policy_ref: policy.policy_id.clone(),
            evidence_refs: policy.evidence_refs.clone(),
            precondition_refs: policy.precondition_refs.clone(),
            expected_admission_effect: policy.expected_admission_effect,
            reactivation_condition: policy.reactivation_condition.clone(),
            reversible: policy.reversible,
            approval_ref: policy.approval_ref.clone(),
            performed_by: performed_by.to_owned(),
            created_at: policy.effective_at.unwrap_or(policy.created_at),
            write_receipt: None,
        })
    }

    /// Applies a previously gated transition to the in-memory projection.
    /// Returns `false` for an exact replay or a stale/non-contiguous transition.
    pub fn apply_transition(&mut self, transition: &MemoryStateTransition) -> bool {
        let current = self.state_for(&transition.target_ref);
        if current == transition.to_state || current != transition.from_state {
            return false;
        }
        self.states
            .insert(transition.target_ref.clone(), transition.to_state);
        true
    }

    pub fn reverse_transition(
        &self,
        transition: &MemoryStateTransition,
        performed_by: &str,
        evidence_refs: Vec<String>,
    ) -> Result<MemoryStateTransition, MemoryLifecycleDecision> {
        if !transition.reversible
            || transition.to_state == MemoryLifecycleState::HardDeleted
            || self.state_for(&transition.target_ref) != transition.to_state
            || evidence_refs.is_empty()
        {
            return Err(MemoryLifecycleDecision::DenyUnsafeSuppression);
        }
        Ok(MemoryStateTransition {
            transition_id: deterministic_id(
                "memory-reversal",
                &[&transition.transition_id, state_name(transition.from_state)],
            ),
            project_id: transition.project_id,
            target_ref: transition.target_ref.clone(),
            from_state: transition.to_state,
            to_state: transition.from_state,
            operator: ForgettingOperator::Restore,
            reason: transition.reason,
            policy_ref: transition.policy_ref.clone(),
            evidence_refs,
            precondition_refs: vec![transition.transition_id.clone()],
            expected_admission_effect: MemoryEcologyDecision::KeepHot,
            reactivation_condition: transition.reactivation_condition.clone(),
            reversible: true,
            approval_ref: None,
            performed_by: performed_by.to_owned(),
            created_at: OffsetDateTime::now_utc(),
            write_receipt: None,
        })
    }

    pub fn trajectory_correctness(
        transitions: &[MemoryStateTransition],
        observed_admission_effect: MemoryEcologyDecision,
        evidence_refs: Vec<String>,
    ) -> MemoryTrajectoryCorrectness {
        let target_ref = transitions
            .first()
            .map(|transition| transition.target_ref.clone())
            .unwrap_or_default();
        let contiguous = !transitions.is_empty()
            && transitions
                .iter()
                .all(|transition| transition.target_ref == target_ref)
            && transitions
                .windows(2)
                .all(|pair| pair[0].to_state == pair[1].from_state);
        let expected_admission_effect = transitions
            .last()
            .map_or(MemoryEcologyDecision::KeepHot, |transition| {
                transition.expected_admission_effect
            });
        let transition_refs = transitions
            .iter()
            .map(|transition| transition.transition_id.clone())
            .collect::<Vec<_>>();
        MemoryTrajectoryCorrectness {
            trajectory_id: deterministic_id(
                "memory-trajectory",
                &transition_refs
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            ),
            target_ref,
            transition_refs,
            expected_admission_effect,
            observed_admission_effect,
            correct: contiguous
                && expected_admission_effect == observed_admission_effect
                && !evidence_refs.is_empty(),
            evidence_refs,
            write_receipt: None,
        }
    }

    pub async fn apply_policy_through_writer(
        &self,
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        policy: &ForgettingPolicy,
        performed_by: &str,
    ) -> Result<MemoryLifecycleApplyOutcome, EngineError> {
        let transition = match self.transition_for_policy(policy, performed_by) {
            Ok(transition) => transition,
            Err(decision) => {
                return Ok(MemoryLifecycleApplyOutcome {
                    decision,
                    transition: None,
                    write_receipt: None,
                });
            }
        };
        let write_receipt =
            MemoryLifecycleMemoryWriter::write_transition(handle, admission, &transition).await?;
        Ok(MemoryLifecycleApplyOutcome {
            decision: MemoryLifecycleDecision::Allow,
            transition: Some(transition),
            write_receipt: Some(write_receipt),
        })
    }

    pub fn filter_l0_response(
        mut response: RecallL0Response,
        audit_mode: bool,
    ) -> RecallL0Response {
        response.rank_trace.lifecycle_suppressions = response
            .handles
            .iter()
            .filter_map(|handle| {
                let state = handle.lifecycle_state?;
                (!is_default_visible_lifecycle(state)).then(|| L0SuppressionTrace {
                    handle: handle.handle.clone(),
                    reason: format!("lifecycle_{state:?}").to_ascii_lowercase(),
                })
            })
            .collect();
        response.handles = filter_l0_handles(response.handles, audit_mode);
        response.truncation.returned = response.handles.len();
        response.rank_trace.candidates_returned = response.handles.len();
        response.rank_trace.no_useful_memory = response.handles.is_empty();
        response
    }

    pub fn lifecycle_packet(
        states: &[(String, MemoryLifecycleState)],
        minority_records: &[MinorityPressureRecord],
    ) -> MemoryLifecyclePacketView {
        let mut packet = MemoryLifecyclePacketView::default();
        for (target_ref, state) in states {
            match state {
                MemoryLifecycleState::Suppressed
                | MemoryLifecycleState::Quarantined
                | MemoryLifecycleState::Forgotten
                | MemoryLifecycleState::HardDeleted => {
                    packet.suppressed_refs.push(target_ref.clone());
                }
                MemoryLifecycleState::Dormant | MemoryLifecycleState::Demoted => {
                    packet.demoted_refs.push(target_ref.clone());
                }
                MemoryLifecycleState::Superseded => packet.superseded_refs.push(target_ref.clone()),
                MemoryLifecycleState::Archived | MemoryLifecycleState::RetainedForAudit => {
                    packet.archived_refs.push(target_ref.clone());
                }
                MemoryLifecycleState::Active
                | MemoryLifecycleState::Restored
                | MemoryLifecycleState::CompressedInto
                | MemoryLifecycleState::Poisoned
                | MemoryLifecycleState::ReactivationCandidate => {}
            }
        }
        packet.minority_preserved_refs = minority_records
            .iter()
            .filter(|record| {
                MemoryLifecycleGate::minority_is_pinned(record, OffsetDateTime::now_utc())
            })
            .map(|record| record.minority_claim_ref.clone())
            .collect();
        if !packet.superseded_refs.is_empty() {
            packet
                .lifecycle_warnings
                .push("superseded refs require replacement before packet use".to_owned());
        }
        packet
    }

    pub fn replace_superseded_refs(&self, refs: &[String]) -> Vec<String> {
        let mut seen = BTreeSet::new();
        refs.iter()
            .map(|target_ref| {
                self.superseding_refs
                    .get(target_ref)
                    .cloned()
                    .unwrap_or_else(|| target_ref.clone())
            })
            .filter(|target_ref| seen.insert(target_ref.clone()))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct MemoryLifecycleApplyOutcome {
    pub decision: MemoryLifecycleDecision,
    pub transition: Option<MemoryStateTransition>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Default)]
pub struct ForgettingPolicyService;

impl ForgettingPolicyService {
    pub fn propose(
        project_id: ProjectId,
        target_ref: &str,
        operator: ForgettingOperator,
        reason: ForgettingReason,
        evidence_refs: Vec<String>,
        rollback_or_tombstone_ref: Option<String>,
        reactivation_condition: Option<ReactivationCondition>,
    ) -> ForgettingPolicy {
        ForgettingPolicy {
            policy_id: format!("forgetting-policy-{}", WriteId::new_v7()),
            project_id,
            target_ref: target_ref.to_owned(),
            reason,
            operator,
            evidence_refs,
            rollback_or_tombstone_ref,
            reactivation_condition,
            expected_current_state: MemoryLifecycleState::Active,
            observed_epistemic_status: eliot_types::EpistemicStatus::Observed,
            scope: vec!["project".to_owned()],
            precondition_refs: Vec::new(),
            effective_at: Some(OffsetDateTime::now_utc()),
            expires_at: None,
            expected_admission_effect: ecology_decision_for_operator(operator),
            reversible: operator != ForgettingOperator::Purge,
            requires_admin_approval: operator == ForgettingOperator::Purge,
            approval_ref: None,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn validate(policy: &ForgettingPolicy) -> MemoryLifecycleDecision {
        if policy.operator == ForgettingOperator::Purge
            && (policy.reason != ForgettingReason::Privacy
                || policy.reversible
                || policy.approval_ref.as_deref().is_none_or(str::is_empty)
                || !policy.requires_admin_approval)
        {
            return MemoryLifecycleDecision::DenyPurgeInI0;
        }
        if matches!(
            policy.operator,
            ForgettingOperator::Suppress
                | ForgettingOperator::Demote
                | ForgettingOperator::Archive
                | ForgettingOperator::MarkPoisoned
                | ForgettingOperator::RetainAuditOnly
                | ForgettingOperator::Compress
                | ForgettingOperator::Forget
                | ForgettingOperator::Restore
                | ForgettingOperator::Purge
        ) && policy.evidence_refs.is_empty()
        {
            return MemoryLifecycleDecision::RequireEvidence;
        }
        if policy.operator == ForgettingOperator::Supersede
            && policy
                .rollback_or_tombstone_ref
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return MemoryLifecycleDecision::RequireSupersedingRecord;
        }
        if policy.operator == ForgettingOperator::Forget
            && policy
                .rollback_or_tombstone_ref
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return MemoryLifecycleDecision::RequireSupersedingRecord;
        }
        MemoryLifecycleDecision::Allow
    }

    pub fn supports_operator_name(name: &str) -> bool {
        let normalized = name.trim().to_ascii_lowercase();
        normalized != "purge"
            && ForgettingOperator::all_i0()
                .iter()
                .any(|operator| operator_name(*operator) == normalized)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryLifecycleGate;

impl MemoryLifecycleGate {
    pub fn decide(
        policy: &ForgettingPolicy,
        minority_records: &[MinorityPressureRecord],
    ) -> MemoryLifecycleDecision {
        Self::decide_at(
            policy,
            minority_records,
            policy.expected_current_state,
            OffsetDateTime::now_utc(),
        )
    }

    pub fn decide_at(
        policy: &ForgettingPolicy,
        minority_records: &[MinorityPressureRecord],
        current_state: MemoryLifecycleState,
        now: OffsetDateTime,
    ) -> MemoryLifecycleDecision {
        if policy.effective_at.is_some_and(|effective| effective > now)
            || policy.expires_at.is_some_and(|expires| expires <= now)
            || policy.expected_current_state != current_state
            || current_state == MemoryLifecycleState::HardDeleted
        {
            return MemoryLifecycleDecision::DenyUnsafeSuppression;
        }
        if policy.operator != ForgettingOperator::Restore
            && minority_records.iter().any(|record| {
                record.minority_claim_ref == policy.target_ref
                    && Self::minority_is_pinned(record, now)
            })
        {
            return MemoryLifecycleDecision::ProtectMinorityEvidence;
        }
        let basic = ForgettingPolicyService::validate(policy);
        if basic != MemoryLifecycleDecision::Allow {
            return basic;
        }
        if policy.operator == ForgettingOperator::Restore {
            if !matches!(
                current_state,
                MemoryLifecycleState::Dormant
                    | MemoryLifecycleState::Suppressed
                    | MemoryLifecycleState::Archived
                    | MemoryLifecycleState::Quarantined
                    | MemoryLifecycleState::Forgotten
            ) {
                return MemoryLifecycleDecision::DenyUnsafeSuppression;
            }
            let Some(condition) = policy.reactivation_condition.as_ref() else {
                return MemoryLifecycleDecision::RequireEvidence;
            };
            if condition.expires_at.is_some_and(|expires| expires <= now)
                || condition
                    .required_evidence_refs
                    .iter()
                    .any(|required| !policy.evidence_refs.contains(required))
            {
                return MemoryLifecycleDecision::RequireEvidence;
            }
        }
        MemoryLifecycleDecision::Allow
    }

    pub fn minority_is_pinned(record: &MinorityPressureRecord, now: OffsetDateTime) -> bool {
        record.pinned
            && record.status == MinorityPressureStatus::Open
            && record.resolved_by_ref.is_none()
            && record
                .suppression_forbidden_until
                .is_none_or(|expires| expires > now)
    }

    pub fn release_minority(
        record: &MinorityPressureRecord,
        status: MinorityPressureStatus,
        resolution_ref: &str,
    ) -> Result<MinorityPressureRecord, MemoryLifecycleDecision> {
        if status == MinorityPressureStatus::Open
            || resolution_ref.trim().is_empty()
            || record
                .release_condition
                .as_deref()
                .is_some_and(|required| required != resolution_ref)
        {
            return Err(MemoryLifecycleDecision::ProtectMinorityEvidence);
        }
        let mut released = record.clone();
        released.status = status;
        released.pinned = false;
        released.resolved_by_ref = Some(resolution_ref.to_owned());
        Ok(released)
    }

    pub fn decide_operator_name(name: &str) -> MemoryLifecycleDecision {
        if name.trim().eq_ignore_ascii_case("purge") {
            MemoryLifecycleDecision::DenyPurgeInI0
        } else if ForgettingPolicyService::supports_operator_name(name) {
            MemoryLifecycleDecision::Allow
        } else {
            MemoryLifecycleDecision::DenyUnsafeSuppression
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryVitalityService;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryVitalitySignals {
    pub reuse_count: u64,
    pub beneficial_use_count: u64,
    pub prevented_failure_count: u64,
    pub correct_verifier_selection_count: u64,
    pub verification_success_count: u64,
    pub verification_failure_count: u64,
    pub stale_hits: u64,
    pub false_activation_count: u64,
    pub negative_transfer_count: u64,
    pub contradiction_count: u64,
    pub context_cost_tokens: u64,
    pub maintenance_cost_units: u64,
    pub minority_importance_millis: i64,
    pub freshness_millis: i64,
    pub scope_fit_millis: i64,
}

impl MemoryVitalityService {
    pub fn score(project_id: ProjectId, memory_ref: &str) -> MemoryVitalityScore {
        Self::score_from_signals(
            project_id,
            memory_ref,
            &MemoryVitalitySignals {
                reuse_count: 1,
                verification_success_count: 1,
                freshness_millis: 750,
                scope_fit_millis: 750,
                context_cost_tokens: 64,
                maintenance_cost_units: 1,
                ..MemoryVitalitySignals::default()
            },
        )
    }

    pub fn score_from_signals(
        project_id: ProjectId,
        memory_ref: &str,
        signals: &MemoryVitalitySignals,
    ) -> MemoryVitalityScore {
        let utility_raw = weighted(signals.beneficial_use_count, 140)
            + weighted(signals.prevented_failure_count, 190)
            + weighted(signals.correct_verifier_selection_count, 120)
            + weighted(signals.verification_success_count, 50)
            + weighted(signals.reuse_count, 15)
            + signals.minority_importance_millis / 3
            + signals.freshness_millis / 4
            + signals.scope_fit_millis / 4
            - u64_to_i64(signals.context_cost_tokens) / 5
            - weighted(signals.maintenance_cost_units, 20);
        let harm_raw = weighted(signals.negative_transfer_count, 300)
            + weighted(signals.false_activation_count, 220)
            + weighted(signals.stale_hits, 120)
            + weighted(signals.verification_failure_count, 100)
            + weighted(signals.contradiction_count, 160)
            + u64_to_i64(signals.context_cost_tokens) / 10
            + weighted(signals.maintenance_cost_units, 20);
        let utility_millis = utility_raw.clamp(0, 1000);
        let harm_millis = harm_raw.clamp(0, 1000);
        let decision = if signals.negative_transfer_count > 0 || signals.false_activation_count >= 2
        {
            MemoryEcologyDecision::Suppress
        } else if signals.contradiction_count > 0 {
            MemoryEcologyDecision::SplitPattern
        } else if signals.stale_hits > 0 {
            MemoryEcologyDecision::RequireRevalidation
        } else if harm_millis > utility_millis {
            MemoryEcologyDecision::Demote
        } else if signals.context_cost_tokens > 512 && signals.beneficial_use_count == 0 {
            MemoryEcologyDecision::KeepHandleOnly
        } else {
            MemoryEcologyDecision::KeepHot
        };
        MemoryVitalityScore {
            memory_ref: memory_ref.to_owned(),
            project_id,
            reuse_count: signals.reuse_count,
            decision_delta_history: Vec::new(),
            verification_success_count: signals.verification_success_count,
            verification_failure_count: signals.verification_failure_count,
            stale_hits: signals.stale_hits,
            false_activation_count: signals.false_activation_count,
            beneficial_use_count: signals.beneficial_use_count,
            prevented_failure_count: signals.prevented_failure_count,
            correct_verifier_selection_count: signals.correct_verifier_selection_count,
            negative_transfer_count: signals.negative_transfer_count,
            contradiction_count: signals.contradiction_count,
            context_cost_tokens: signals.context_cost_tokens,
            maintenance_cost_units: signals.maintenance_cost_units,
            minority_importance_millis: signals.minority_importance_millis,
            freshness_millis: signals.freshness_millis.clamp(0, 1000),
            scope_fit_millis: signals.scope_fit_millis.clamp(0, 1000),
            utility_millis,
            harm_millis,
            decision,
            recency_score: millis_as_score(signals.freshness_millis),
            scope_fit_score: millis_as_score(signals.scope_fit_millis),
            utility_score: millis_as_score(utility_millis),
            harm_score: millis_as_score(harm_millis),
            computed_at: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryGravityService;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryGravitySignals {
    pub packet_inclusion_count: u64,
    pub top_rank_count: u64,
    pub cluster_share_millis: i64,
}

impl MemoryGravityService {
    pub fn gravity(score: &MemoryVitalityScore) -> MemoryGravity {
        Self::gravity_from_signals(
            score,
            &MemoryGravitySignals {
                packet_inclusion_count: score.reuse_count,
                top_rank_count: 0,
                cluster_share_millis: 0,
            },
        )
    }

    pub fn gravity_from_signals(
        score: &MemoryVitalityScore,
        signals: &MemoryGravitySignals,
    ) -> MemoryGravity {
        let activation_pressure_millis = (weighted(signals.packet_inclusion_count, 50)
            + weighted(signals.top_rank_count, 100)
            + signals.cluster_share_millis / 2
            + weighted(score.reuse_count, 10))
        .clamp(0, 1000);
        let dominates = activation_pressure_millis >= 750;
        let decision = if dominates && score.contradiction_count > 0 {
            MemoryEcologyDecision::SplitPattern
        } else if dominates && score.harm_millis >= score.utility_millis {
            MemoryEcologyDecision::Suppress
        } else {
            score.decision
        };
        let suppression_needed = matches!(
            decision,
            MemoryEcologyDecision::Suppress | MemoryEcologyDecision::SplitPattern
        );
        MemoryGravity {
            memory_ref: score.memory_ref.clone(),
            activation_pressure_millis,
            decision,
            activation_pressure: millis_as_score(activation_pressure_millis),
            why_it_keeps_appearing: vec![format!(
                "packet_inclusions={} top_rank={} cluster_share_millis={}",
                signals.packet_inclusion_count,
                signals.top_rank_count,
                signals.cluster_share_millis.clamp(0, 1000)
            )],
            harm_or_utility: if suppression_needed {
                "observed activation pressure is disproportionate to governed value".to_owned()
            } else {
                "observed value justifies current activation pressure".to_owned()
            },
            suppression_needed,
            evidence_refs: vec![format!("vitality:{}", score.memory_ref)],
            computed_at: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryInfluenceService;

impl MemoryInfluenceService {
    pub fn report(
        project_id: ProjectId,
        task_id: Option<TaskId>,
        packet_id: Option<String>,
        included_refs: Vec<String>,
        lifecycle: &MemoryLifecyclePacketView,
    ) -> MemoryInfluenceReport {
        MemoryInfluenceReport {
            report_id: format!("memory-influence-{}", WriteId::new_v7()),
            project_id,
            task_id,
            packet_id,
            included_refs,
            suppressed_refs: lifecycle.suppressed_refs.clone(),
            demoted_refs: lifecycle.demoted_refs.clone(),
            superseded_refs: lifecycle.superseded_refs.clone(),
            archived_refs: lifecycle.archived_refs.clone(),
            minority_preserved_refs: lifecycle.minority_preserved_refs.clone(),
            missing_context_regret_refs: Vec::new(),
            outcome: None,
            generated_at: OffsetDateTime::now_utc(),
            write_receipt: None,
        }
    }

    pub fn attach_outcome(
        report: &mut MemoryInfluenceReport,
        mut outcome: MemoryInfluenceOutcome,
    ) -> Result<(), EngineError> {
        outcome.evidence_refs.sort();
        outcome.evidence_refs.dedup();
        validate_influence_outcome(&outcome)?;
        report.outcome = Some(outcome);
        Ok(())
    }

    pub fn validate_for_write(report: &MemoryInfluenceReport) -> Result<(), EngineError> {
        if let Some(outcome) = &report.outcome {
            validate_influence_outcome(outcome)?;
        }
        Ok(())
    }
}

fn validate_influence_outcome(outcome: &MemoryInfluenceOutcome) -> Result<(), EngineError> {
    let missing = [
        ("changed_action_or_tool", &outcome.changed_action_or_tool),
        ("verifier", &outcome.verifier),
        ("avoided_path", &outcome.avoided_path),
        ("downstream_outcome", &outcome.downstream_outcome),
    ]
    .into_iter()
    .find_map(|(name, value)| value.trim().is_empty().then_some(name));
    if let Some(missing) = missing {
        return Err(EngineError::WriteRejected(format!(
            "memory influence outcome is missing observable field {missing}"
        )));
    }
    if outcome.evidence_refs.is_empty()
        || outcome
            .evidence_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
    {
        return Err(EngineError::WriteRejected(
            "memory influence outcome requires observable evidence refs".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeMemoryGateReport {
    pub fingerprint: String,
    pub repeated_count: u64,
    pub blocked: bool,
    pub decision: NegativeMemoryDecision,
    pub reasons: Vec<String>,
    pub decision_receipt: NegativeMemoryDecisionReceipt,
    pub recommended_operator: Option<ForgettingOperator>,
}

#[derive(Clone, Debug, Default)]
pub struct NegativeMemoryGate;

impl NegativeMemoryGate {
    pub fn evaluate(fingerprint: &str, repeated_count: u64) -> NegativeMemoryGateReport {
        Self::evaluate_scoped(&NegativeMemoryGateInput {
            fingerprint: fingerprint.to_owned(),
            repeated_count,
            scope_matches: true,
            ..NegativeMemoryGateInput::default()
        })
    }

    pub fn evaluate_scoped(input: &NegativeMemoryGateInput) -> NegativeMemoryGateReport {
        let all_reopen_conditions_satisfied = !input.reopen_conditions.is_empty()
            && input.reopen_conditions.iter().all(|condition| {
                input
                    .satisfied_reopen_conditions
                    .iter()
                    .any(|satisfied| satisfied == condition)
            })
            && !input.discriminative_evidence_refs.is_empty();
        let (decision, reasons) = if !input.scope_matches {
            (
                NegativeMemoryDecision::Allow,
                vec!["failure fingerprint scope does not match the current path".to_owned()],
            )
        } else if input.repeated_count < 2 {
            (
                NegativeMemoryDecision::Allow,
                vec!["failure has not repeated enough to block the path".to_owned()],
            )
        } else if all_reopen_conditions_satisfied {
            (
                NegativeMemoryDecision::Reopen,
                vec!["all scoped reopen conditions have discriminative evidence".to_owned()],
            )
        } else if input.reopen_conditions.is_empty() {
            (
                NegativeMemoryDecision::BlockRepeatedFailure,
                vec!["matching repeated failure has no satisfied reopen route".to_owned()],
            )
        } else {
            (
                NegativeMemoryDecision::RequireDiscriminativeProbe,
                vec!["reopen conditions require new discriminative evidence".to_owned()],
            )
        };
        let blocked = matches!(
            decision,
            NegativeMemoryDecision::BlockRepeatedFailure
                | NegativeMemoryDecision::RequireDiscriminativeProbe
        );
        let decision_receipt = NegativeMemoryDecisionReceipt {
            receipt_id: format!("negative-memory-{}", WriteId::new_v7()),
            fingerprint: input.fingerprint.clone(),
            decision,
            reasons: reasons.clone(),
            reopen_conditions: input.reopen_conditions.clone(),
            evidence_refs: input.discriminative_evidence_refs.clone(),
            canonical_receipt: None,
        };
        NegativeMemoryGateReport {
            fingerprint: input.fingerprint.clone(),
            repeated_count: input.repeated_count,
            blocked,
            decision,
            reasons,
            decision_receipt,
            recommended_operator: None,
        }
    }
}

pub struct MemoryLifecycleMemoryWriter;

impl MemoryLifecycleMemoryWriter {
    pub async fn write_suppression_receipt(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        receipt: &SuppressionReceipt,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_lifecycle_observation(handle, admission, "suppression_receipt", receipt).await
    }

    pub async fn write_demotion_receipt(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        receipt: &DemotionReceipt,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_lifecycle_observation(handle, admission, "demotion_receipt", receipt).await
    }

    pub async fn write_supersession_receipt(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        receipt: &SupersessionReceipt,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_lifecycle_observation(handle, admission, "supersession_receipt", receipt).await
    }

    pub async fn write_archive_receipt(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        receipt: &ArchiveReceipt,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_lifecycle_observation(handle, admission, "archive_receipt", receipt).await
    }

    pub async fn write_transition(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        transition: &MemoryStateTransition,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_lifecycle_observation(handle, admission, "state_transition", transition).await
    }

    pub async fn write_influence_report(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        report: &mut MemoryInfluenceReport,
    ) -> Result<WriteReceiptRef, EngineError> {
        MemoryInfluenceService::validate_for_write(report)?;
        let receipt =
            write_lifecycle_observation(handle, admission, "memory_influence_report", &*report)
                .await?;
        report.write_receipt = Some(receipt.clone());
        Ok(receipt)
    }
}

pub fn memory_pressure_report() -> MemoryPressureReport {
    MemoryPressureReport {
        duplicate_pressure: "low".to_owned(),
        stale_activation_pressure: "low".to_owned(),
        skill_distractor_pressure: "low".to_owned(),
        open_lifecycle_proposals: 0,
        suppressed_recent_regret: 0,
    }
}

const fn is_default_visible_lifecycle(state: MemoryLifecycleState) -> bool {
    !matches!(
        state,
        MemoryLifecycleState::Suppressed
            | MemoryLifecycleState::Archived
            | MemoryLifecycleState::Quarantined
            | MemoryLifecycleState::Forgotten
            | MemoryLifecycleState::HardDeleted
    )
}

fn filter_l0_handles(
    handles: Vec<MemoryHandlePreview>,
    audit_mode: bool,
) -> Vec<MemoryHandlePreview> {
    handles
        .into_iter()
        .filter_map(
            |mut handle| match handle.lifecycle_state.unwrap_or_default() {
                MemoryLifecycleState::Suppressed
                | MemoryLifecycleState::Archived
                | MemoryLifecycleState::Quarantined
                | MemoryLifecycleState::Forgotten
                | MemoryLifecycleState::HardDeleted
                    if !audit_mode =>
                {
                    None
                }
                state => {
                    if audit_mode && state != MemoryLifecycleState::Active {
                        handle.lifecycle_badge = Some(format!("{state:?}").to_ascii_lowercase());
                    }
                    Some(handle)
                }
            },
        )
        .collect()
}

fn state_for_operator(operator: ForgettingOperator) -> MemoryLifecycleState {
    match operator {
        ForgettingOperator::Suppress => MemoryLifecycleState::Suppressed,
        ForgettingOperator::Demote | ForgettingOperator::Compress => MemoryLifecycleState::Dormant,
        ForgettingOperator::Supersede | ForgettingOperator::Archive => {
            MemoryLifecycleState::Archived
        }
        ForgettingOperator::Forget => MemoryLifecycleState::Forgotten,
        ForgettingOperator::Restore => MemoryLifecycleState::Restored,
        ForgettingOperator::Purge => MemoryLifecycleState::HardDeleted,
        ForgettingOperator::MarkPoisoned => MemoryLifecycleState::Poisoned,
        ForgettingOperator::RetainAuditOnly => MemoryLifecycleState::RetainedForAudit,
    }
}

fn state_name(state: MemoryLifecycleState) -> &'static str {
    match state {
        MemoryLifecycleState::Active => "active",
        MemoryLifecycleState::Dormant => "dormant",
        MemoryLifecycleState::Suppressed => "suppressed",
        MemoryLifecycleState::Archived => "archived",
        MemoryLifecycleState::Quarantined => "quarantined",
        MemoryLifecycleState::Forgotten => "forgotten",
        MemoryLifecycleState::Restored => "restored",
        MemoryLifecycleState::HardDeleted => "hard_deleted",
        MemoryLifecycleState::Demoted => "demoted",
        MemoryLifecycleState::Superseded => "superseded",
        MemoryLifecycleState::CompressedInto => "compressed_into",
        MemoryLifecycleState::Poisoned => "poisoned",
        MemoryLifecycleState::RetainedForAudit => "retained_for_audit",
        MemoryLifecycleState::ReactivationCandidate => "reactivation_candidate",
    }
}

fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update(&[0]);
        hasher.update(part.as_bytes());
    }
    format!("{prefix}:{}", hasher.finalize().to_hex())
}

fn weighted(value: u64, weight: i64) -> i64 {
    u64_to_i64(value).saturating_mul(weight)
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn millis_as_score(value: i64) -> f64 {
    i32::try_from(value.clamp(0, 1000)).map_or(1.0, |value| f64::from(value) / 1000.0)
}

fn operator_name(operator: ForgettingOperator) -> &'static str {
    match operator {
        ForgettingOperator::Suppress => "suppress",
        ForgettingOperator::Demote => "demote",
        ForgettingOperator::Supersede => "supersede",
        ForgettingOperator::Archive => "archive",
        ForgettingOperator::Compress => "compress",
        ForgettingOperator::Forget => "forget",
        ForgettingOperator::Restore => "restore",
        ForgettingOperator::Purge => "purge",
        ForgettingOperator::MarkPoisoned => "markpoisoned",
        ForgettingOperator::RetainAuditOnly => "retainauditonly",
    }
}

const fn ecology_decision_for_operator(operator: ForgettingOperator) -> MemoryEcologyDecision {
    match operator {
        ForgettingOperator::Compress => MemoryEcologyDecision::KeepHandleOnly,
        ForgettingOperator::Demote => MemoryEcologyDecision::Demote,
        ForgettingOperator::Suppress => MemoryEcologyDecision::Suppress,
        ForgettingOperator::Supersede => MemoryEcologyDecision::RequireRevalidation,
        ForgettingOperator::Archive | ForgettingOperator::RetainAuditOnly => {
            MemoryEcologyDecision::Archive
        }
        ForgettingOperator::Forget => MemoryEcologyDecision::ForgetCandidate,
        ForgettingOperator::Restore => MemoryEcologyDecision::KeepHot,
        ForgettingOperator::Purge => MemoryEcologyDecision::PurgeRequiresAdmin,
        ForgettingOperator::MarkPoisoned => MemoryEcologyDecision::Quarantine,
    }
}

async fn write_lifecycle_observation<T>(
    handle: &WriterHandle,
    admission: &WriteAdmissionService,
    kind: &str,
    body: &T,
) -> Result<WriteReceiptRef, EngineError>
where
    T: Serialize,
{
    let body_value = serde_json::to_value(body)?;
    let project_id = body_value
        .get("project_id")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_else(ProjectId::new_v7);
    let (write_id, agent_id) = deterministic_lifecycle_context_ids(project_id, kind, &body_value)?;
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id,
            agent_id,
            session_id: None,
            project_id,
            task_id: None::<TaskId>,
            scope: "memory-lifecycle-i0".to_owned(),
            authority: "local-memory-lifecycle".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot_memory_lifecycle".to_owned(),
        observation: format!("Memory lifecycle {kind} written through WriterActor"),
        payload: json!({
            "receipt_kind": kind,
            "receipt_body": body_value,
            "writer_path": "semantic_command_writer_actor"
        }),
    });
    let envelope = admission.admit(&command)?;
    let receipt = handle.submit(envelope).await?;
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

fn deterministic_lifecycle_context_ids(
    project_id: ProjectId,
    kind: &str,
    body: &serde_json::Value,
) -> Result<(WriteId, AgentId), EngineError> {
    let material = serde_json::to_vec(&(project_id, kind, body))?;
    let write_id = deterministic_uuid_text(b"eliot-l10-write", &material);
    let agent_id = deterministic_uuid_text(b"eliot-l10-agent", &material);
    Ok((
        WriteId::from_str(&write_id).map_err(|error| {
            EngineError::WriteRejected(format!("invalid deterministic L10 write id: {error}"))
        })?,
        AgentId::from_str(&agent_id).map_err(|error| {
            EngineError::WriteRejected(format!("invalid deterministic L10 agent id: {error}"))
        })?,
    ))
}

fn deterministic_uuid_text(domain: &[u8], material: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(material);
    let hex = hasher.finalize().to_hex().to_string();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod influence_outcome_tests {
    use super::*;

    fn outcome() -> MemoryInfluenceOutcome {
        MemoryInfluenceOutcome {
            changed_action_or_tool: "selected cargo-workspace-check".to_owned(),
            verifier: "eliot/verifier/cargo-workspace-check@1".to_owned(),
            avoided_path: "unscoped verified authority".to_owned(),
            downstream_outcome: "wrong-branch memory remained historical".to_owned(),
            evidence_refs: vec![
                "verification:2".to_owned(),
                "packet:1".to_owned(),
                "verification:2".to_owned(),
            ],
        }
    }

    #[test]
    fn observable_outcome_serializes_and_is_admitted_for_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut report = MemoryInfluenceService::report(
            ProjectId::new_v7(),
            None,
            Some("packet:1".to_owned()),
            vec!["claim:1".to_owned()],
            &MemoryLifecyclePacketView::default(),
        );

        MemoryInfluenceService::attach_outcome(&mut report, outcome())?;
        MemoryInfluenceService::validate_for_write(&report)?;
        let value = serde_json::to_value(&report)?;

        assert_eq!(
            value
                .pointer("/outcome/changed_action_or_tool")
                .and_then(|value| value.as_str()),
            Some("selected cargo-workspace-check")
        );
        assert_eq!(
            value
                .pointer("/outcome/evidence_refs")
                .and_then(|value| value.as_array())
                .map(Vec::len),
            Some(2)
        );
        Ok(())
    }

    #[test]
    fn write_admission_rejects_empty_or_hidden_reasoning_outcomes() {
        let mut report = MemoryInfluenceService::report(
            ProjectId::new_v7(),
            None,
            None,
            Vec::new(),
            &MemoryLifecyclePacketView::default(),
        );
        let mut invalid = outcome();
        invalid.verifier.clear();
        assert!(MemoryInfluenceService::attach_outcome(&mut report, invalid).is_err());

        let serialized = serde_json::json!({
            "changed_action_or_tool": "tool delta",
            "verifier": "verifier ref",
            "avoided_path": "avoided path",
            "downstream_outcome": "outcome",
            "evidence_refs": ["packet:1"],
            "hidden_reasoning": "must never be admitted"
        });
        assert!(serde_json::from_value::<MemoryInfluenceOutcome>(serialized).is_err());
    }

    #[test]
    fn negative_memory_requires_probe_then_reopens_on_exact_evidence() {
        let mut input = NegativeMemoryGateInput {
            fingerprint: "failure:wrong-owner".to_owned(),
            repeated_count: 2,
            scope_matches: true,
            reopen_conditions: vec!["runtime owner changed".to_owned()],
            ..NegativeMemoryGateInput::default()
        };
        let blocked = NegativeMemoryGate::evaluate_scoped(&input);
        assert_eq!(
            blocked.decision,
            NegativeMemoryDecision::RequireDiscriminativeProbe
        );
        assert!(blocked.blocked);
        assert!(blocked.recommended_operator.is_none());

        input
            .satisfied_reopen_conditions
            .push("runtime owner changed".to_owned());
        input
            .discriminative_evidence_refs
            .push("observation:new-owner".to_owned());
        let reopened = NegativeMemoryGate::evaluate_scoped(&input);
        assert_eq!(reopened.decision, NegativeMemoryDecision::Reopen);
        assert!(!reopened.blocked);
        assert_eq!(
            reopened.decision_receipt.evidence_refs,
            vec!["observation:new-owner"]
        );
    }

    #[test]
    fn negative_memory_does_not_false_block_wrong_scope() {
        let report = NegativeMemoryGate::evaluate_scoped(&NegativeMemoryGateInput {
            fingerprint: "failure:other-project".to_owned(),
            repeated_count: 9,
            scope_matches: false,
            ..NegativeMemoryGateInput::default()
        });
        assert_eq!(report.decision, NegativeMemoryDecision::Allow);
        assert!(!report.blocked);
    }
}
