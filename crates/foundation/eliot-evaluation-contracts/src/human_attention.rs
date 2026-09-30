//! Store-neutral Human attention evaluation records (I11.10).
//!
//! These types preserve observations and their limits. Structural validation
//! does not establish evaluator authority, evidence truth, policy superiority,
//! or Human attention from interaction proxies.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ClockReading, ContractId, ContractVersion};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    ComparisonBasis, CoverageState, DecisionOpportunityDenominator, EvaluationContractError,
    ObservationWindowSpec, ObservationWindowStatus, bounded_reason, text, texts, unique_texts,
};

/// Stable wire name for the I11.10 Human attention evaluation record.
pub const HUMAN_ATTENTION_EVALUATION_CONTRACT_NAME: &str = "eliot.evaluation.human-attention";
/// Schema revision for the Human attention evaluation record.
pub const HUMAN_ATTENTION_EVALUATION_CONTRACT_VERSION: ContractVersion =
    ContractVersion::new(1, 0, 0);

/// A revision-addressed Human attention evaluation.
///
/// The record deliberately has no aggregate score or qualification flag.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionEvaluation {
    pub contract_version: ContractVersion,
    pub evaluation_id: ContractId,
    /// Monotonic revision within `evaluation_id`, starting at one.
    pub revision: u64,
    pub evaluator_scope_uncertainty_and_invalidation: EvaluatorScopeUncertaintyInvalidation,
    pub policy_revision: ProfileRevisionRef,
    pub notification_revision: ProfileRevisionRef,
    pub approval_revision: ProfileRevisionRef,
    pub telemetry_revision: ProfileRevisionRef,
    pub observation_window: HumanAttentionObservationWindow,
    pub evidence_manifest: HumanAttentionEvidenceManifest,
    pub method: HumanAttentionMethod,
    pub policy_and_task_risk_profile: HumanAttentionMetricGroup,
    pub notification_approval_and_telemetry_profile: HumanAttentionMetricGroup,
    pub missed_critical_and_false_critical_counts: HumanAttentionMetricGroup,
    pub pre_exposure_prevention_and_conditional_intervention: HumanAttentionMetricGroup,
    pub final_harm_and_residual_risk: HumanAttentionMetricGroup,
    pub benign_false_blocks_and_abandoned_work: HumanAttentionMetricGroup,
    pub interruption_and_resumption_time_quality: HumanAttentionMetricGroup,
    pub task_correctness_rework_and_human_attention: HumanAttentionMetricGroup,
    pub overtrust_undertrust_and_recoverability_observations: HumanAttentionMetricGroup,
    pub privacy_purpose_retention_and_disclosure_cost: HumanAttentionMetricGroup,
    /// Conclusions drawn from the measurements. Every claim is conditional on
    /// the metrics it names; no claim aggregates dimensions into a ranking.
    pub claims: Vec<HumanAttentionClaim>,
    pub created_at: ClockReading,
    pub expires_at: ClockReading,
    pub predecessor: Option<HumanAttentionEvaluationRevisionRef>,
}

impl HumanAttentionEvaluation {
    /// Checks schema identity, revision lineage, metric completeness, and
    /// source/denominator bindings. This grants no authority or truth status.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.validate_metadata()?;
        self.validate_measurements()?;
        self.validate_claims()?;
        self.validate_manifest_bindings_and_expiry()
    }

    fn validate_metadata(&self) -> Result<(), EvaluationContractError> {
        if self.contract_version != HUMAN_ATTENTION_EVALUATION_CONTRACT_VERSION {
            return Err(EvaluationContractError::InvalidDependency {
                field: "human_attention.contract_version",
                reason: "unsupported Human attention evaluation contract version",
            });
        }
        text(self.evaluation_id.as_str(), "human_attention.evaluation_id")?;
        if self.revision == 0 {
            return Err(EvaluationContractError::InvalidInterval {
                field: "human_attention.revision",
            });
        }
        match (&self.predecessor, self.revision) {
            (None, 1) => {}
            (Some(predecessor), revision)
                if predecessor.evaluation_id == self.evaluation_id
                    && predecessor.revision.checked_add(1) == Some(revision) =>
            {
                predecessor.validate()?;
            }
            _ => {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.predecessor",
                    reason: "revisions after the first must link the immediately preceding revision",
                });
            }
        }

        self.created_at
            .validate()
            .map_err(|_| EvaluationContractError::InvalidDependency {
                field: "human_attention.created_at",
                reason: "invalid clock reading",
            })?;
        self.expires_at
            .validate()
            .map_err(|_| EvaluationContractError::InvalidDependency {
                field: "human_attention.expires_at",
                reason: "invalid clock reading",
            })?;
        if let (Some(created), Some(expires)) =
            (self.created_at.known_time_ms, self.expires_at.known_time_ms)
            && expires <= created
        {
            return Err(EvaluationContractError::InvalidInterval {
                field: "human_attention.created_at/expires_at",
            });
        }

        self.evaluator_scope_uncertainty_and_invalidation
            .validate()?;
        for profile in [
            &self.policy_revision,
            &self.notification_revision,
            &self.approval_revision,
            &self.telemetry_revision,
        ] {
            profile.validate()?;
        }
        self.observation_window.validate()?;
        self.evidence_manifest.validate()?;
        self.method.validate()?;
        Ok(())
    }

    fn validate_measurements(&self) -> Result<(), EvaluationContractError> {
        let scope = &self
            .evaluator_scope_uncertainty_and_invalidation
            .authorized_scope;
        self.policy_and_task_risk_profile.validate(
            HumanAttentionMetricGroupKind::PolicyAndTaskRiskProfile,
            &self.observation_window,
            &self.evidence_manifest,
            scope,
        )?;
        self.notification_approval_and_telemetry_profile.validate(
            HumanAttentionMetricGroupKind::NotificationApprovalAndTelemetryProfile,
            &self.observation_window,
            &self.evidence_manifest,
            scope,
        )?;
        self.missed_critical_and_false_critical_counts.validate(
            HumanAttentionMetricGroupKind::MissedCriticalAndFalseCriticalCounts,
            &self.observation_window,
            &self.evidence_manifest,
            scope,
        )?;
        self.pre_exposure_prevention_and_conditional_intervention
            .validate(
                HumanAttentionMetricGroupKind::PreExposurePreventionAndConditionalIntervention,
                &self.observation_window,
                &self.evidence_manifest,
                scope,
            )?;
        self.final_harm_and_residual_risk.validate(
            HumanAttentionMetricGroupKind::FinalHarmAndResidualRisk,
            &self.observation_window,
            &self.evidence_manifest,
            scope,
        )?;
        self.benign_false_blocks_and_abandoned_work.validate(
            HumanAttentionMetricGroupKind::BenignFalseBlocksAndAbandonedWork,
            &self.observation_window,
            &self.evidence_manifest,
            scope,
        )?;
        self.interruption_and_resumption_time_quality.validate(
            HumanAttentionMetricGroupKind::InterruptionAndResumptionTimeQuality,
            &self.observation_window,
            &self.evidence_manifest,
            scope,
        )?;
        self.task_correctness_rework_and_human_attention.validate(
            HumanAttentionMetricGroupKind::TaskCorrectnessReworkAndHumanAttention,
            &self.observation_window,
            &self.evidence_manifest,
            scope,
        )?;
        self.overtrust_undertrust_and_recoverability_observations
            .validate(
                HumanAttentionMetricGroupKind::OvertrustUndertrustAndRecoverabilityObservations,
                &self.observation_window,
                &self.evidence_manifest,
                scope,
            )?;
        self.privacy_purpose_retention_and_disclosure_cost
            .validate(
                HumanAttentionMetricGroupKind::PrivacyPurposeRetentionAndDisclosureCost,
                &self.observation_window,
                &self.evidence_manifest,
                scope,
            )?;
        Ok(())
    }

    fn validate_manifest_bindings_and_expiry(&self) -> Result<(), EvaluationContractError> {
        let scope = &self
            .evaluator_scope_uncertainty_and_invalidation
            .authorized_scope;
        let mut referenced_evidence = Vec::new();
        referenced_evidence.extend_from_slice(
            &self
                .evaluator_scope_uncertainty_and_invalidation
                .evaluator
                .authority_evidence_refs,
        );
        referenced_evidence.extend_from_slice(&scope.scope_evidence_refs);
        referenced_evidence.extend_from_slice(&scope.risk_population_evidence_refs);
        referenced_evidence.extend_from_slice(
            &self
                .evaluator_scope_uncertainty_and_invalidation
                .uncertainty
                .evidence_refs,
        );
        if let Some(invalidation) = &self
            .evaluator_scope_uncertainty_and_invalidation
            .invalidation
        {
            referenced_evidence.extend_from_slice(&invalidation.evidence_refs);
        }
        for profile in [
            &self.policy_revision,
            &self.notification_revision,
            &self.approval_revision,
            &self.telemetry_revision,
        ] {
            referenced_evidence.extend_from_slice(&profile.evidence_refs);
        }
        for evidence_ref in referenced_evidence {
            if !self.evidence_manifest.contains(&evidence_ref) {
                return Err(EvaluationContractError::InvalidDependency {
                    field: "human_attention.evidence_manifest.evidence_refs",
                    reason: "record evidence reference is absent from the evidence manifest",
                });
            }
        }

        if let (Some(expires), Some(closed)) = (
            self.expires_at.known_time_ms,
            self.observation_window
                .closed_at
                .as_ref()
                .and_then(|reading| reading.known_time_ms),
        ) && expires <= closed
        {
            return Err(EvaluationContractError::InvalidInterval {
                field: "human_attention.observation_window/expires_at",
            });
        }
        Ok(())
    }
}

/// Stable revision link used for correction history.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionEvaluationRevisionRef {
    pub evaluation_id: ContractId,
    pub revision: u64,
}

impl HumanAttentionEvaluationRevisionRef {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(
            self.evaluation_id.as_str(),
            "human_attention.predecessor.evaluation_id",
        )?;
        if self.revision == 0 {
            return Err(EvaluationContractError::InvalidInterval {
                field: "human_attention.predecessor.revision",
            });
        }
        Ok(())
    }
}

/// Evaluator identity plus a declared authority binding and exact scope.
///
/// The contract records an authorization claim and its references; an owner
/// must authenticate and authorize it independently.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorScopeUncertaintyInvalidation {
    pub evaluator: EvaluatorIdentity,
    pub authorized_scope: HumanAttentionEvaluationScope,
    pub uncertainty: HumanAttentionUncertainty,
    pub invalidation: Option<HumanAttentionInvalidation>,
}

impl EvaluatorScopeUncertaintyInvalidation {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        self.evaluator.validate()?;
        self.authorized_scope.validate()?;
        self.uncertainty.validate()?;
        if let Some(invalidation) = &self.invalidation {
            invalidation.validate()?;
        }
        Ok(())
    }
}

/// Identity of the evaluator who assembled the record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorIdentity {
    pub principal_id: String,
    pub role: EvaluatorRole,
    pub authority_evidence_refs: Vec<ArtifactId>,
}

impl EvaluatorIdentity {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.principal_id, "human_attention.evaluator.principal_id")?;
        unique_optional_artifacts(
            &self.authority_evidence_refs,
            "human_attention.evaluator.authority_evidence_refs",
        )
    }
}

/// Roles recorded by an evaluation; this is descriptive and confers no access.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvaluatorRole {
    HumanEvaluator,
    AuthorizedService,
}

/// Task and risk population plus the exact scope claimed by the evaluator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionEvaluationScope {
    pub authorized_scope_refs: Vec<String>,
    pub task_population_refs: Vec<String>,
    pub task_population_coverage: CoverageState,
    pub risk_population_refs: Vec<String>,
    pub risk_population_coverage: CoverageState,
    pub risk_population_evidence_refs: Vec<ArtifactId>,
    pub scope_evidence_refs: Vec<ArtifactId>,
}

impl HumanAttentionEvaluationScope {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        unique_texts(
            &self.authorized_scope_refs,
            "human_attention.scope.authorized_scope_refs",
        )?;
        unique_texts(
            &self.task_population_refs,
            "human_attention.scope.task_population_refs",
        )?;
        if self.task_population_coverage == CoverageState::NotApplicable {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.scope.task_population_coverage",
                reason: "task evaluation scope cannot be not applicable",
            });
        }
        if self.risk_population_refs.is_empty() {
            if !matches!(
                self.risk_population_coverage,
                CoverageState::NotApplicable | CoverageState::Unavailable | CoverageState::Unknown
            ) {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.scope.risk_population_coverage",
                    reason: "an empty risk population requires explicit not-applicable or unavailable coverage",
                });
            }
            if self.risk_population_coverage == CoverageState::NotApplicable
                && self.risk_population_evidence_refs.is_empty()
            {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.scope.risk_population_evidence_refs",
                    reason: "a known empty risk population requires evidence references",
                });
            }
        } else {
            unique_texts(
                &self.risk_population_refs,
                "human_attention.scope.risk_population_refs",
            )?;
            if self.risk_population_coverage == CoverageState::NotApplicable {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.scope.risk_population_coverage",
                    reason: "a populated risk scope cannot be not applicable",
                });
            }
        }
        unique_optional_artifacts(
            &self.risk_population_evidence_refs,
            "human_attention.scope.risk_population_evidence_refs",
        )?;
        unique_optional_artifacts(
            &self.scope_evidence_refs,
            "human_attention.scope.scope_evidence_refs",
        )
    }

    fn population_refs(&self, population: HumanAttentionPopulation) -> &[String] {
        match population {
            HumanAttentionPopulation::Tasks => &self.task_population_refs,
            HumanAttentionPopulation::RiskOpportunities => &self.risk_population_refs,
        }
    }
}

/// Distinct eligible opportunity populations used by measurements. Risk
/// opportunities may yield zero distinct risk events.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanAttentionPopulation {
    Tasks,
    RiskOpportunities,
}

/// Version binding for an evaluated policy/profile input.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRevisionRef {
    pub profile_id: ContractId,
    pub revision: String,
    pub evidence_refs: Vec<ArtifactId>,
}

impl ProfileRevisionRef {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(
            self.profile_id.as_str(),
            "human_attention.profile.profile_id",
        )?;
        text(&self.revision, "human_attention.profile.revision")?;
        unique_optional_artifacts(&self.evidence_refs, "human_attention.profile.evidence_refs")
    }
}

/// Bounded observation interval with explicit status and censoring reason.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionObservationWindow {
    pub specification: ObservationWindowSpec,
    pub opened_at: ClockReading,
    pub closed_at: Option<ClockReading>,
    pub censoring_reason: Option<String>,
}

impl HumanAttentionObservationWindow {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        self.specification.validate()?;
        validate_clock(&self.opened_at, "human_attention.window.opened_at")?;
        if let Some(closed_at) = &self.closed_at {
            validate_clock(closed_at, "human_attention.window.closed_at")?;
            if let (Some(opened), Some(closed)) =
                (self.opened_at.known_time_ms, closed_at.known_time_ms)
                && closed < opened
            {
                return Err(EvaluationContractError::InvalidInterval {
                    field: "human_attention.window.opened_at/closed_at",
                });
            }
        }
        match (
            self.specification.status,
            self.closed_at.as_ref(),
            &self.censoring_reason,
        ) {
            (ObservationWindowStatus::Open, None, None)
            | (
                ObservationWindowStatus::Matured | ObservationWindowStatus::Regressed,
                Some(_),
                None,
            ) => {}
            (ObservationWindowStatus::CensoredOrInconclusive, _, Some(reason)) => {
                text(reason, "human_attention.window.censoring_reason")?;
            }
            _ => {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.window.status",
                    reason: "window status, close time, and censoring reason disagree",
                });
            }
        }
        Ok(())
    }
}

/// Versioned list of evidence artifacts admitted to the record's manifest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionEvidenceManifest {
    pub manifest_id: ContractId,
    pub revision: String,
    pub evidence_refs: Vec<ArtifactId>,
}

impl HumanAttentionEvidenceManifest {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(
            self.manifest_id.as_str(),
            "human_attention.evidence_manifest.manifest_id",
        )?;
        text(&self.revision, "human_attention.evidence_manifest.revision")?;
        unique_optional_artifacts(
            &self.evidence_refs,
            "human_attention.evidence_manifest.evidence_refs",
        )
    }

    fn contains(&self, artifact: &ArtifactId) -> bool {
        self.evidence_refs
            .iter()
            .any(|candidate| candidate == artifact)
    }
}

/// Evaluation method and declared comparison basis, without a superiority claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionMethod {
    pub method_ref: String,
    pub method_description: String,
    pub comparison_basis: ComparisonBasis,
    pub comparator_profile_refs: Vec<String>,
    pub comparison_reason: Option<String>,
}

impl HumanAttentionMethod {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.method_ref, "human_attention.method.method_ref")?;
        text(
            &self.method_description,
            "human_attention.method.method_description",
        )?;
        if !self.comparator_profile_refs.is_empty() {
            unique_texts(
                &self.comparator_profile_refs,
                "human_attention.method.comparator_profile_refs",
            )?;
        }
        match self.comparison_basis {
            ComparisonBasis::None | ComparisonBasis::NotApplicableWithReason => {
                let reason = self.comparison_reason.as_deref().ok_or(
                    EvaluationContractError::EvidenceState {
                        field: "human_attention.method.comparison_reason",
                        reason: "unavailable or inapplicable comparison requires a reason",
                    },
                )?;
                text(reason, "human_attention.method.comparison_reason")?;
            }
            ComparisonBasis::ExactPrechangeBehavior
            | ComparisonBasis::MatchedControl
            | ComparisonBasis::MemoryFreeControl
            | ComparisonBasis::HistoricalReference => {
                if self.comparator_profile_refs.is_empty() {
                    return Err(EvaluationContractError::EmptyCollection {
                        field: "human_attention.method.comparator_profile_refs",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Explicit uncertainty assessment. It has no confidence score.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionUncertainty {
    pub assessment: UncertaintyAssessmentState,
    pub assessment_basis: String,
    pub limitations: Vec<String>,
    pub evidence_refs: Vec<ArtifactId>,
}

impl HumanAttentionUncertainty {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(
            &self.assessment_basis,
            "human_attention.uncertainty.assessment_basis",
        )?;
        if !self.limitations.is_empty() {
            unique_texts(&self.limitations, "human_attention.uncertainty.limitations")?;
        }
        unique_optional_artifacts(
            &self.evidence_refs,
            "human_attention.uncertainty.evidence_refs",
        )?;
        if self.assessment == UncertaintyAssessmentState::NotAssessed && self.limitations.is_empty()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.uncertainty.limitations",
                reason: "unassessed uncertainty requires explicit known limitations or gaps",
            });
        }
        Ok(())
    }
}

/// Whether uncertainty was assessed within the declared scope.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UncertaintyAssessmentState {
    Assessed,
    NotAssessed,
}

/// Append-only invalidation statement; it does not delete or rewrite history.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionInvalidation {
    pub invalidated_at: ClockReading,
    pub affected_scope_refs: Vec<String>,
    pub reason: String,
    pub evidence_refs: Vec<ArtifactId>,
}

impl HumanAttentionInvalidation {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        validate_clock(
            &self.invalidated_at,
            "human_attention.invalidation.invalidated_at",
        )?;
        unique_texts(
            &self.affected_scope_refs,
            "human_attention.invalidation.affected_scope_refs",
        )?;
        text(&self.reason, "human_attention.invalidation.reason")?;
        unique_optional_artifacts(
            &self.evidence_refs,
            "human_attention.invalidation.evidence_refs",
        )
    }
}

/// One required I11.10 metric group.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionMetricGroup {
    pub metrics: Vec<HumanAttentionMetricObservation>,
}

impl HumanAttentionMetricGroup {
    fn validate(
        &self,
        expected_group: HumanAttentionMetricGroupKind,
        window: &HumanAttentionObservationWindow,
        manifest: &HumanAttentionEvidenceManifest,
        scope: &HumanAttentionEvaluationScope,
    ) -> Result<(), EvaluationContractError> {
        if self.metrics.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "human_attention.measurement_group.metrics",
            });
        }
        let mut observed = BTreeSet::new();
        for metric in &self.metrics {
            if metric.metric.group() != expected_group {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.measurement_group.metric",
                    reason: "metric is recorded in the wrong I11.10 group",
                });
            }
            if !observed.insert(metric.metric) {
                return Err(EvaluationContractError::DuplicateIdentity {
                    field: "human_attention.measurement_group.metrics",
                });
            }
            metric.validate(window, manifest, scope)?;
        }
        let required = expected_group.required_metrics();
        if required
            .iter()
            .any(|required_metric| !observed.contains(required_metric))
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.measurement_group.metrics",
                reason: "required I11.10 metrics must be present, including explicit unknowns",
            });
        }
        Ok(())
    }
}

/// Exact required groups from I11.10.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanAttentionMetricGroupKind {
    PolicyAndTaskRiskProfile,
    NotificationApprovalAndTelemetryProfile,
    MissedCriticalAndFalseCriticalCounts,
    PreExposurePreventionAndConditionalIntervention,
    FinalHarmAndResidualRisk,
    BenignFalseBlocksAndAbandonedWork,
    InterruptionAndResumptionTimeQuality,
    TaskCorrectnessReworkAndHumanAttention,
    OvertrustUndertrustAndRecoverabilityObservations,
    PrivacyPurposeRetentionAndDisclosureCost,
}

/// Closed metric key set prevents proxy metrics and conflated event counts.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanAttentionMetric {
    PolicyAndTaskRiskProfile,
    NotificationApprovalAndTelemetryProfile,
    DeduplicatedInboxItems,
    DeliveryAttempts,
    DistinctRiskEvents,
    MissedCriticalRiskEvents,
    FalseCriticalRiskEvents,
    PreExposurePreventionEvents,
    ConditionalInterventionEvents,
    FinalHarmEvents,
    ResidualRiskObservation,
    BenignFalseBlockTasks,
    AbandonedWorkTasks,
    InterruptionDuration,
    ResumptionLatency,
    ResumptionQualityObservation,
    TaskCorrectnessObservation,
    ReworkEvents,
    HumanAttentionObservation,
    OvertrustObservation,
    UndertrustObservation,
    RecoverabilityObservation,
    PrivacyPurposeCost,
    PrivacyRetentionCost,
    PrivacyDisclosureCost,
}

impl HumanAttentionMetric {
    const fn group(self) -> HumanAttentionMetricGroupKind {
        use HumanAttentionMetric as M;
        match self {
            M::PolicyAndTaskRiskProfile => HumanAttentionMetricGroupKind::PolicyAndTaskRiskProfile,
            M::NotificationApprovalAndTelemetryProfile
            | M::DeduplicatedInboxItems
            | M::DeliveryAttempts
            | M::DistinctRiskEvents => {
                HumanAttentionMetricGroupKind::NotificationApprovalAndTelemetryProfile
            }
            M::MissedCriticalRiskEvents | M::FalseCriticalRiskEvents => {
                HumanAttentionMetricGroupKind::MissedCriticalAndFalseCriticalCounts
            }
            M::PreExposurePreventionEvents | M::ConditionalInterventionEvents => {
                HumanAttentionMetricGroupKind::PreExposurePreventionAndConditionalIntervention
            }
            M::FinalHarmEvents | M::ResidualRiskObservation => {
                HumanAttentionMetricGroupKind::FinalHarmAndResidualRisk
            }
            M::BenignFalseBlockTasks | M::AbandonedWorkTasks => {
                HumanAttentionMetricGroupKind::BenignFalseBlocksAndAbandonedWork
            }
            M::InterruptionDuration | M::ResumptionLatency | M::ResumptionQualityObservation => {
                HumanAttentionMetricGroupKind::InterruptionAndResumptionTimeQuality
            }
            M::TaskCorrectnessObservation | M::ReworkEvents | M::HumanAttentionObservation => {
                HumanAttentionMetricGroupKind::TaskCorrectnessReworkAndHumanAttention
            }
            M::OvertrustObservation | M::UndertrustObservation | M::RecoverabilityObservation => {
                HumanAttentionMetricGroupKind::OvertrustUndertrustAndRecoverabilityObservations
            }
            M::PrivacyPurposeCost | M::PrivacyRetentionCost | M::PrivacyDisclosureCost => {
                HumanAttentionMetricGroupKind::PrivacyPurposeRetentionAndDisclosureCost
            }
        }
    }

    const fn required_unit(self) -> MetricUnitClass {
        use HumanAttentionMetric as M;
        match self {
            M::PolicyAndTaskRiskProfile
            | M::NotificationApprovalAndTelemetryProfile
            | M::ResidualRiskObservation
            | M::ResumptionQualityObservation
            | M::TaskCorrectnessObservation
            | M::HumanAttentionObservation
            | M::OvertrustObservation
            | M::UndertrustObservation
            | M::RecoverabilityObservation => MetricUnitClass::Observation,
            M::InterruptionDuration | M::ResumptionLatency => MetricUnitClass::Milliseconds,
            M::PrivacyPurposeCost | M::PrivacyRetentionCost | M::PrivacyDisclosureCost => {
                MetricUnitClass::Named
            }
            M::DeduplicatedInboxItems
            | M::DeliveryAttempts
            | M::DistinctRiskEvents
            | M::MissedCriticalRiskEvents
            | M::FalseCriticalRiskEvents
            | M::PreExposurePreventionEvents
            | M::ConditionalInterventionEvents
            | M::FinalHarmEvents
            | M::BenignFalseBlockTasks
            | M::AbandonedWorkTasks
            | M::ReworkEvents => MetricUnitClass::Count,
        }
    }

    const fn population(self) -> HumanAttentionPopulation {
        use HumanAttentionMetric as M;
        match self {
            M::DistinctRiskEvents
            | M::MissedCriticalRiskEvents
            | M::FalseCriticalRiskEvents
            | M::PreExposurePreventionEvents
            | M::ConditionalInterventionEvents
            | M::FinalHarmEvents
            | M::ResidualRiskObservation => HumanAttentionPopulation::RiskOpportunities,
            _ => HumanAttentionPopulation::Tasks,
        }
    }
}

impl HumanAttentionMetricGroupKind {
    const fn required_metrics(self) -> &'static [HumanAttentionMetric] {
        use HumanAttentionMetric as M;
        use HumanAttentionMetricGroupKind as G;
        match self {
            G::PolicyAndTaskRiskProfile => &[M::PolicyAndTaskRiskProfile],
            G::NotificationApprovalAndTelemetryProfile => &[
                M::NotificationApprovalAndTelemetryProfile,
                M::DeduplicatedInboxItems,
                M::DeliveryAttempts,
                M::DistinctRiskEvents,
            ],
            G::MissedCriticalAndFalseCriticalCounts => {
                &[M::MissedCriticalRiskEvents, M::FalseCriticalRiskEvents]
            }
            G::PreExposurePreventionAndConditionalIntervention => &[
                M::PreExposurePreventionEvents,
                M::ConditionalInterventionEvents,
            ],
            G::FinalHarmAndResidualRisk => &[M::FinalHarmEvents, M::ResidualRiskObservation],
            G::BenignFalseBlocksAndAbandonedWork => {
                &[M::BenignFalseBlockTasks, M::AbandonedWorkTasks]
            }
            G::InterruptionAndResumptionTimeQuality => &[
                M::InterruptionDuration,
                M::ResumptionLatency,
                M::ResumptionQualityObservation,
            ],
            G::TaskCorrectnessReworkAndHumanAttention => &[
                M::TaskCorrectnessObservation,
                M::ReworkEvents,
                M::HumanAttentionObservation,
            ],
            G::OvertrustUndertrustAndRecoverabilityObservations => &[
                M::OvertrustObservation,
                M::UndertrustObservation,
                M::RecoverabilityObservation,
            ],
            G::PrivacyPurposeRetentionAndDisclosureCost => &[
                M::PrivacyPurposeCost,
                M::PrivacyRetentionCost,
                M::PrivacyDisclosureCost,
            ],
        }
    }
}

/// Physical unit; privacy cost requires a named, explicit unit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", content = "name")]
pub enum HumanAttentionMetricUnit {
    Count,
    Milliseconds,
    Observation,
    Named(String),
}

/// A complete opportunity denominator or an explicitly unavailable/empty
/// population. Missing outcomes keep their complete opportunity denominator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum HumanAttentionMetricDenominator {
    DecisionOpportunities {
        denominator: Box<DecisionOpportunityDenominator>,
    },
    NoEligibleOpportunities {
        reason: String,
        evidence_refs: Vec<ArtifactId>,
    },
    PopulationUnavailable {
        coverage: CoverageState,
        reason: String,
        evidence_refs: Vec<ArtifactId>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetricUnitClass {
    Count,
    Milliseconds,
    Observation,
    Named,
}

impl HumanAttentionMetricUnit {
    fn class(&self) -> MetricUnitClass {
        match self {
            Self::Count => MetricUnitClass::Count,
            Self::Milliseconds => MetricUnitClass::Milliseconds,
            Self::Observation => MetricUnitClass::Observation,
            Self::Named(_) => MetricUnitClass::Named,
        }
    }

    fn validate(&self) -> Result<(), EvaluationContractError> {
        if let Self::Named(name) = self {
            text(name, "human_attention.metric.unit")?;
        }
        Ok(())
    }
}

/// One interpretable measurement with its full denominator and provenance.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionMetricObservation {
    pub metric: HumanAttentionMetric,
    pub value: HumanAttentionMetricValue,
    pub unit: HumanAttentionMetricUnit,
    pub observation_window_ref: ContractId,
    pub population: HumanAttentionPopulation,
    pub denominator: HumanAttentionMetricDenominator,
    pub source_refs: Vec<HumanAttentionMetricSourceRef>,
    pub coverage: CoverageState,
}

impl HumanAttentionMetricObservation {
    fn validate(
        &self,
        window: &HumanAttentionObservationWindow,
        manifest: &HumanAttentionEvidenceManifest,
        scope: &HumanAttentionEvaluationScope,
    ) -> Result<(), EvaluationContractError> {
        text(
            self.observation_window_ref.as_str(),
            "human_attention.metric.observation_window_ref",
        )?;
        if self.observation_window_ref != window.specification.window_id {
            return Err(EvaluationContractError::InvalidDependency {
                field: "human_attention.metric.observation_window_ref",
                reason: "metric window must bind the record observation window",
            });
        }
        if self.population != self.metric.population() {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.metric.population",
                reason: "metric population does not match its typed metric",
            });
        }
        self.validate_denominator(scope, manifest)?;
        self.validate_value_and_sources(manifest)
    }

    fn validate_denominator(
        &self,
        scope: &HumanAttentionEvaluationScope,
        manifest: &HumanAttentionEvidenceManifest,
    ) -> Result<(), EvaluationContractError> {
        let scope_population = scope.population_refs(self.population);
        match (&self.denominator, self.population, &self.value) {
            (HumanAttentionMetricDenominator::DecisionOpportunities { denominator }, _, _) => {
                denominator.validate()?;
                let denominator_population: BTreeSet<&str> = denominator
                    .eligible_subject_refs
                    .iter()
                    .map(String::as_str)
                    .collect();
                let declared_population: BTreeSet<&str> =
                    scope_population.iter().map(String::as_str).collect();
                if declared_population.is_empty() || denominator_population != declared_population {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "human_attention.metric.denominator.eligible_subject_refs",
                        reason: "metric denominator must retain the complete declared task or risk population",
                    });
                }
                if self.coverage == CoverageState::Complete
                    && denominator.coverage_state != CoverageState::Complete
                {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "human_attention.metric.coverage",
                        reason: "complete metric coverage requires a complete denominator",
                    });
                }
                let population_coverage = match self.population {
                    HumanAttentionPopulation::Tasks => scope.task_population_coverage,
                    HumanAttentionPopulation::RiskOpportunities => scope.risk_population_coverage,
                };
                if self.coverage == CoverageState::Complete
                    && population_coverage != CoverageState::Complete
                {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "human_attention.metric.coverage",
                        reason: "complete metric coverage requires a complete declared population",
                    });
                }
                if matches!(
                    self.coverage,
                    CoverageState::Unavailable | CoverageState::Unknown
                ) && !matches!(&self.value, HumanAttentionMetricValue::Unknown { .. })
                {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "human_attention.metric.value",
                        reason: "unavailable or unknown collection cannot assert an observed value",
                    });
                }
            }
            (
                HumanAttentionMetricDenominator::NoEligibleOpportunities {
                    reason,
                    evidence_refs,
                },
                HumanAttentionPopulation::RiskOpportunities,
                HumanAttentionMetricValue::NotApplicable { .. },
            ) if scope.risk_population_refs.is_empty()
                && scope.risk_population_coverage == CoverageState::NotApplicable
                && self.coverage == CoverageState::NotApplicable =>
            {
                text(reason, "human_attention.metric.denominator.reason")?;
                validate_required_manifest_refs(evidence_refs, manifest)?;
            }
            (
                HumanAttentionMetricDenominator::PopulationUnavailable {
                    coverage,
                    reason,
                    evidence_refs,
                },
                HumanAttentionPopulation::RiskOpportunities,
                HumanAttentionMetricValue::Unknown { .. },
            ) if scope.risk_population_refs.is_empty()
                && matches!(
                    coverage,
                    CoverageState::Unavailable | CoverageState::Unknown
                )
                && scope.risk_population_coverage == *coverage
                && self.coverage == *coverage =>
            {
                text(reason, "human_attention.metric.denominator.reason")?;
                validate_manifest_refs(evidence_refs, manifest)?;
            }
            _ => {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.metric.denominator",
                    reason: "denominator state does not match the declared eligible population and value status",
                });
            }
        }
        Ok(())
    }

    fn validate_value_and_sources(
        &self,
        manifest: &HumanAttentionEvidenceManifest,
    ) -> Result<(), EvaluationContractError> {
        if self.unit.class() != self.metric.required_unit() {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.metric.unit",
                reason: "metric unit does not match its typed metric",
            });
        }
        self.unit.validate()?;
        self.value.validate(&self.unit)?;
        if matches!(&self.value, HumanAttentionMetricValue::Unknown { .. })
            && self.coverage == CoverageState::Complete
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.metric.coverage",
                reason: "an unknown value cannot claim complete metric coverage",
            });
        }
        if matches!(&self.value, HumanAttentionMetricValue::NotApplicable { .. })
            && self.coverage != CoverageState::NotApplicable
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.metric.coverage",
                reason: "a not-applicable value requires not-applicable metric coverage",
            });
        }
        if !self.source_refs.is_empty() {
            let ids: Vec<String> = self
                .source_refs
                .iter()
                .map(|source| source.evidence_ref.to_string())
                .collect();
            unique_texts(&ids, "human_attention.metric.source_refs")?;
        }
        for source in &self.source_refs {
            if !manifest.contains(&source.evidence_ref) {
                return Err(EvaluationContractError::InvalidDependency {
                    field: "human_attention.metric.source_refs",
                    reason: "metric source is absent from the evidence manifest",
                });
            }
            source.validate_for(self.metric)?;
        }
        if matches!(
            &self.value,
            HumanAttentionMetricValue::ObservedNumber { .. }
                | HumanAttentionMetricValue::ObservedText { .. }
        ) && self.source_refs.is_empty()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.metric.source_refs",
                reason: "an observed metric requires source references",
            });
        }
        if self.coverage == CoverageState::NotApplicable
            && !matches!(&self.value, HumanAttentionMetricValue::NotApplicable { .. })
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.metric.value",
                reason: "not-applicable coverage requires a not-applicable value",
            });
        }
        Ok(())
    }
}

/// Measurement value, including explicit missingness. Numeric zero is an
/// ordinary observed number and is distinct from both Unknown and N/A.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum HumanAttentionMetricValue {
    ObservedNumber {
        coefficient: i64,
        decimal_places: u32,
    },
    ObservedText {
        observation: String,
    },
    Unknown {
        reason: String,
    },
    NotApplicable {
        reason: String,
    },
}

impl HumanAttentionMetricValue {
    fn validate(&self, unit: &HumanAttentionMetricUnit) -> Result<(), EvaluationContractError> {
        match self {
            Self::ObservedNumber {
                coefficient,
                decimal_places,
            } => {
                if matches!(unit, HumanAttentionMetricUnit::Observation)
                    || (matches!(
                        unit,
                        HumanAttentionMetricUnit::Count | HumanAttentionMetricUnit::Milliseconds
                    ) && (*coefficient < 0 || *decimal_places != 0))
                {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "human_attention.metric.value",
                        reason: "numeric value is incompatible with its unit",
                    });
                }
            }
            Self::ObservedText { observation } => {
                if !matches!(unit, HumanAttentionMetricUnit::Observation) {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "human_attention.metric.value",
                        reason: "text observations require the observation unit",
                    });
                }
                text(observation, "human_attention.metric.observation")?;
            }
            Self::Unknown { reason } | Self::NotApplicable { reason } => {
                text(reason, "human_attention.metric.missingness_reason")?;
            }
        }
        Ok(())
    }
}

/// Typed origin class for metric evidence; interaction proxies are not an
/// admitted origin for attention, trust, or task correctness.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanAttentionEvidenceKind {
    PolicyProfile,
    TaskRiskProfile,
    NotificationLifecycle,
    DeliveryAttempt,
    RiskEvent,
    ApprovalRecord,
    TelemetryCollection,
    TaskOutcome,
    TaskVerifier,
    HumanReport,
    InterruptionMeasurement,
    RecoverabilityAssessment,
    PrivacyAssessment,
}

/// Evidence artifact reference and typed evidence role.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionMetricSourceRef {
    pub evidence_ref: ArtifactId,
    pub kind: HumanAttentionEvidenceKind,
}

impl HumanAttentionMetricSourceRef {
    fn validate_for(&self, metric: HumanAttentionMetric) -> Result<(), EvaluationContractError> {
        use HumanAttentionEvidenceKind as K;
        use HumanAttentionMetric as M;
        let permitted = match metric {
            M::HumanAttentionObservation | M::OvertrustObservation | M::UndertrustObservation => {
                matches!(self.kind, K::HumanReport)
            }
            M::TaskCorrectnessObservation | M::ReworkEvents => {
                matches!(self.kind, K::TaskOutcome | K::TaskVerifier)
            }
            M::ResumptionQualityObservation => {
                matches!(self.kind, K::HumanReport | K::InterruptionMeasurement)
            }
            M::RecoverabilityObservation => {
                matches!(self.kind, K::RecoverabilityAssessment | K::HumanReport)
            }
            M::PolicyAndTaskRiskProfile => {
                matches!(self.kind, K::PolicyProfile | K::TaskRiskProfile)
            }
            M::NotificationApprovalAndTelemetryProfile => matches!(
                self.kind,
                K::NotificationLifecycle | K::ApprovalRecord | K::TelemetryCollection
            ),
            M::DeduplicatedInboxItems => matches!(self.kind, K::NotificationLifecycle),
            M::DeliveryAttempts => matches!(self.kind, K::DeliveryAttempt),
            M::DistinctRiskEvents
            | M::MissedCriticalRiskEvents
            | M::FalseCriticalRiskEvents
            | M::PreExposurePreventionEvents
            | M::ConditionalInterventionEvents
            | M::FinalHarmEvents
            | M::ResidualRiskObservation => matches!(self.kind, K::RiskEvent),
            M::BenignFalseBlockTasks | M::AbandonedWorkTasks => {
                matches!(self.kind, K::TaskOutcome | K::TaskVerifier)
            }
            M::InterruptionDuration | M::ResumptionLatency => {
                matches!(self.kind, K::InterruptionMeasurement)
            }
            M::PrivacyPurposeCost | M::PrivacyRetentionCost | M::PrivacyDisclosureCost => {
                matches!(self.kind, K::PrivacyAssessment | K::TelemetryCollection)
            }
        };
        if !permitted {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.metric.source_refs.kind",
                reason: "evidence role is not admissible for this metric",
            });
        }
        Ok(())
    }
}

/// One conclusion drawn from the record's measurements.
///
/// A claim names the metrics it rests on; it never carries an aggregate
/// ranking, and a difference, prevention, or false-negative claim is admissible
/// only on a declared matched or paired profile with applicable task-risk and
/// exposure context.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionClaim {
    pub claim_ref: String,
    pub kind: HumanAttentionClaimKind,
    pub statement: String,
    /// Metrics this claim actually reads. Each must be measured by this record
    /// with an observed value; an unknown cannot support a conclusion.
    pub supporting_metrics: Vec<HumanAttentionMetric>,
    pub basis: HumanAttentionClaimBasis,
}

/// Closed claim kinds. There is no superiority or overall-ranking kind, so a
/// profile with fewer notifications cannot be recorded as simply better.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanAttentionClaimKind {
    /// What was observed on the evaluated profile, with no control.
    DescriptiveObservation,
    /// An observed difference against the declared comparator profile.
    ComparativeDifference,
    /// Harm a stricter policy is credited with preventing.
    AttributedPrevention,
    /// Risk events a suppression policy failed to surface.
    SuppressionFalseNegative,
}

impl HumanAttentionClaimKind {
    /// The measured count a claim of this kind must name, so a prevented action
    /// is credited from an observed pre-exposure prevention count and a
    /// suppression false-negative rate from an observed missed-critical count,
    /// never from a lower blocking, harm, or alert figure.
    const fn required_evidence_metric(self) -> Option<HumanAttentionMetric> {
        match self {
            Self::DescriptiveObservation | Self::ComparativeDifference => None,
            Self::AttributedPrevention => Some(HumanAttentionMetric::PreExposurePreventionEvents),
            Self::SuppressionFalseNegative => Some(HumanAttentionMetric::MissedCriticalRiskEvents),
        }
    }
}

/// The evidence posture a claim requires.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum HumanAttentionClaimBasis {
    /// A descriptive record is useful on its own and asserts no difference.
    Descriptive { observation_window_ref: ContractId },
    /// A comparative claim, conditional on the declared matched or paired
    /// profile and on the task-risk and exposure context it applies to.
    Comparative {
        matched_profile_ref: String,
        applicability: HumanAttentionClaimApplicability,
        caveats: Vec<HumanAttentionClaimCaveat>,
    },
}

/// The task-risk and exposure context a comparative conclusion applies to.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionClaimApplicability {
    pub task_risk_context: String,
    pub exposure_context: String,
}

/// Selection bias, censoring, intervention effect, and alternative
/// explanations are preserved on every comparative conclusion.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum HumanAttentionClaimCaveat {
    SelectionBias { statement: String },
    Censoring { statement: String },
    InterventionEffect { statement: String },
    AlternativeExplanation { statement: String },
}

impl HumanAttentionClaimCaveat {
    const fn label(&self) -> &'static str {
        match self {
            Self::SelectionBias { .. } => "selection_bias",
            Self::Censoring { .. } => "censoring",
            Self::InterventionEffect { .. } => "intervention_effect",
            Self::AlternativeExplanation { .. } => "alternative_explanation",
        }
    }

    fn statement(&self) -> &str {
        match self {
            Self::SelectionBias { statement }
            | Self::Censoring { statement }
            | Self::InterventionEffect { statement }
            | Self::AlternativeExplanation { statement } => statement,
        }
    }
}

impl HumanAttentionClaim {
    fn validate(
        &self,
        method: &HumanAttentionMethod,
        window: &HumanAttentionObservationWindow,
    ) -> Result<(), EvaluationContractError> {
        text(&self.claim_ref, "human_attention.claim.claim_ref")?;
        text(&self.statement, "human_attention.claim.statement")?;
        if self.supporting_metrics.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "human_attention.claim.supporting_metrics",
            });
        }
        let mut named = BTreeSet::new();
        if self.supporting_metrics.iter().any(|m| !named.insert(*m)) {
            return Err(EvaluationContractError::DuplicateIdentity {
                field: "human_attention.claim.supporting_metrics",
            });
        }
        match (&self.basis, self.kind) {
            (
                HumanAttentionClaimBasis::Descriptive {
                    observation_window_ref,
                },
                HumanAttentionClaimKind::DescriptiveObservation,
            ) => {
                if *observation_window_ref != window.specification.window_id {
                    return Err(EvaluationContractError::InvalidDependency {
                        field: "human_attention.claim.basis.observation_window_ref",
                        reason: "a descriptive claim must bind the record observation window",
                    });
                }
            }
            (
                HumanAttentionClaimBasis::Comparative {
                    matched_profile_ref,
                    applicability,
                    caveats,
                },
                kind,
            ) => {
                self.validate_comparative(
                    kind,
                    matched_profile_ref,
                    applicability,
                    caveats,
                    method,
                )?;
            }
            _ => {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.claim.basis",
                    reason: "only a descriptive observation may stand without a comparator profile",
                });
            }
        }
        Ok(())
    }

    fn validate_comparative(
        &self,
        kind: HumanAttentionClaimKind,
        matched_profile_ref: &str,
        applicability: &HumanAttentionClaimApplicability,
        caveats: &[HumanAttentionClaimCaveat],
        method: &HumanAttentionMethod,
    ) -> Result<(), EvaluationContractError> {
        if kind == HumanAttentionClaimKind::DescriptiveObservation {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.claim.kind",
                reason: "a comparator profile does not make a description a difference",
            });
        }
        text(
            matched_profile_ref,
            "human_attention.claim.basis.matched_profile_ref",
        )?;
        if matches!(
            method.comparison_basis,
            ComparisonBasis::None | ComparisonBasis::NotApplicableWithReason
        ) {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.method.comparison_basis",
                reason: "a comparative conclusion requires a declared comparison basis",
            });
        }
        if !method
            .comparator_profile_refs
            .iter()
            .any(|profile| profile == matched_profile_ref)
        {
            return Err(EvaluationContractError::InvalidDependency {
                field: "human_attention.claim.basis.matched_profile_ref",
                reason: "a comparative claim must name a profile declared by the record method",
            });
        }
        text(
            &applicability.task_risk_context,
            "human_attention.claim.basis.applicability.task_risk_context",
        )?;
        text(
            &applicability.exposure_context,
            "human_attention.claim.basis.applicability.exposure_context",
        )?;

        for required in [
            "selection_bias",
            "censoring",
            "intervention_effect",
            "alternative_explanation",
        ] {
            if !caveats.iter().any(|caveat| caveat.label() == required) {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.claim.basis.caveats",
                    reason: "a comparative conclusion must preserve every declared caveat",
                });
            }
        }
        let mut seen = BTreeSet::new();
        for caveat in caveats {
            if !seen.insert(caveat.label()) {
                return Err(EvaluationContractError::DuplicateIdentity {
                    field: "human_attention.claim.basis.caveats",
                });
            }
            text(
                caveat.statement(),
                "human_attention.claim.basis.caveats.statement",
            )?;
        }

        self.validate_kind_evidence(kind)
    }

    /// A prevented action is credited only from an observed pre-exposure
    /// prevention count, and a suppression false-negative rate only from an
    /// observed missed-critical count. Neither is inferred from a lower
    /// blocking, harm, or alert figure.
    fn validate_kind_evidence(
        &self,
        kind: HumanAttentionClaimKind,
    ) -> Result<(), EvaluationContractError> {
        if let Some(required_metric) = kind.required_evidence_metric()
            && !self.supporting_metrics.contains(&required_metric)
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.claim.supporting_metrics",
                reason: "the claim must name the measured risk or prevention count it rests on",
            });
        }
        if self
            .supporting_metrics
            .iter()
            .all(|m| m.is_volume_or_profile_shape())
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.claim.supporting_metrics",
                reason: "volume and profile shape alone support no conclusion",
            });
        }
        Ok(())
    }
}

impl HumanAttentionMetric {
    /// Volume, delivery, and profile-shape metrics. They describe how much
    /// attention a policy asked for, not what it achieved, so they can never
    /// be the sole support of a comparative conclusion.
    const fn is_volume_or_profile_shape(self) -> bool {
        use HumanAttentionMetric as M;
        matches!(
            self,
            M::DeduplicatedInboxItems
                | M::DeliveryAttempts
                | M::NotificationApprovalAndTelemetryProfile
                | M::PolicyAndTaskRiskProfile
        )
    }
}

impl HumanAttentionEvaluation {
    /// Every claim rests only on metrics this record measured with an observed
    /// value; an unknown or not-applicable measurement supports no conclusion.
    fn validate_claims(&self) -> Result<(), EvaluationContractError> {
        let mut seen = BTreeSet::new();
        for claim in &self.claims {
            if !seen.insert(claim.claim_ref.as_str()) {
                return Err(EvaluationContractError::DuplicateIdentity {
                    field: "human_attention.claims.claim_ref",
                });
            }
            claim.validate(&self.method, &self.observation_window)?;
            for metric in &claim.supporting_metrics {
                let Some(observation) = self.observation_for(*metric) else {
                    return Err(EvaluationContractError::InvalidDependency {
                        field: "human_attention.claim.supporting_metrics",
                        reason: "the claim names a metric this record does not measure",
                    });
                };
                if matches!(
                    &observation.value,
                    HumanAttentionMetricValue::Unknown { .. }
                        | HumanAttentionMetricValue::NotApplicable { .. }
                ) {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "human_attention.claim.supporting_metrics",
                        reason: "an unknown measurement cannot support a conclusion",
                    });
                }
            }
        }
        Ok(())
    }

    fn observation_for(
        &self,
        metric: HumanAttentionMetric,
    ) -> Option<&HumanAttentionMetricObservation> {
        [
            &self.policy_and_task_risk_profile,
            &self.notification_approval_and_telemetry_profile,
            &self.missed_critical_and_false_critical_counts,
            &self.pre_exposure_prevention_and_conditional_intervention,
            &self.final_harm_and_residual_risk,
            &self.benign_false_blocks_and_abandoned_work,
            &self.interruption_and_resumption_time_quality,
            &self.task_correctness_rework_and_human_attention,
            &self.overtrust_undertrust_and_recoverability_observations,
            &self.privacy_purpose_retention_and_disclosure_cost,
        ]
        .iter()
        .flat_map(|group| group.metrics.iter())
        .find(|observation| observation.metric == metric)
    }
}

fn validate_clock(
    reading: &ClockReading,
    field: &'static str,
) -> Result<(), EvaluationContractError> {
    reading
        .validate()
        .map_err(|_| EvaluationContractError::InvalidDependency {
            field,
            reason: "invalid clock reading",
        })
}

fn unique_optional_artifacts(
    values: &[ArtifactId],
    field: &'static str,
) -> Result<(), EvaluationContractError> {
    if values.is_empty() {
        return Ok(());
    }
    let ids: Vec<String> = values.iter().map(ToString::to_string).collect();
    unique_texts(&ids, field)
}

fn validate_manifest_refs(
    values: &[ArtifactId],
    manifest: &HumanAttentionEvidenceManifest,
) -> Result<(), EvaluationContractError> {
    unique_optional_artifacts(values, "human_attention.metric.denominator.evidence_refs")?;
    if values
        .iter()
        .any(|evidence_ref| !manifest.contains(evidence_ref))
    {
        return Err(EvaluationContractError::InvalidDependency {
            field: "human_attention.metric.denominator.evidence_refs",
            reason: "denominator source is absent from the evidence manifest",
        });
    }
    Ok(())
}

fn validate_required_manifest_refs(
    values: &[ArtifactId],
    manifest: &HumanAttentionEvidenceManifest,
) -> Result<(), EvaluationContractError> {
    if values.is_empty() {
        return Err(EvaluationContractError::EmptyCollection {
            field: "human_attention.metric.denominator.evidence_refs",
        });
    }
    validate_manifest_refs(values, manifest)
}

// ---------------------------------------------------------------------------
// Bounded owner-evidence producer/assembly (issue #1784 item W3).
//
// The assembly is a pure, store-neutral producer step owned by the shared
// evaluation contracts. It turns caller-nominated owner evidence into the ten
// required I11.10 metric groups with consistent source-revision and
// evaluation-window bindings, so the Governor evaluation integration can admit
// an assembled candidate onto the persist path without touching owner stores.
//
// Authority and access posture (I11.8): the caller nominates evidence, and
// nomination authorizes nothing. This section performs no authentication, no
// capability check, no owner read, and no completeness attestation: every
// admitted reference stays caller-asserted, admissibility is re-checked per
// metric by evidence kind, and any unavailable observation becomes an explicit
// unknown with an exact gap. The Governor admits semantics, the Kernel checks
// the current fence and mediates persistence, and the Store commits.
//
// Measurement posture (I11.7, I11.10): an observed zero is an ordinary
// observed count and is distinct from missing collection; unavailable evidence
// yields `Unknown` values plus [`HumanAttentionEvidenceGap`] entries, never
// synthetic zeros. Attention, trust, and recoverability observations admit
// only `HumanReport` evidence: there is no interaction, click, or silence
// input anywhere in this section, so attention is never inferred from a click
// or from the absence of complaint. No score is computed, aggregated, or
// ranked; comparative conclusions stay with the claim layer (item W4).
//
// The assembly performs no telemetry collection, no model call, and no job
// admission; it is a total function over its input and returns typed
// [`EvaluationContractError`] failures instead of panicking.
// ---------------------------------------------------------------------------

/// Closed names for the bounded owner reads an assembly consumes.
///
/// Each name identifies one owner-side read by role, never by store path or
/// live handle. The caller nominates already-admitted evidence for a read;
/// nomination authorizes no access and establishes no completeness.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanAttentionEvidenceRead {
    /// Notification delivery attempts (I11.7 delivery outcomes).
    NotificationDelivery,
    /// Per-item inbox disposition completeness (I11.7 persistent obligations).
    NotificationDisposition,
    /// Approvals with exact action scope and expiry (I11.10).
    ExpiringApproval,
    /// Task outcomes: blocks, abandonment, and rework.
    TaskOutcome,
    /// Task verifier observations: correctness evidence.
    TaskVerifier,
    /// Risk and outcome events: harm, prevention, and intervention counts.
    RiskEventOutcome,
    /// Human reports: attention, trust, recoverability, resumption quality.
    HumanReport,
    /// Interruption and resumption measurements.
    InterruptionMeasurement,
    /// Privacy assessments and purpose/retention/disclosure cost.
    PrivacyRecord,
    /// Evaluated policy profile revision.
    PolicyProfile,
    /// Task and risk population profile revision.
    TaskRiskProfile,
    /// Telemetry collection revision bound to profile and privacy evidence.
    TelemetryCollection,
}

/// One exact evidence gap: the named read, the affected metric slot, and the
/// caller-supplied reason the observation is unavailable.
///
/// Gaps are first-class assembly output. They never become zeros, and a
/// non-empty gap list marks the assembled evidence partial.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionEvidenceGap {
    pub read: HumanAttentionEvidenceRead,
    pub metric: HumanAttentionMetric,
    pub reason: String,
}

/// The exact source revision bound for one named read used by an assembly.
///
/// The same read may bind two revisions when two owners contribute (for
/// example telemetry revisions from the approval and privacy owners); each
/// binding records which owner revision was nominated.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionSourceBinding {
    pub read: HumanAttentionEvidenceRead,
    pub source_revision: String,
}

/// A nominated count: an observed value, or the exact reason it is
/// unavailable. An observed zero is an observation; missing collection is
/// never encoded as zero.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NominatedCountObservation {
    pub observed: Option<u64>,
    pub unavailable_reason: Option<String>,
}

/// A nominated text observation: an observed statement, or the exact reason
/// it is unavailable. A blank statement is refused; nominate unavailability
/// instead.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NominatedTextObservation {
    pub observed: Option<String>,
    pub unavailable_reason: Option<String>,
}

/// A nominated privacy cost with its explicit named unit. The unit is always
/// required because cost counts are meaningless without it; the value is an
/// observed count or an exact unavailability reason.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NominatedPrivacyCostObservation {
    pub unit: String,
    pub observed: Option<u64>,
    pub unavailable_reason: Option<String>,
}

/// Nominated notification evidence: delivery attempts and inbox disposition.
///
/// Delivery and disposition are distinct owner reads with distinct revisions;
/// deduplicated inbox items, delivery attempts, and distinct risk events stay
/// distinct counts.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionNotificationEvidence {
    pub delivery_source_revision: String,
    pub disposition_source_revision: String,
    pub evidence_refs: Vec<HumanAttentionMetricSourceRef>,
    pub deduplicated_inbox_items: NominatedCountObservation,
    pub delivery_attempts: NominatedCountObservation,
}

/// Nominated approval evidence: the exact expiring-approval boundary posture.
///
/// The profile observation describes the admitted approval boundary (exact
/// scope and expiry); its sources join notification and telemetry references
/// into one joint posture over the notification/approval/telemetry profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionApprovalEvidence {
    pub approval_source_revision: String,
    pub telemetry_source_revision: String,
    pub evidence_refs: Vec<HumanAttentionMetricSourceRef>,
    pub notification_approval_telemetry_profile: NominatedTextObservation,
}

/// Nominated task outcomes: benign false blocks, abandoned work, and rework.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionTaskOutcomeEvidence {
    pub task_source_revision: String,
    pub evidence_refs: Vec<HumanAttentionMetricSourceRef>,
    pub benign_false_block_tasks: NominatedCountObservation,
    pub abandoned_work_tasks: NominatedCountObservation,
    pub rework_events: NominatedCountObservation,
}

/// Nominated task-verifier evidence: correctness observations.
///
/// Verifier references may additionally source the task-outcome counts; the
/// correctness text itself is owned by this read for gap naming.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionTaskVerifierEvidence {
    pub verifier_source_revision: String,
    pub evidence_refs: Vec<HumanAttentionMetricSourceRef>,
    pub task_correctness_observation: NominatedTextObservation,
}

/// Nominated risk and outcome events: distinct, missed, and false-critical
/// risk, pre-exposure prevention versus conditional intervention, final harm,
/// and residual risk.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionRiskOutcomeEvidence {
    pub risk_source_revision: String,
    pub evidence_refs: Vec<HumanAttentionMetricSourceRef>,
    pub distinct_risk_events: NominatedCountObservation,
    pub missed_critical_risk_events: NominatedCountObservation,
    pub false_critical_risk_events: NominatedCountObservation,
    pub pre_exposure_prevention_events: NominatedCountObservation,
    pub conditional_intervention_events: NominatedCountObservation,
    pub final_harm_events: NominatedCountObservation,
    pub residual_risk_observation: NominatedTextObservation,
}

/// Nominated Human reports: attention, trust, recoverability, and resumption
/// quality.
///
/// These slots admit only `HumanReport` evidence (recoverability additionally
/// admits interruption measurements). No click, acknowledgement, or silence
/// signal is an input here, so no assembly output can infer attention, trust,
/// or task success from interaction proxies.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionHumanReportEvidence {
    pub report_source_revision: String,
    pub evidence_refs: Vec<HumanAttentionMetricSourceRef>,
    pub human_attention_observation: NominatedTextObservation,
    pub overtrust_observation: NominatedTextObservation,
    pub undertrust_observation: NominatedTextObservation,
    pub recoverability_observation: NominatedTextObservation,
    pub resumption_quality_observation: NominatedTextObservation,
}

/// Nominated interruption measurements: durations and resumption latency.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionInterruptionEvidence {
    pub measurement_source_revision: String,
    pub evidence_refs: Vec<HumanAttentionMetricSourceRef>,
    pub interruption_duration_ms: NominatedCountObservation,
    pub resumption_latency_ms: NominatedCountObservation,
}

/// Nominated privacy evidence: purpose, retention, and disclosure cost with
/// explicit named units.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionPrivacyEvidence {
    pub privacy_source_revision: String,
    pub telemetry_source_revision: String,
    pub evidence_refs: Vec<HumanAttentionMetricSourceRef>,
    pub purpose_cost: NominatedPrivacyCostObservation,
    pub retention_cost: NominatedPrivacyCostObservation,
    pub disclosure_cost: NominatedPrivacyCostObservation,
}

/// Nominated profile evidence: the evaluated policy and task/risk posture.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionProfileEvidence {
    pub policy_source_revision: String,
    pub task_risk_source_revision: String,
    pub evidence_refs: Vec<HumanAttentionMetricSourceRef>,
    pub policy_and_task_risk_profile: NominatedTextObservation,
}

/// Caller-framed denominator provenance for one opportunity population.
///
/// The eligible subjects always come from the bound evaluation scope; this
/// framing supplies the observable boundaries, blind intervals, and the exact
/// denominator source and revision the caller read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionDenominatorFraming {
    pub observable_boundaries: Vec<String>,
    pub unobservable_boundaries_and_blind_intervals: Vec<String>,
    pub denominator_source_and_revision: String,
}

/// Complete caller-nominated input for one assembly.
///
/// Every field is caller-asserted: nomination authorizes no access and
/// establishes no completeness. Failing or inaccessible owner reads are
/// expressed as unavailable slots with exact reasons, never as zeros or
/// invented continuity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionAssemblyInput {
    /// The evaluation window every assembled observation binds.
    pub observation_window: HumanAttentionObservationWindow,
    /// The authorized scope whose populations bind every denominator.
    pub evaluation_scope: HumanAttentionEvaluationScope,
    pub manifest_id: ContractId,
    pub manifest_revision: String,
    pub notification: HumanAttentionNotificationEvidence,
    pub approvals: HumanAttentionApprovalEvidence,
    pub task_outcomes: HumanAttentionTaskOutcomeEvidence,
    pub task_verifier: HumanAttentionTaskVerifierEvidence,
    pub risk_outcomes: HumanAttentionRiskOutcomeEvidence,
    pub human_reports: HumanAttentionHumanReportEvidence,
    pub interruptions: HumanAttentionInterruptionEvidence,
    pub privacy: HumanAttentionPrivacyEvidence,
    pub profiles: HumanAttentionProfileEvidence,
    pub task_denominator: HumanAttentionDenominatorFraming,
    pub risk_denominator: HumanAttentionDenominatorFraming,
    /// Absence evidence for a known empty risk population. Required exactly
    /// when the scope risk population is empty with not-applicable coverage;
    /// forbidden otherwise.
    pub risk_absence_evidence_refs: Vec<ArtifactId>,
    /// Why risk outcomes could not be read for an empty risk population with
    /// unavailable or unknown coverage. Required exactly then; forbidden
    /// otherwise.
    pub risk_unavailable_reason: Option<String>,
}

/// Whether the assembled evidence is complete or carries exact gaps.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanAttentionAssemblyStatus {
    Complete,
    Partial,
}

/// Assembled bounded owner evidence: the ten I11.10 metric groups with
/// consistent window, manifest, and source-revision bindings, plus the exact
/// gaps that mark a partial record.
///
/// Every group satisfies structural validation on return, so the Governor
/// producer can embed these groups into a candidate record directly. A
/// `Partial` status never blocks persistence outright; it obliges the
/// producer to carry the gaps into uncertainty and comparison limits instead
/// of tuning policy from incomplete evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionAssembledEvidence {
    pub observation_window_ref: ContractId,
    pub evidence_manifest: HumanAttentionEvidenceManifest,
    pub source_bindings: Vec<HumanAttentionSourceBinding>,
    pub policy_and_task_risk_profile: HumanAttentionMetricGroup,
    pub notification_approval_and_telemetry_profile: HumanAttentionMetricGroup,
    pub missed_critical_and_false_critical_counts: HumanAttentionMetricGroup,
    pub pre_exposure_prevention_and_conditional_intervention: HumanAttentionMetricGroup,
    pub final_harm_and_residual_risk: HumanAttentionMetricGroup,
    pub benign_false_blocks_and_abandoned_work: HumanAttentionMetricGroup,
    pub interruption_and_resumption_time_quality: HumanAttentionMetricGroup,
    pub task_correctness_rework_and_human_attention: HumanAttentionMetricGroup,
    pub overtrust_undertrust_and_recoverability_observations: HumanAttentionMetricGroup,
    pub privacy_purpose_retention_and_disclosure_cost: HumanAttentionMetricGroup,
    pub gaps: Vec<HumanAttentionEvidenceGap>,
    pub status: HumanAttentionAssemblyStatus,
}

/// Fixed absence value reason for a known empty risk population.
const RISK_ABSENCE_VALUE_REASON: &str = "the declared risk population is explicitly empty";
/// Fixed absence denominator reason for a known empty risk population.
const RISK_ABSENCE_DENOMINATOR_REASON: &str =
    "no risk opportunities are eligible in this evaluation scope";

/// One population's denominator with its derived completeness flag.
struct PopulationBinding {
    population: HumanAttentionPopulation,
    denominator: HumanAttentionMetricDenominator,
    denominator_complete: bool,
}

/// Keeps only references admissible for `metric`, deterministically ordered.
///
/// Admissibility reuses the metric source rules, so an attention, trust, or
/// task-correctness slot can never be sourced from interaction proxies: no
/// such evidence kind exists, and wrong-kind nominations are dropped here and
/// refused as sourceless observations downstream.
fn admissible_sources(
    candidates: &[HumanAttentionMetricSourceRef],
    metric: HumanAttentionMetric,
) -> Vec<HumanAttentionMetricSourceRef> {
    let mut admitted: Vec<HumanAttentionMetricSourceRef> = candidates
        .iter()
        .filter(|source| source.validate_for(metric).is_ok())
        .cloned()
        .collect();
    admitted.sort_by(|left, right| left.evidence_ref.cmp(&right.evidence_ref));
    admitted.dedup_by(|left, right| left.evidence_ref == right.evidence_ref);
    admitted
}

/// Requires the exact caller-supplied reason an observation is unavailable.
fn unavailable_reason(slot_reason: &Option<String>) -> Result<&str, EvaluationContractError> {
    match slot_reason.as_deref() {
        Some(reason) => {
            text(reason, "human_attention.assembly.unavailable_reason")?;
            Ok(reason)
        }
        None => Err(EvaluationContractError::InvalidText {
            field: "human_attention.assembly.unavailable_reason",
        }),
    }
}

/// Assembles one count slot: an observed count (zero included) with admissible
/// sources, or an explicit unknown with an exact gap. Missing collection is
/// never encoded as zero.
fn count_observation(
    binding: &PopulationBinding,
    window_ref: &ContractId,
    metric: HumanAttentionMetric,
    slot: &NominatedCountObservation,
    read: HumanAttentionEvidenceRead,
    candidates: &[HumanAttentionMetricSourceRef],
) -> Result<
    (
        HumanAttentionMetricObservation,
        Option<HumanAttentionEvidenceGap>,
    ),
    EvaluationContractError,
> {
    let unit = match metric.required_unit() {
        MetricUnitClass::Count => HumanAttentionMetricUnit::Count,
        MetricUnitClass::Milliseconds => HumanAttentionMetricUnit::Milliseconds,
        MetricUnitClass::Observation | MetricUnitClass::Named => {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.assembly.metric",
                reason: "count assembly reached a non-count metric",
            });
        }
    };
    match slot.observed {
        Some(observed) => {
            let sources = admissible_sources(candidates, metric);
            if sources.is_empty() {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.assembly.source_refs",
                    reason: "an available owner read without admissible evidence cannot support an observation",
                });
            }
            let coefficient =
                i64::try_from(observed).map_err(|_| EvaluationContractError::InvalidInterval {
                    field: "human_attention.assembly.count",
                })?;
            let coverage = if binding.denominator_complete {
                CoverageState::Complete
            } else {
                CoverageState::Partial
            };
            Ok((
                HumanAttentionMetricObservation {
                    metric,
                    value: HumanAttentionMetricValue::ObservedNumber {
                        coefficient,
                        decimal_places: 0,
                    },
                    unit,
                    observation_window_ref: window_ref.clone(),
                    population: binding.population,
                    denominator: binding.denominator.clone(),
                    source_refs: sources,
                    coverage,
                },
                None,
            ))
        }
        None => {
            let reason = unavailable_reason(&slot.unavailable_reason)?;
            Ok((
                HumanAttentionMetricObservation {
                    metric,
                    value: HumanAttentionMetricValue::Unknown {
                        reason: reason.to_string(),
                    },
                    unit,
                    observation_window_ref: window_ref.clone(),
                    population: binding.population,
                    denominator: binding.denominator.clone(),
                    source_refs: Vec::new(),
                    coverage: CoverageState::Unavailable,
                },
                Some(HumanAttentionEvidenceGap {
                    read,
                    metric,
                    reason: reason.to_string(),
                }),
            ))
        }
    }
}

/// Assembles one text slot: an observed statement with admissible sources, or
/// an explicit unknown with an exact gap. Blank statements are refused.
fn text_observation(
    binding: &PopulationBinding,
    window_ref: &ContractId,
    metric: HumanAttentionMetric,
    slot: &NominatedTextObservation,
    read: HumanAttentionEvidenceRead,
    candidates: &[HumanAttentionMetricSourceRef],
) -> Result<
    (
        HumanAttentionMetricObservation,
        Option<HumanAttentionEvidenceGap>,
    ),
    EvaluationContractError,
> {
    if metric.required_unit() != MetricUnitClass::Observation {
        return Err(EvaluationContractError::EvidenceState {
            field: "human_attention.assembly.metric",
            reason: "text assembly reached a non-observation metric",
        });
    }
    match &slot.observed {
        Some(observed) => {
            text(observed, "human_attention.assembly.observation")?;
            let sources = admissible_sources(candidates, metric);
            if sources.is_empty() {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.assembly.source_refs",
                    reason: "an available owner read without admissible evidence cannot support an observation",
                });
            }
            let coverage = if binding.denominator_complete {
                CoverageState::Complete
            } else {
                CoverageState::Partial
            };
            Ok((
                HumanAttentionMetricObservation {
                    metric,
                    value: HumanAttentionMetricValue::ObservedText {
                        observation: observed.clone(),
                    },
                    unit: HumanAttentionMetricUnit::Observation,
                    observation_window_ref: window_ref.clone(),
                    population: binding.population,
                    denominator: binding.denominator.clone(),
                    source_refs: sources,
                    coverage,
                },
                None,
            ))
        }
        None => {
            let reason = unavailable_reason(&slot.unavailable_reason)?;
            Ok((
                HumanAttentionMetricObservation {
                    metric,
                    value: HumanAttentionMetricValue::Unknown {
                        reason: reason.to_string(),
                    },
                    unit: HumanAttentionMetricUnit::Observation,
                    observation_window_ref: window_ref.clone(),
                    population: binding.population,
                    denominator: binding.denominator.clone(),
                    source_refs: Vec::new(),
                    coverage: CoverageState::Unavailable,
                },
                Some(HumanAttentionEvidenceGap {
                    read,
                    metric,
                    reason: reason.to_string(),
                }),
            ))
        }
    }
}

/// Assembles one privacy-cost slot with its explicit named unit.
///
/// Privacy costs carry counts under caller-named units; the unit is required
/// even when the value is unavailable, because a unit-less cost is
/// uninterpretable.
fn privacy_observation(
    binding: &PopulationBinding,
    window_ref: &ContractId,
    metric: HumanAttentionMetric,
    slot: &NominatedPrivacyCostObservation,
    read: HumanAttentionEvidenceRead,
    candidates: &[HumanAttentionMetricSourceRef],
) -> Result<
    (
        HumanAttentionMetricObservation,
        Option<HumanAttentionEvidenceGap>,
    ),
    EvaluationContractError,
> {
    if metric.required_unit() != MetricUnitClass::Named {
        return Err(EvaluationContractError::EvidenceState {
            field: "human_attention.assembly.metric",
            reason: "privacy assembly reached a non-privacy metric",
        });
    }
    text(&slot.unit, "human_attention.assembly.privacy_unit")?;
    let unit = HumanAttentionMetricUnit::Named(slot.unit.clone());
    match slot.observed {
        Some(observed) => {
            let sources = admissible_sources(candidates, metric);
            if sources.is_empty() {
                return Err(EvaluationContractError::EvidenceState {
                    field: "human_attention.assembly.source_refs",
                    reason: "an available owner read without admissible evidence cannot support an observation",
                });
            }
            let coefficient =
                i64::try_from(observed).map_err(|_| EvaluationContractError::InvalidInterval {
                    field: "human_attention.assembly.count",
                })?;
            let coverage = if binding.denominator_complete {
                CoverageState::Complete
            } else {
                CoverageState::Partial
            };
            Ok((
                HumanAttentionMetricObservation {
                    metric,
                    value: HumanAttentionMetricValue::ObservedNumber {
                        coefficient,
                        decimal_places: 0,
                    },
                    unit,
                    observation_window_ref: window_ref.clone(),
                    population: binding.population,
                    denominator: binding.denominator.clone(),
                    source_refs: sources,
                    coverage,
                },
                None,
            ))
        }
        None => {
            let reason = unavailable_reason(&slot.unavailable_reason)?;
            Ok((
                HumanAttentionMetricObservation {
                    metric,
                    value: HumanAttentionMetricValue::Unknown {
                        reason: reason.to_string(),
                    },
                    unit,
                    observation_window_ref: window_ref.clone(),
                    population: binding.population,
                    denominator: binding.denominator.clone(),
                    source_refs: Vec::new(),
                    coverage: CoverageState::Unavailable,
                },
                Some(HumanAttentionEvidenceGap {
                    read,
                    metric,
                    reason: reason.to_string(),
                }),
            ))
        }
    }
}

/// Records an exact gap when a slot is unavailable.
fn push_gap(gaps: &mut Vec<HumanAttentionEvidenceGap>, gap: Option<HumanAttentionEvidenceGap>) {
    if let Some(gap) = gap {
        gaps.push(gap);
    }
}

/// Builds one population denominator over the complete declared population.
///
/// Missing outcomes keep the complete opportunity denominator: collection
/// gaps change coverage, never the eligible set. Complete coverage additionally
/// requires a closed window, no blind intervals, and a complete declared
/// population.
fn decision_denominator(
    eligible: &[String],
    framing: &HumanAttentionDenominatorFraming,
    window: &HumanAttentionObservationWindow,
    scope_coverage: CoverageState,
    collection_full: bool,
) -> Result<(HumanAttentionMetricDenominator, bool), EvaluationContractError> {
    let framing_complete = window.closed_at.is_some()
        && framing
            .unobservable_boundaries_and_blind_intervals
            .is_empty();
    let coverage =
        if collection_full && framing_complete && scope_coverage == CoverageState::Complete {
            CoverageState::Complete
        } else if collection_full {
            if scope_coverage == CoverageState::Complete {
                CoverageState::Partial
            } else {
                scope_coverage
            }
        } else {
            CoverageState::Unavailable
        };
    let denominator = DecisionOpportunityDenominator {
        eligible_subject_refs: eligible.to_vec(),
        ineligible_subject_refs_with_reason: Vec::new(),
        opportunity_start: window.opened_at.clone(),
        opportunity_end: window.closed_at.clone(),
        observable_boundaries: framing.observable_boundaries.clone(),
        unobservable_boundaries_and_blind_intervals: framing
            .unobservable_boundaries_and_blind_intervals
            .clone(),
        coverage_state: coverage,
        denominator_source_and_revision: framing.denominator_source_and_revision.clone(),
    };
    denominator.validate()?;
    let complete = coverage == CoverageState::Complete;
    Ok((
        HumanAttentionMetricDenominator::DecisionOpportunities {
            denominator: Box::new(denominator),
        },
        complete,
    ))
}

/// Builds one risk metric for an empty risk population: either not-applicable
/// with absence evidence, or unknown with the caller-supplied reason.
fn empty_risk_metric(
    metric: HumanAttentionMetric,
    value: &HumanAttentionMetricValue,
    denominator: &HumanAttentionMetricDenominator,
    coverage: CoverageState,
    window_ref: &ContractId,
) -> Result<HumanAttentionMetricObservation, EvaluationContractError> {
    let unit = match metric.required_unit() {
        MetricUnitClass::Count => HumanAttentionMetricUnit::Count,
        MetricUnitClass::Observation => HumanAttentionMetricUnit::Observation,
        MetricUnitClass::Milliseconds | MetricUnitClass::Named => {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.assembly.metric",
                reason: "risk absence assembly reached a non-risk metric",
            });
        }
    };
    Ok(HumanAttentionMetricObservation {
        metric,
        value: value.clone(),
        unit,
        observation_window_ref: window_ref.clone(),
        population: HumanAttentionPopulation::RiskOpportunities,
        denominator: denominator.clone(),
        source_refs: Vec::new(),
        coverage,
    })
}

/// Checks every nominated source revision is an exact non-blank binding.
fn check_assembly_revisions(
    input: &HumanAttentionAssemblyInput,
) -> Result<(), EvaluationContractError> {
    text(
        &input.notification.delivery_source_revision,
        "human_attention.assembly.delivery_source_revision",
    )?;
    text(
        &input.notification.disposition_source_revision,
        "human_attention.assembly.disposition_source_revision",
    )?;
    text(
        &input.approvals.approval_source_revision,
        "human_attention.assembly.approval_source_revision",
    )?;
    text(
        &input.approvals.telemetry_source_revision,
        "human_attention.assembly.approval_telemetry_source_revision",
    )?;
    text(
        &input.task_outcomes.task_source_revision,
        "human_attention.assembly.task_source_revision",
    )?;
    text(
        &input.task_verifier.verifier_source_revision,
        "human_attention.assembly.verifier_source_revision",
    )?;
    text(
        &input.risk_outcomes.risk_source_revision,
        "human_attention.assembly.risk_source_revision",
    )?;
    text(
        &input.human_reports.report_source_revision,
        "human_attention.assembly.report_source_revision",
    )?;
    text(
        &input.interruptions.measurement_source_revision,
        "human_attention.assembly.measurement_source_revision",
    )?;
    text(
        &input.privacy.privacy_source_revision,
        "human_attention.assembly.privacy_source_revision",
    )?;
    text(
        &input.privacy.telemetry_source_revision,
        "human_attention.assembly.privacy_telemetry_source_revision",
    )?;
    text(
        &input.profiles.policy_source_revision,
        "human_attention.assembly.policy_source_revision",
    )?;
    text(
        &input.profiles.task_risk_source_revision,
        "human_attention.assembly.task_risk_source_revision",
    )
}

/// Checks the conditional risk-absence fields and binds the risk framing.
///
/// Absence evidence is required exactly for a known empty risk population; an
/// unavailability reason is required exactly for an empty population with
/// unavailable or unknown coverage; both are forbidden when risk
/// opportunities exist. The risk framing stays bound in every path as the
/// provenance of the attempted risk read.
fn check_risk_absence_fields(
    input: &HumanAttentionAssemblyInput,
) -> Result<(), EvaluationContractError> {
    if !input.evaluation_scope.risk_population_refs.is_empty() {
        if !input.risk_absence_evidence_refs.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.assembly.risk_absence_evidence_refs",
                reason: "absence evidence applies only to an explicitly empty risk population",
            });
        }
        if input.risk_unavailable_reason.is_some() {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.assembly.risk_unavailable_reason",
                reason: "an unavailability reason applies only to an explicitly empty risk population",
            });
        }
        return Ok(());
    }
    if input.evaluation_scope.risk_population_coverage == CoverageState::NotApplicable {
        if input.risk_absence_evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "human_attention.assembly.risk_absence_evidence_refs",
            });
        }
        if input.risk_unavailable_reason.is_some() {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.assembly.risk_unavailable_reason",
                reason: "a known empty risk population takes absence evidence, not an unavailability reason",
            });
        }
    } else {
        if !matches!(
            input.evaluation_scope.risk_population_coverage,
            CoverageState::Unavailable | CoverageState::Unknown
        ) {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.assembly.scope.risk_population_coverage",
                reason: "an empty risk population requires explicit not-applicable or unavailable coverage",
            });
        }
        if !input.risk_absence_evidence_refs.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "human_attention.assembly.risk_absence_evidence_refs",
                reason: "absence evidence applies only to a known empty risk population",
            });
        }
        match &input.risk_unavailable_reason {
            Some(reason) => {
                text(reason, "human_attention.assembly.risk_unavailable_reason")?;
            }
            None => {
                return Err(EvaluationContractError::InvalidText {
                    field: "human_attention.assembly.risk_unavailable_reason",
                });
            }
        }
    }
    texts(
        &input.risk_denominator.observable_boundaries,
        "human_attention.assembly.risk_denominator.observable_boundaries",
    )?;
    for boundary in &input
        .risk_denominator
        .unobservable_boundaries_and_blind_intervals
    {
        bounded_reason(
            boundary,
            "human_attention.assembly.risk_denominator.blind_interval",
        )?;
    }
    text(
        &input.risk_denominator.denominator_source_and_revision,
        "human_attention.assembly.risk_denominator.source_and_revision",
    )
}

/// Collects the admitted evidence references into a deterministic manifest.
///
/// Absence evidence joins the manifest only on the not-applicable risk path;
/// the conditional field check forbids it elsewhere, so the union is exact.
fn assemble_evidence_manifest(
    input: &HumanAttentionAssemblyInput,
) -> Result<HumanAttentionEvidenceManifest, EvaluationContractError> {
    let mut evidence_refs: Vec<ArtifactId> = Vec::new();
    for sources in [
        &input.notification.evidence_refs,
        &input.approvals.evidence_refs,
        &input.task_outcomes.evidence_refs,
        &input.task_verifier.evidence_refs,
        &input.risk_outcomes.evidence_refs,
        &input.human_reports.evidence_refs,
        &input.interruptions.evidence_refs,
        &input.privacy.evidence_refs,
        &input.profiles.evidence_refs,
    ] {
        for source in sources {
            evidence_refs.push(source.evidence_ref.clone());
        }
    }
    evidence_refs.extend(input.risk_absence_evidence_refs.iter().cloned());
    evidence_refs.sort();
    evidence_refs.dedup();
    let manifest = HumanAttentionEvidenceManifest {
        manifest_id: input.manifest_id.clone(),
        revision: input.manifest_revision.clone(),
        evidence_refs,
    };
    manifest.validate()?;
    Ok(manifest)
}

/// Assembles the ten I11.10 metric groups from bounded owner evidence.
///
/// Every observation binds the input window; every denominator binds the
/// complete declared population; every source revision is recorded. Available
/// slots become observed values with admissible sources; unavailable slots
/// become explicit unknowns with exact gaps, never synthetic zeros. The
/// returned groups satisfy structural validation, so the Governor producer
/// can embed them into a candidate record directly.
pub fn assemble_human_attention_evidence(
    input: &HumanAttentionAssemblyInput,
) -> Result<HumanAttentionAssembledEvidence, EvaluationContractError> {
    input.observation_window.validate()?;
    input.evaluation_scope.validate()?;
    check_assembly_revisions(input)?;
    check_risk_absence_fields(input)?;
    let manifest = assemble_evidence_manifest(input)?;
    let window_ref = input.observation_window.specification.window_id.clone();

    let task_collection_full = input
        .notification
        .deduplicated_inbox_items
        .observed
        .is_some()
        && input.notification.delivery_attempts.observed.is_some()
        && input
            .approvals
            .notification_approval_telemetry_profile
            .observed
            .is_some()
        && input
            .profiles
            .policy_and_task_risk_profile
            .observed
            .is_some()
        && input
            .task_outcomes
            .benign_false_block_tasks
            .observed
            .is_some()
        && input.task_outcomes.abandoned_work_tasks.observed.is_some()
        && input.task_outcomes.rework_events.observed.is_some()
        && input
            .task_verifier
            .task_correctness_observation
            .observed
            .is_some()
        && input
            .interruptions
            .interruption_duration_ms
            .observed
            .is_some()
        && input.interruptions.resumption_latency_ms.observed.is_some()
        && input
            .human_reports
            .human_attention_observation
            .observed
            .is_some()
        && input.human_reports.overtrust_observation.observed.is_some()
        && input
            .human_reports
            .undertrust_observation
            .observed
            .is_some()
        && input
            .human_reports
            .recoverability_observation
            .observed
            .is_some()
        && input
            .human_reports
            .resumption_quality_observation
            .observed
            .is_some()
        && input.privacy.purpose_cost.observed.is_some()
        && input.privacy.retention_cost.observed.is_some()
        && input.privacy.disclosure_cost.observed.is_some();
    let (task_denominator, task_complete) = decision_denominator(
        &input.evaluation_scope.task_population_refs,
        &input.task_denominator,
        &input.observation_window,
        input.evaluation_scope.task_population_coverage,
        task_collection_full,
    )?;
    let tasks = PopulationBinding {
        population: HumanAttentionPopulation::Tasks,
        denominator: task_denominator,
        denominator_complete: task_complete,
    };

    let mut gaps: Vec<HumanAttentionEvidenceGap> = Vec::new();

    let (policy_profile, gap) = text_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::PolicyAndTaskRiskProfile,
        &input.profiles.policy_and_task_risk_profile,
        HumanAttentionEvidenceRead::PolicyProfile,
        &input.profiles.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let policy_and_task_risk_profile = HumanAttentionMetricGroup {
        metrics: vec![policy_profile],
    };

    let mut profile_candidates = Vec::new();
    profile_candidates.extend_from_slice(&input.notification.evidence_refs);
    profile_candidates.extend_from_slice(&input.approvals.evidence_refs);
    profile_candidates.extend_from_slice(&input.privacy.evidence_refs);
    let (notification_profile, gap) = text_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::NotificationApprovalAndTelemetryProfile,
        &input.approvals.notification_approval_telemetry_profile,
        HumanAttentionEvidenceRead::ExpiringApproval,
        &profile_candidates,
    )?;
    push_gap(&mut gaps, gap);
    let (deduplicated_inbox_items, gap) = count_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::DeduplicatedInboxItems,
        &input.notification.deduplicated_inbox_items,
        HumanAttentionEvidenceRead::NotificationDisposition,
        &input.notification.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let (delivery_attempts, gap) = count_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::DeliveryAttempts,
        &input.notification.delivery_attempts,
        HumanAttentionEvidenceRead::NotificationDelivery,
        &input.notification.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);

    let mut task_verifier_candidates = Vec::new();
    task_verifier_candidates.extend_from_slice(&input.task_outcomes.evidence_refs);
    task_verifier_candidates.extend_from_slice(&input.task_verifier.evidence_refs);
    let (benign_false_blocks, gap) = count_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::BenignFalseBlockTasks,
        &input.task_outcomes.benign_false_block_tasks,
        HumanAttentionEvidenceRead::TaskOutcome,
        &task_verifier_candidates,
    )?;
    push_gap(&mut gaps, gap);
    let (abandoned_work, gap) = count_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::AbandonedWorkTasks,
        &input.task_outcomes.abandoned_work_tasks,
        HumanAttentionEvidenceRead::TaskOutcome,
        &task_verifier_candidates,
    )?;
    push_gap(&mut gaps, gap);
    let benign_false_blocks_and_abandoned_work = HumanAttentionMetricGroup {
        metrics: vec![benign_false_blocks, abandoned_work],
    };

    let (interruption_duration, gap) = count_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::InterruptionDuration,
        &input.interruptions.interruption_duration_ms,
        HumanAttentionEvidenceRead::InterruptionMeasurement,
        &input.interruptions.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let (resumption_latency, gap) = count_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::ResumptionLatency,
        &input.interruptions.resumption_latency_ms,
        HumanAttentionEvidenceRead::InterruptionMeasurement,
        &input.interruptions.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let mut resumption_candidates = Vec::new();
    resumption_candidates.extend_from_slice(&input.human_reports.evidence_refs);
    resumption_candidates.extend_from_slice(&input.interruptions.evidence_refs);
    let (resumption_quality, gap) = text_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::ResumptionQualityObservation,
        &input.human_reports.resumption_quality_observation,
        HumanAttentionEvidenceRead::HumanReport,
        &resumption_candidates,
    )?;
    push_gap(&mut gaps, gap);
    let interruption_and_resumption_time_quality = HumanAttentionMetricGroup {
        metrics: vec![
            interruption_duration,
            resumption_latency,
            resumption_quality,
        ],
    };

    let (task_correctness, gap) = text_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::TaskCorrectnessObservation,
        &input.task_verifier.task_correctness_observation,
        HumanAttentionEvidenceRead::TaskVerifier,
        &task_verifier_candidates,
    )?;
    push_gap(&mut gaps, gap);
    let (rework_events, gap) = count_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::ReworkEvents,
        &input.task_outcomes.rework_events,
        HumanAttentionEvidenceRead::TaskOutcome,
        &task_verifier_candidates,
    )?;
    push_gap(&mut gaps, gap);
    let (human_attention, gap) = text_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::HumanAttentionObservation,
        &input.human_reports.human_attention_observation,
        HumanAttentionEvidenceRead::HumanReport,
        &input.human_reports.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let task_correctness_rework_and_human_attention = HumanAttentionMetricGroup {
        metrics: vec![task_correctness, rework_events, human_attention],
    };

    let (overtrust, gap) = text_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::OvertrustObservation,
        &input.human_reports.overtrust_observation,
        HumanAttentionEvidenceRead::HumanReport,
        &input.human_reports.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let (undertrust, gap) = text_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::UndertrustObservation,
        &input.human_reports.undertrust_observation,
        HumanAttentionEvidenceRead::HumanReport,
        &input.human_reports.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let (recoverability, gap) = text_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::RecoverabilityObservation,
        &input.human_reports.recoverability_observation,
        HumanAttentionEvidenceRead::HumanReport,
        &input.human_reports.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let overtrust_undertrust_and_recoverability_observations = HumanAttentionMetricGroup {
        metrics: vec![overtrust, undertrust, recoverability],
    };

    let (purpose_cost, gap) = privacy_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::PrivacyPurposeCost,
        &input.privacy.purpose_cost,
        HumanAttentionEvidenceRead::PrivacyRecord,
        &input.privacy.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let (retention_cost, gap) = privacy_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::PrivacyRetentionCost,
        &input.privacy.retention_cost,
        HumanAttentionEvidenceRead::PrivacyRecord,
        &input.privacy.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let (disclosure_cost, gap) = privacy_observation(
        &tasks,
        &window_ref,
        HumanAttentionMetric::PrivacyDisclosureCost,
        &input.privacy.disclosure_cost,
        HumanAttentionEvidenceRead::PrivacyRecord,
        &input.privacy.evidence_refs,
    )?;
    push_gap(&mut gaps, gap);
    let privacy_purpose_retention_and_disclosure_cost = HumanAttentionMetricGroup {
        metrics: vec![purpose_cost, retention_cost, disclosure_cost],
    };

    let scope = &input.evaluation_scope;
    let notification_approval_and_telemetry_profile;
    let missed_critical_and_false_critical_counts;
    let pre_exposure_prevention_and_conditional_intervention;
    let final_harm_and_residual_risk;
    if scope.risk_population_refs.is_empty() {
        if scope.risk_population_coverage == CoverageState::NotApplicable {
            let denominator = HumanAttentionMetricDenominator::NoEligibleOpportunities {
                reason: RISK_ABSENCE_DENOMINATOR_REASON.to_string(),
                evidence_refs: input.risk_absence_evidence_refs.clone(),
            };
            let value = HumanAttentionMetricValue::NotApplicable {
                reason: RISK_ABSENCE_VALUE_REASON.to_string(),
            };
            let distinct = empty_risk_metric(
                HumanAttentionMetric::DistinctRiskEvents,
                &value,
                &denominator,
                CoverageState::NotApplicable,
                &window_ref,
            )?;
            let missed = empty_risk_metric(
                HumanAttentionMetric::MissedCriticalRiskEvents,
                &value,
                &denominator,
                CoverageState::NotApplicable,
                &window_ref,
            )?;
            let false_critical = empty_risk_metric(
                HumanAttentionMetric::FalseCriticalRiskEvents,
                &value,
                &denominator,
                CoverageState::NotApplicable,
                &window_ref,
            )?;
            let prevented = empty_risk_metric(
                HumanAttentionMetric::PreExposurePreventionEvents,
                &value,
                &denominator,
                CoverageState::NotApplicable,
                &window_ref,
            )?;
            let conditional = empty_risk_metric(
                HumanAttentionMetric::ConditionalInterventionEvents,
                &value,
                &denominator,
                CoverageState::NotApplicable,
                &window_ref,
            )?;
            let harm = empty_risk_metric(
                HumanAttentionMetric::FinalHarmEvents,
                &value,
                &denominator,
                CoverageState::NotApplicable,
                &window_ref,
            )?;
            let residual = empty_risk_metric(
                HumanAttentionMetric::ResidualRiskObservation,
                &value,
                &denominator,
                CoverageState::NotApplicable,
                &window_ref,
            )?;
            notification_approval_and_telemetry_profile = HumanAttentionMetricGroup {
                metrics: vec![
                    notification_profile,
                    deduplicated_inbox_items,
                    delivery_attempts,
                    distinct,
                ],
            };
            missed_critical_and_false_critical_counts = HumanAttentionMetricGroup {
                metrics: vec![missed, false_critical],
            };
            pre_exposure_prevention_and_conditional_intervention = HumanAttentionMetricGroup {
                metrics: vec![prevented, conditional],
            };
            final_harm_and_residual_risk = HumanAttentionMetricGroup {
                metrics: vec![harm, residual],
            };
        } else {
            let coverage = scope.risk_population_coverage;
            let reason = match input.risk_unavailable_reason.as_deref() {
                Some(reason) => {
                    text(reason, "human_attention.assembly.risk_unavailable_reason")?;
                    reason
                }
                None => {
                    return Err(EvaluationContractError::InvalidText {
                        field: "human_attention.assembly.risk_unavailable_reason",
                    });
                }
            };
            let denominator = HumanAttentionMetricDenominator::PopulationUnavailable {
                coverage,
                reason: reason.to_string(),
                evidence_refs: Vec::new(),
            };
            let value = HumanAttentionMetricValue::Unknown {
                reason: reason.to_string(),
            };
            let distinct = empty_risk_metric(
                HumanAttentionMetric::DistinctRiskEvents,
                &value,
                &denominator,
                coverage,
                &window_ref,
            )?;
            let missed = empty_risk_metric(
                HumanAttentionMetric::MissedCriticalRiskEvents,
                &value,
                &denominator,
                coverage,
                &window_ref,
            )?;
            let false_critical = empty_risk_metric(
                HumanAttentionMetric::FalseCriticalRiskEvents,
                &value,
                &denominator,
                coverage,
                &window_ref,
            )?;
            let prevented = empty_risk_metric(
                HumanAttentionMetric::PreExposurePreventionEvents,
                &value,
                &denominator,
                coverage,
                &window_ref,
            )?;
            let conditional = empty_risk_metric(
                HumanAttentionMetric::ConditionalInterventionEvents,
                &value,
                &denominator,
                coverage,
                &window_ref,
            )?;
            let harm = empty_risk_metric(
                HumanAttentionMetric::FinalHarmEvents,
                &value,
                &denominator,
                coverage,
                &window_ref,
            )?;
            let residual = empty_risk_metric(
                HumanAttentionMetric::ResidualRiskObservation,
                &value,
                &denominator,
                coverage,
                &window_ref,
            )?;
            for metric in [
                HumanAttentionMetric::DistinctRiskEvents,
                HumanAttentionMetric::MissedCriticalRiskEvents,
                HumanAttentionMetric::FalseCriticalRiskEvents,
                HumanAttentionMetric::PreExposurePreventionEvents,
                HumanAttentionMetric::ConditionalInterventionEvents,
                HumanAttentionMetric::FinalHarmEvents,
                HumanAttentionMetric::ResidualRiskObservation,
            ] {
                gaps.push(HumanAttentionEvidenceGap {
                    read: HumanAttentionEvidenceRead::RiskEventOutcome,
                    metric,
                    reason: reason.to_string(),
                });
            }
            notification_approval_and_telemetry_profile = HumanAttentionMetricGroup {
                metrics: vec![
                    notification_profile,
                    deduplicated_inbox_items,
                    delivery_attempts,
                    distinct,
                ],
            };
            missed_critical_and_false_critical_counts = HumanAttentionMetricGroup {
                metrics: vec![missed, false_critical],
            };
            pre_exposure_prevention_and_conditional_intervention = HumanAttentionMetricGroup {
                metrics: vec![prevented, conditional],
            };
            final_harm_and_residual_risk = HumanAttentionMetricGroup {
                metrics: vec![harm, residual],
            };
        }
    } else {
        let risk_collection_full = input.risk_outcomes.distinct_risk_events.observed.is_some()
            && input
                .risk_outcomes
                .missed_critical_risk_events
                .observed
                .is_some()
            && input
                .risk_outcomes
                .false_critical_risk_events
                .observed
                .is_some()
            && input
                .risk_outcomes
                .pre_exposure_prevention_events
                .observed
                .is_some()
            && input
                .risk_outcomes
                .conditional_intervention_events
                .observed
                .is_some()
            && input.risk_outcomes.final_harm_events.observed.is_some()
            && input
                .risk_outcomes
                .residual_risk_observation
                .observed
                .is_some();
        let (risk_denominator, risk_complete) = decision_denominator(
            &scope.risk_population_refs,
            &input.risk_denominator,
            &input.observation_window,
            scope.risk_population_coverage,
            risk_collection_full,
        )?;
        let risks = PopulationBinding {
            population: HumanAttentionPopulation::RiskOpportunities,
            denominator: risk_denominator,
            denominator_complete: risk_complete,
        };
        let (distinct, gap) = count_observation(
            &risks,
            &window_ref,
            HumanAttentionMetric::DistinctRiskEvents,
            &input.risk_outcomes.distinct_risk_events,
            HumanAttentionEvidenceRead::RiskEventOutcome,
            &input.risk_outcomes.evidence_refs,
        )?;
        push_gap(&mut gaps, gap);
        let (missed, gap) = count_observation(
            &risks,
            &window_ref,
            HumanAttentionMetric::MissedCriticalRiskEvents,
            &input.risk_outcomes.missed_critical_risk_events,
            HumanAttentionEvidenceRead::RiskEventOutcome,
            &input.risk_outcomes.evidence_refs,
        )?;
        push_gap(&mut gaps, gap);
        let (false_critical, gap) = count_observation(
            &risks,
            &window_ref,
            HumanAttentionMetric::FalseCriticalRiskEvents,
            &input.risk_outcomes.false_critical_risk_events,
            HumanAttentionEvidenceRead::RiskEventOutcome,
            &input.risk_outcomes.evidence_refs,
        )?;
        push_gap(&mut gaps, gap);
        let (prevented, gap) = count_observation(
            &risks,
            &window_ref,
            HumanAttentionMetric::PreExposurePreventionEvents,
            &input.risk_outcomes.pre_exposure_prevention_events,
            HumanAttentionEvidenceRead::RiskEventOutcome,
            &input.risk_outcomes.evidence_refs,
        )?;
        push_gap(&mut gaps, gap);
        let (conditional, gap) = count_observation(
            &risks,
            &window_ref,
            HumanAttentionMetric::ConditionalInterventionEvents,
            &input.risk_outcomes.conditional_intervention_events,
            HumanAttentionEvidenceRead::RiskEventOutcome,
            &input.risk_outcomes.evidence_refs,
        )?;
        push_gap(&mut gaps, gap);
        let (harm, gap) = count_observation(
            &risks,
            &window_ref,
            HumanAttentionMetric::FinalHarmEvents,
            &input.risk_outcomes.final_harm_events,
            HumanAttentionEvidenceRead::RiskEventOutcome,
            &input.risk_outcomes.evidence_refs,
        )?;
        push_gap(&mut gaps, gap);
        let (residual, gap) = text_observation(
            &risks,
            &window_ref,
            HumanAttentionMetric::ResidualRiskObservation,
            &input.risk_outcomes.residual_risk_observation,
            HumanAttentionEvidenceRead::RiskEventOutcome,
            &input.risk_outcomes.evidence_refs,
        )?;
        push_gap(&mut gaps, gap);
        notification_approval_and_telemetry_profile = HumanAttentionMetricGroup {
            metrics: vec![
                notification_profile,
                deduplicated_inbox_items,
                delivery_attempts,
                distinct,
            ],
        };
        missed_critical_and_false_critical_counts = HumanAttentionMetricGroup {
            metrics: vec![missed, false_critical],
        };
        pre_exposure_prevention_and_conditional_intervention = HumanAttentionMetricGroup {
            metrics: vec![prevented, conditional],
        };
        final_harm_and_residual_risk = HumanAttentionMetricGroup {
            metrics: vec![harm, residual],
        };
    }

    policy_and_task_risk_profile.validate(
        HumanAttentionMetricGroupKind::PolicyAndTaskRiskProfile,
        &input.observation_window,
        &manifest,
        scope,
    )?;
    notification_approval_and_telemetry_profile.validate(
        HumanAttentionMetricGroupKind::NotificationApprovalAndTelemetryProfile,
        &input.observation_window,
        &manifest,
        scope,
    )?;
    missed_critical_and_false_critical_counts.validate(
        HumanAttentionMetricGroupKind::MissedCriticalAndFalseCriticalCounts,
        &input.observation_window,
        &manifest,
        scope,
    )?;
    pre_exposure_prevention_and_conditional_intervention.validate(
        HumanAttentionMetricGroupKind::PreExposurePreventionAndConditionalIntervention,
        &input.observation_window,
        &manifest,
        scope,
    )?;
    final_harm_and_residual_risk.validate(
        HumanAttentionMetricGroupKind::FinalHarmAndResidualRisk,
        &input.observation_window,
        &manifest,
        scope,
    )?;
    benign_false_blocks_and_abandoned_work.validate(
        HumanAttentionMetricGroupKind::BenignFalseBlocksAndAbandonedWork,
        &input.observation_window,
        &manifest,
        scope,
    )?;
    interruption_and_resumption_time_quality.validate(
        HumanAttentionMetricGroupKind::InterruptionAndResumptionTimeQuality,
        &input.observation_window,
        &manifest,
        scope,
    )?;
    task_correctness_rework_and_human_attention.validate(
        HumanAttentionMetricGroupKind::TaskCorrectnessReworkAndHumanAttention,
        &input.observation_window,
        &manifest,
        scope,
    )?;
    overtrust_undertrust_and_recoverability_observations.validate(
        HumanAttentionMetricGroupKind::OvertrustUndertrustAndRecoverabilityObservations,
        &input.observation_window,
        &manifest,
        scope,
    )?;
    privacy_purpose_retention_and_disclosure_cost.validate(
        HumanAttentionMetricGroupKind::PrivacyPurposeRetentionAndDisclosureCost,
        &input.observation_window,
        &manifest,
        scope,
    )?;

    let source_bindings = vec![
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::NotificationDelivery,
            source_revision: input.notification.delivery_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::NotificationDisposition,
            source_revision: input.notification.disposition_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::ExpiringApproval,
            source_revision: input.approvals.approval_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::TelemetryCollection,
            source_revision: input.approvals.telemetry_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::TaskOutcome,
            source_revision: input.task_outcomes.task_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::TaskVerifier,
            source_revision: input.task_verifier.verifier_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::RiskEventOutcome,
            source_revision: input.risk_outcomes.risk_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::HumanReport,
            source_revision: input.human_reports.report_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::InterruptionMeasurement,
            source_revision: input.interruptions.measurement_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::PrivacyRecord,
            source_revision: input.privacy.privacy_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::TelemetryCollection,
            source_revision: input.privacy.telemetry_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::PolicyProfile,
            source_revision: input.profiles.policy_source_revision.clone(),
        },
        HumanAttentionSourceBinding {
            read: HumanAttentionEvidenceRead::TaskRiskProfile,
            source_revision: input.profiles.task_risk_source_revision.clone(),
        },
    ];

    let status = if gaps.is_empty() {
        HumanAttentionAssemblyStatus::Complete
    } else {
        HumanAttentionAssemblyStatus::Partial
    };
    Ok(HumanAttentionAssembledEvidence {
        observation_window_ref: window_ref,
        evidence_manifest: manifest,
        source_bindings,
        policy_and_task_risk_profile,
        notification_approval_and_telemetry_profile,
        missed_critical_and_false_critical_counts,
        pre_exposure_prevention_and_conditional_intervention,
        final_harm_and_residual_risk,
        benign_false_blocks_and_abandoned_work,
        interruption_and_resumption_time_quality,
        task_correctness_rework_and_human_attention,
        overtrust_undertrust_and_recoverability_observations,
        privacy_purpose_retention_and_disclosure_cost,
        gaps,
        status,
    })
}
