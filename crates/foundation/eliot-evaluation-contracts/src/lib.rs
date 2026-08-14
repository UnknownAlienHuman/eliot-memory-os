//! Store-neutral contracts for bounded product and recovery evaluation (C0-13).
//!
//! This crate describes claims, scopes, observations and budget evidence.  It
//! does not execute an evaluator, issue proof, decide task finish, or own a
//! product/release status.  Every validator is structural and claim-scoped;
//! no missing observation is inferred as success.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractVersion, ProductId, ReceiptId, RequestId, TaskId,
    TaskRevision,
};
use eliot_graph_api::{GraphFreshness, GraphRevision};
use eliot_instrument_api::{ExecutionStatus, VerificationOutcome};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable wire name for the C0-13 surface.
pub const CONTRACT_NAME: &str = "eliot.foundation.evaluation-contracts";
/// Current wire revision for the C0-13 surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Structural validation failures.  These errors never imply a product or
/// release verdict.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EvaluationContractError {
    /// A required text field is blank or contains control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A required collection has no members.
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    /// A collection contains the same identity more than once.
    #[error("{field} contains a duplicate identity")]
    DuplicateIdentity { field: &'static str },
    /// A numeric or temporal interval is inverted or zero where positive is required.
    #[error("{field} has an invalid interval or zero value")]
    InvalidInterval { field: &'static str },
    /// A claim is broader than its declared evidence ceiling.
    #[error("claim exceeds the available proof ceiling")]
    ProofOverclaim,
    /// A status does not carry the evidence needed to interpret it.
    #[error("{field} has incompatible evidence: {reason}")]
    EvidenceState {
        field: &'static str,
        reason: &'static str,
    },
    /// A canonical C0-01 clock or graph revision rejected its value.
    #[error("{field} is invalid: {reason}")]
    InvalidDependency {
        field: &'static str,
        reason: &'static str,
    },
}

fn text(value: &str, field: &'static str) -> Result<(), EvaluationContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(EvaluationContractError::InvalidText { field });
    }
    Ok(())
}

fn texts(values: &[String], field: &'static str) -> Result<(), EvaluationContractError> {
    if values.is_empty() {
        return Err(EvaluationContractError::EmptyCollection { field });
    }
    for value in values {
        text(value, field)?;
    }
    Ok(())
}

fn unique_texts(values: &[String], field: &'static str) -> Result<(), EvaluationContractError> {
    texts(values, field)?;
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(EvaluationContractError::DuplicateIdentity { field });
    }
    Ok(())
}

/// The comparison basis for an outcome claim.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComparisonBasis {
    /// Compare against exact pre-change behavior on the same scope.
    ExactPrechangeBehavior,
    /// Compare against an authorized matched control.
    MatchedControl,
    /// Compare against a memory-free control.
    MemoryFreeControl,
    /// Compare against a declared historical reference.
    HistoricalReference,
    /// No separate control can change a deterministic conclusion.
    NotApplicableWithReason,
}

/// Lifecycle of a user outcome objective.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectiveStatus {
    Active,
    Achieved,
    Refuted,
    Superseded,
    Cancelled,
}

/// Lifecycle of a recovery acceptance profile.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryProfileStatus {
    Active,
    Satisfied,
    Superseded,
}

/// The intended claim depth of a product evaluation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimKind {
    Deterministic,
    Stochastic,
    Comparative,
    PopulationLevel,
    NonInferiority,
    Generalization,
}

/// Product-evidence disposition.  It is not task finish or release authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductEvidenceStatus {
    CurrentlyVerified,
    ResidualWindowOpen,
    Matured,
    Regressed,
    CensoredOrInconclusive,
}

/// Trial execution and observation state.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrialStatus {
    Planned,
    Running,
    Succeeded,
    Failed,
    Partial,
    Excluded,
    Censored,
    Contaminated,
    Unknown,
}

/// Explicit trial outcome.  Unknown is first-class and never a success alias.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum TrialOutcome {
    Improved { summary: String },
    NoChange { summary: String },
    Regressed { summary: String },
    Inconclusive { reason: String },
    Unknown { reason: String },
}

impl TrialOutcome {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        match self {
            Self::Improved { summary }
            | Self::NoChange { summary }
            | Self::Regressed { summary }
            | Self::Inconclusive { reason: summary }
            | Self::Unknown { reason: summary } => text(summary, "trial.outcome")?,
        }
        Ok(())
    }

    /// Whether this outcome is explicitly uncertain.
    pub const fn is_uncertain(&self) -> bool {
        matches!(self, Self::Inconclusive { .. } | Self::Unknown { .. })
    }
}

/// The evidence scope attached to a claim or report input.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceScope {
    Shape,
    Contract,
    OperationalSpine,
    ProductOutcome,
}

/// A source identity and the contract revisions it was evaluated against.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductIdentityRef {
    /// Product/source identity.
    pub product_id: ProductId,
    /// Exact source or artifact revision.
    pub source_revision: String,
    /// Contract revisions used by the proof surface.
    pub contract_revisions: Vec<ContractVersion>,
}

impl ProductIdentityRef {
    /// Validates exact identity binding.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.source_revision, "product_identity.source_revision")?;
        if self.contract_revisions.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "product_identity.contract_revisions",
            });
        }
        Ok(())
    }
}

/// One named recovery gap and its discriminator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGap {
    /// Stable gap identity.
    pub gap_id: ContractId,
    /// Human-readable bounded description.
    pub description: String,
    /// Observable discriminator that can resolve the gap.
    pub discriminator: String,
}

impl RecoveryGap {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.description, "recovery_gap.description")?;
        text(&self.discriminator, "recovery_gap.discriminator")
    }
}

/// Human-owned user/task outcome objective state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserOutcomeObjectiveState {
    pub objective_id: ContractId,
    pub owner: String,
    pub task_family_and_population: String,
    pub intended_user_outcome: String,
    pub primary_outcome_measure: String,
    pub comparison_basis: ComparisonBasis,
    pub comparison_reason: Option<String>,
    pub counter_metrics: Vec<String>,
    pub disproof_and_stop_conditions: Vec<String>,
    pub evaluation_plan_ref: Option<ContractId>,
    pub product_identity_ref: ProductIdentityRef,
    pub outcome_evidence_refs: Vec<ArtifactId>,
    pub status: ObjectiveStatus,
    pub revision: TaskRevision,
}

impl UserOutcomeObjectiveState {
    /// Validates scope, comparison rationale and objective evidence shape.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.owner, "objective.owner")?;
        text(
            &self.task_family_and_population,
            "objective.task_family_and_population",
        )?;
        text(
            &self.intended_user_outcome,
            "objective.intended_user_outcome",
        )?;
        text(
            &self.primary_outcome_measure,
            "objective.primary_outcome_measure",
        )?;
        self.product_identity_ref.validate()?;
        texts(&self.counter_metrics, "objective.counter_metrics")?;
        texts(
            &self.disproof_and_stop_conditions,
            "objective.disproof_and_stop_conditions",
        )?;
        if self.comparison_basis == ComparisonBasis::NotApplicableWithReason {
            match &self.comparison_reason {
                Some(reason) => text(reason, "objective.comparison_reason")?,
                None => {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "objective.comparison_reason",
                        reason: "not-applicable comparison requires a reason",
                    });
                }
            }
        }
        if self.status == ObjectiveStatus::Achieved && self.outcome_evidence_refs.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "objective.outcome_evidence_refs",
                reason: "achieved objective requires outcome evidence",
            });
        }
        Ok(())
    }
}

/// Bounded set of currently blocking invariant gaps.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAcceptanceProfile {
    pub profile_id: ContractId,
    pub objective_ref: ContractId,
    pub invariant_gaps: Vec<RecoveryGap>,
    pub affected_owners: Vec<String>,
    pub discriminators: Vec<String>,
    pub enablement_condition: String,
    pub status: RecoveryProfileStatus,
    pub revision: TaskRevision,
}

impl RecoveryAcceptanceProfile {
    /// Validates recovery scope without declaring the profile satisfied.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        texts(&self.affected_owners, "recovery.affected_owners")?;
        texts(&self.discriminators, "recovery.discriminators")?;
        text(&self.enablement_condition, "recovery.enablement_condition")?;
        for gap in &self.invariant_gaps {
            gap.validate()?;
        }
        if self.status == RecoveryProfileStatus::Satisfied && !self.invariant_gaps.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "recovery.invariant_gaps",
                reason: "satisfied profile cannot retain unresolved gaps",
            });
        }
        Ok(())
    }
}

/// Exact verifier reference used by a proof brief.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierEvidenceRef {
    pub run_id: RequestId,
    pub verifier_id: ContractId,
    pub scope: String,
    pub execution: ExecutionStatus,
    pub outcome: VerificationOutcome,
    pub proof_ceiling: ProofCeiling,
    pub evidence_refs: Vec<ArtifactId>,
}

impl VerifierEvidenceRef {
    /// Validates that the reference is scoped and not an execution shortcut.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.scope, "verifier.scope")?;
        if self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "verifier.evidence_refs",
            });
        }
        if !self.execution.is_terminal() {
            return Err(EvaluationContractError::EvidenceState {
                field: "verifier.execution",
                reason: "proof reference requires a terminal execution status",
            });
        }
        Ok(())
    }
}

/// Budget and time envelope for a deterministic spine proof.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetTimeEnvelope {
    pub max_wall_time_ms: u64,
    pub max_model_calls: u64,
    pub max_tool_calls: u64,
    pub max_human_attention_ms: u64,
}

impl BudgetTimeEnvelope {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.max_wall_time_ms == 0 {
            return Err(EvaluationContractError::InvalidInterval {
                field: "budget.max_wall_time_ms",
            });
        }
        Ok(())
    }
}

/// Bounded proof brief for deterministic operational-spine properties.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalSpineProofBrief {
    pub exact_product_identity_and_contract_revisions: ProductIdentityRef,
    pub user_outcome_and_one_causal_property: String,
    pub task_and_environment: String,
    pub comparison_basis: ComparisonBasis,
    pub comparison_reason: Option<String>,
    pub expected_observable_and_exact_verifier: VerifierEvidenceRef,
    pub counter_metrics_and_known_confounders: Vec<String>,
    pub budget_and_time_envelope: BudgetTimeEnvelope,
    pub stop_kill_rollback_and_claim_boundary: String,
    pub delayed_observation_or_recurrence_window: Option<ObservationWindowSpec>,
    pub proof_ceiling: ProofCeiling,
}

impl OperationalSpineProofBrief {
    /// Validates exact identity, verifier scope, uncertainty and budget bounds.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.exact_product_identity_and_contract_revisions
            .validate()?;
        text(
            &self.user_outcome_and_one_causal_property,
            "brief.user_outcome_and_one_causal_property",
        )?;
        text(&self.task_and_environment, "brief.task_and_environment")?;
        text(
            &self.stop_kill_rollback_and_claim_boundary,
            "brief.stop_kill_rollback_and_claim_boundary",
        )?;
        texts(
            &self.counter_metrics_and_known_confounders,
            "brief.counter_metrics_and_known_confounders",
        )?;
        self.expected_observable_and_exact_verifier.validate()?;
        self.budget_and_time_envelope.validate()?;
        if self.comparison_basis == ComparisonBasis::NotApplicableWithReason {
            match &self.comparison_reason {
                Some(reason) => text(reason, "brief.comparison_reason")?,
                None => {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "brief.comparison_reason",
                        reason: "not-applicable comparison requires a reason",
                    });
                }
            }
        }
        if let Some(window) = &self.delayed_observation_or_recurrence_window {
            window.validate()?;
        }
        if self.proof_ceiling > self.expected_observable_and_exact_verifier.proof_ceiling {
            return Err(EvaluationContractError::ProofOverclaim);
        }
        Ok(())
    }
}

/// Equivalence class for a comparative budget ledger.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BudgetEquivalence {
    Exact,
    TokenMatched,
    ComputeMatched,
    CostMatched,
    NonEquivalent,
    Unknown,
}

/// One arm's measured resource/cost evidence.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetEvidence {
    pub arm_id: String,
    pub inference_tokens: u64,
    pub cache_tokens: u64,
    pub reasoning_tokens: u64,
    pub model_cost_micros: u64,
    pub model_calls: u64,
    pub retries: u64,
    pub tool_calls: u64,
    pub process_calls: u64,
    pub verifier_calls: u64,
    pub cpu_ms: u64,
    pub ram_mb_peak: u64,
    pub disk_bytes: u64,
    pub network_bytes: u64,
    pub queue_wait_ms: u64,
    pub wall_time_ms: u64,
    pub human_attention_ms: u64,
    pub hidden_background_cost_micros: u64,
}

impl BudgetEvidence {
    /// Validates arm identity; zero measurements remain valid observations.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.arm_id, "budget.arm_id")
    }
}

/// Immutable comparison budget ledger.  It records equivalence; it does not
/// infer equivalence from matching-looking fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetEquivalenceLedger {
    pub ledger_id: ContractId,
    pub arm_ids_and_exact_product_route_profiles: Vec<String>,
    pub arm_evidence: Vec<BudgetEvidence>,
    pub equivalence: BudgetEquivalence,
    pub mismatch_and_claim_limit: Option<String>,
}

impl BudgetEquivalenceLedger {
    /// Validates arm uniqueness and explicit mismatch handling.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        unique_texts(
            &self.arm_ids_and_exact_product_route_profiles,
            "budget.arm_ids_and_exact_product_route_profiles",
        )?;
        if self.arm_evidence.len() < 2 {
            return Err(EvaluationContractError::EvidenceState {
                field: "budget.arm_evidence",
                reason: "comparative ledger requires at least two arms",
            });
        }
        let ids: Vec<String> = self
            .arm_evidence
            .iter()
            .map(|evidence| evidence.arm_id.clone())
            .collect();
        unique_texts(&ids, "budget.arm_evidence.arm_id")?;
        for evidence in &self.arm_evidence {
            evidence.validate()?;
            if !self
                .arm_ids_and_exact_product_route_profiles
                .iter()
                .any(|arm| arm == &evidence.arm_id)
            {
                return Err(EvaluationContractError::EvidenceState {
                    field: "budget.arm_evidence.arm_id",
                    reason: "evidence arm is absent from declared profiles",
                });
            }
        }
        if matches!(
            self.equivalence,
            BudgetEquivalence::NonEquivalent | BudgetEquivalence::Unknown
        ) && self.mismatch_and_claim_limit.is_none()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "budget.mismatch_and_claim_limit",
                reason: "non-equivalent or unknown budget requires an explicit claim limit",
            });
        }
        if let Some(limit) = &self.mismatch_and_claim_limit {
            text(limit, "budget.mismatch_and_claim_limit")?;
        }
        Ok(())
    }
}

/// A full plan required for stochastic/comparative/population/generalization claims.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductEvaluationPlan {
    pub plan_id: ContractId,
    pub claim_kinds: Vec<ClaimKind>,
    pub brief: OperationalSpineProofBrief,
    pub target_user_task_population_and_strata: String,
    pub immutable_sample_and_cluster_unit: String,
    pub pilot_holdout_and_contamination_boundaries: String,
    pub comparison_arms_and_budget_equivalence: BudgetEquivalenceLedger,
    pub randomization_pairing_blocking_seed_and_order: String,
    pub route_model_tool_environment_freeze: String,
    pub primary_outcome_quality_floor_and_countermetrics: String,
    pub pilot_variance_and_dependence: String,
    pub minimum_detectable_effect_or_noninferiority_margin: String,
    pub precision_power_or_declared_estimation_policy: String,
    pub evaluator_oracle_and_independence_profile: String,
    pub leakage_and_prior_run_visibility_controls: String,
    pub failed_excluded_censored_trial_policy: String,
    pub delayed_outcome_and_recurrence_policy: String,
    pub preregistered_analysis_and_final_disposition: String,
}

impl ProductEvaluationPlan {
    /// Validates plan completeness and prevents budget/uncertainty erasure.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.claim_kinds.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "plan.claim_kinds",
            });
        }
        self.brief.validate()?;
        self.comparison_arms_and_budget_equivalence.validate()?;
        for (field, value) in [
            (
                "plan.target_user_task_population_and_strata",
                &self.target_user_task_population_and_strata,
            ),
            (
                "plan.immutable_sample_and_cluster_unit",
                &self.immutable_sample_and_cluster_unit,
            ),
            (
                "plan.pilot_holdout_and_contamination_boundaries",
                &self.pilot_holdout_and_contamination_boundaries,
            ),
            (
                "plan.randomization_pairing_blocking_seed_and_order",
                &self.randomization_pairing_blocking_seed_and_order,
            ),
            (
                "plan.route_model_tool_environment_freeze",
                &self.route_model_tool_environment_freeze,
            ),
            (
                "plan.primary_outcome_quality_floor_and_countermetrics",
                &self.primary_outcome_quality_floor_and_countermetrics,
            ),
            (
                "plan.pilot_variance_and_dependence",
                &self.pilot_variance_and_dependence,
            ),
            (
                "plan.minimum_detectable_effect_or_noninferiority_margin",
                &self.minimum_detectable_effect_or_noninferiority_margin,
            ),
            (
                "plan.precision_power_or_declared_estimation_policy",
                &self.precision_power_or_declared_estimation_policy,
            ),
            (
                "plan.evaluator_oracle_and_independence_profile",
                &self.evaluator_oracle_and_independence_profile,
            ),
            (
                "plan.leakage_and_prior_run_visibility_controls",
                &self.leakage_and_prior_run_visibility_controls,
            ),
            (
                "plan.failed_excluded_censored_trial_policy",
                &self.failed_excluded_censored_trial_policy,
            ),
            (
                "plan.delayed_outcome_and_recurrence_policy",
                &self.delayed_outcome_and_recurrence_policy,
            ),
            (
                "plan.preregistered_analysis_and_final_disposition",
                &self.preregistered_analysis_and_final_disposition,
            ),
        ] {
            text(value, field)?;
        }
        Ok(())
    }
}

/// Censoring or exposure record for a trial/window.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CensoringRecord {
    pub reason: String,
    pub observed_until: Option<ClockReading>,
    pub exposure: String,
}

impl CensoringRecord {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.reason, "censoring.reason")?;
        text(&self.exposure, "censoring.exposure")?;
        if let Some(clock) = self.observed_until {
            clock
                .validate()
                .map_err(|_| EvaluationContractError::InvalidDependency {
                    field: "censoring.observed_until",
                    reason: "invalid clock reading",
                })?;
        }
        Ok(())
    }
}

/// One immutable trial/result record retained by a report or evaluator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialRecord {
    pub trial_id: ContractId,
    pub plan_ref: ContractId,
    pub arm_id: String,
    pub request_id: Option<RequestId>,
    pub status: TrialStatus,
    pub outcome: TrialOutcome,
    pub receipt_ref: Option<ReceiptId>,
    pub evidence_refs: Vec<ArtifactId>,
    pub budget_evidence: Option<BudgetEvidence>,
    pub censoring: Option<CensoringRecord>,
    pub contamination_reason: Option<String>,
}

impl TrialRecord {
    /// Validates outcome/status agreement and preserves unknown/censored reasons.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.arm_id, "trial.arm_id")?;
        self.outcome.validate()?;
        if matches!(
            self.status,
            TrialStatus::Succeeded | TrialStatus::Failed | TrialStatus::Partial
        ) && self.evidence_refs.is_empty()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "trial.evidence_refs",
                reason: "terminal observed trial requires evidence references",
            });
        }
        if self.status == TrialStatus::Unknown && !self.outcome.is_uncertain() {
            return Err(EvaluationContractError::EvidenceState {
                field: "trial.outcome",
                reason: "unknown trial status requires unknown or inconclusive outcome",
            });
        }
        if matches!(self.status, TrialStatus::Censored | TrialStatus::Excluded)
            && self.censoring.is_none()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "trial.censoring",
                reason: "censored or excluded trial requires a censoring record",
            });
        }
        if let Some(censoring) = &self.censoring {
            censoring.validate()?;
        }
        if matches!(self.status, TrialStatus::Contaminated) && self.contamination_reason.is_none() {
            return Err(EvaluationContractError::EvidenceState {
                field: "trial.contamination_reason",
                reason: "contaminated trial requires a reason",
            });
        }
        if let Some(reason) = &self.contamination_reason {
            text(reason, "trial.contamination_reason")?;
        }
        if let Some(budget) = &self.budget_evidence {
            budget.validate()?;
        }
        Ok(())
    }
}

/// Delayed outcome observation state.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationWindowStatus {
    Open,
    Matured,
    Regressed,
    CensoredOrInconclusive,
}

/// Declared observation interval and recurrence policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationWindowSpec {
    pub window_id: ContractId,
    pub duration_ms: u64,
    pub recurrence_measure: String,
    pub status: ObservationWindowStatus,
}

impl ObservationWindowSpec {
    /// Validates positive duration and explicit recurrence measure.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.duration_ms == 0 {
            return Err(EvaluationContractError::InvalidInterval {
                field: "observation_window.duration_ms",
            });
        }
        text(
            &self.recurrence_measure,
            "observation_window.recurrence_measure",
        )
    }
}

/// One delayed product outcome observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeObservation {
    pub observation_id: ContractId,
    pub observed_at: ClockReading,
    pub outcome: TrialOutcome,
    pub downstream_rework: String,
    pub maintenance_or_rollback: String,
    pub evidence_refs: Vec<ArtifactId>,
    pub censored: Option<CensoringRecord>,
}

impl OutcomeObservation {
    /// Validates delayed observation without rewriting the original trial.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.observed_at
            .validate()
            .map_err(|_| EvaluationContractError::InvalidDependency {
                field: "outcome_observation.observed_at",
                reason: "invalid clock reading",
            })?;
        self.outcome.validate()?;
        text(
            &self.downstream_rework,
            "outcome_observation.downstream_rework",
        )?;
        text(
            &self.maintenance_or_rollback,
            "outcome_observation.maintenance_or_rollback",
        )?;
        if self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "outcome_observation.evidence_refs",
            });
        }
        if let Some(censored) = &self.censored {
            censored.validate()?;
        }
        Ok(())
    }
}

/// Durable delayed-outcome window linked to an accepted task/artifact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductOutcomeObservationWindow {
    pub window_id: ContractId,
    pub accepted_task_ref: TaskId,
    pub artifact_refs: Vec<ArtifactId>,
    pub release_ref: Option<ArtifactId>,
    pub opened_at: ClockReading,
    pub closes_at: Option<ClockReading>,
    pub status: ObservationWindowStatus,
    pub observations: Vec<OutcomeObservation>,
    pub evaluator_revision: ContractVersion,
    pub rollback_reconciliation: Option<String>,
}

impl ProductOutcomeObservationWindow {
    /// Validates delayed evidence and makes open/censored states explicit.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.artifact_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "outcome_window.artifact_refs",
            });
        }
        self.opened_at
            .validate()
            .map_err(|_| EvaluationContractError::InvalidDependency {
                field: "outcome_window.opened_at",
                reason: "invalid clock reading",
            })?;
        if let Some(closes_at) = self.closes_at {
            closes_at
                .validate()
                .map_err(|_| EvaluationContractError::InvalidDependency {
                    field: "outcome_window.closes_at",
                    reason: "invalid clock reading",
                })?;
            if let (Some(opened), Some(closed)) =
                (self.opened_at.known_time_ms, closes_at.known_time_ms)
                && closed < opened
            {
                return Err(EvaluationContractError::InvalidInterval {
                    field: "outcome_window.opened_at/closes_at",
                });
            }
        }
        if self.status != ObservationWindowStatus::Open && self.observations.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "outcome_window.observations",
                reason: "closed window requires at least one observation",
            });
        }
        for observation in &self.observations {
            observation.validate()?;
        }
        if matches!(
            self.status,
            ObservationWindowStatus::Regressed | ObservationWindowStatus::CensoredOrInconclusive
        ) && self.rollback_reconciliation.is_none()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "outcome_window.rollback_reconciliation",
                reason: "regressed or censored window requires reconciliation text",
            });
        }
        if let Some(reconciliation) = &self.rollback_reconciliation {
            text(reconciliation, "outcome_window.rollback_reconciliation")?;
        }
        Ok(())
    }
}

/// Evidence-bound input accepted by a report renderer.  It cannot alter any
/// objective, trial, verifier, finish or release state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReportInput {
    pub input_id: ContractId,
    pub objective_ref: ContractId,
    pub plan_ref: Option<ContractId>,
    pub product_identity: ProductIdentityRef,
    pub claim_scope: EvidenceScope,
    pub claimed_proof_ceiling: ProofCeiling,
    pub available_proof_ceiling: ProofCeiling,
    pub trial_refs: Vec<ContractId>,
    pub evidence_refs: Vec<ArtifactId>,
    pub uncertainty: String,
    pub status: ProductEvidenceStatus,
    pub outcome_window_ref: Option<ContractId>,
}

impl EvaluationReportInput {
    /// Validates evidence binding and refuses proof overclaims.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.product_identity.validate()?;
        if self.trial_refs.is_empty() && self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "report_input.evidence_refs_or_trial_refs",
            });
        }
        text(&self.uncertainty, "report_input.uncertainty")?;
        if self.claimed_proof_ceiling > self.available_proof_ceiling {
            return Err(EvaluationContractError::ProofOverclaim);
        }
        if matches!(
            self.status,
            ProductEvidenceStatus::CurrentlyVerified | ProductEvidenceStatus::Matured
        ) && self.uncertainty.eq_ignore_ascii_case("unknown")
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "report_input.uncertainty",
                reason: "verified or matured input cannot declare unknown uncertainty",
            });
        }
        Ok(())
    }
}

/// Compatibility alias used by report consumers.
pub type ReportInput = EvaluationReportInput;
/// Compatibility alias for a delayed product outcome record.
pub type DelayedOutcomeWindow = ProductOutcomeObservationWindow;
/// Compatibility alias for a trial/outcome record.
pub type Trial = TrialRecord;

/// Public projection for the C0-13 surface-types slice.
pub mod surface_types {
    pub use super::{
        BudgetEquivalence, BudgetEquivalenceLedger, BudgetEvidence, BudgetTimeEnvelope,
        CensoringRecord, ClaimKind, ComparisonBasis, DelayedOutcomeWindow, EvaluationReportInput,
        EvidenceScope, GraphEvidenceRef, ObjectiveStatus, ObservationWindowSpec,
        ObservationWindowStatus, OperationalSpineProofBrief, OutcomeObservation,
        ProductEvaluationPlan, ProductEvidenceStatus, ProductIdentityRef,
        ProductOutcomeObservationWindow, RecoveryAcceptanceProfile, RecoveryGap,
        RecoveryProfileStatus, ReportInput, Trial, TrialOutcome, TrialRecord, TrialStatus,
        UserOutcomeObjectiveState, VerifierEvidenceRef,
    };
}

/// Public projection for the validation-compatibility slice.
pub mod validation_compatibility {
    pub use super::EvaluationContractError;
}

/// Small, deterministic malformed-consumer fixtures.  They are data only;
/// no fixture can be mistaken for an evaluator result or authority decision.
pub mod negative_consumer_fixtures {
    use serde_json::{Value, json};

    /// JSON with an unknown field, rejected by every deny-unknown-fields surface.
    pub fn unknown_field() -> Value {
        json!({"objective_id": "objective-1", "unknown": true})
    }

    /// JSON with a blank required text value.
    pub fn blank_required_text() -> Value {
        json!({"owner": " ", "intended_user_outcome": ""})
    }

    /// JSON preserving an explicit unknown outcome rather than a false success.
    pub fn explicit_unknown_outcome() -> Value {
        json!({"kind": "UNKNOWN", "reason": "provider did not reconcile"})
    }

    /// JSON for a censoring record without its required reason.
    pub fn censored_without_reason() -> Value {
        json!({"reason": "", "exposure": "partial"})
    }
}

/// Graph evidence can be attached without making the graph an evaluation oracle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEvidenceRef {
    pub revision: GraphRevision,
    pub freshness: GraphFreshness,
    pub scope: String,
    pub evidence_refs: Vec<ArtifactId>,
}

impl GraphEvidenceRef {
    /// Validates a graph evidence attachment's scope and artifact binding.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.scope, "graph_evidence.scope")?;
        if self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "graph_evidence.evidence_refs",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! valid {
        ($type:ty, $value:expr) => {{
            match <$type>::new($value) {
                Ok(value) => value,
                Err(error) => panic!("invalid test value: {error}"),
            }
        }};
    }

    fn product_identity() -> ProductIdentityRef {
        ProductIdentityRef {
            product_id: valid!(ProductId, "product-1"),
            source_revision: "source-1".to_owned(),
            contract_revisions: vec![CONTRACT_VERSION],
        }
    }

    fn budget() -> BudgetEquivalenceLedger {
        BudgetEquivalenceLedger {
            ledger_id: valid!(ContractId, "ledger-1"),
            arm_ids_and_exact_product_route_profiles: vec![
                "control".to_owned(),
                "treatment".to_owned(),
            ],
            arm_evidence: vec![
                BudgetEvidence {
                    arm_id: "control".to_owned(),
                    wall_time_ms: 1,
                    ..Default::default()
                },
                BudgetEvidence {
                    arm_id: "treatment".to_owned(),
                    wall_time_ms: 1,
                    ..Default::default()
                },
            ],
            equivalence: BudgetEquivalence::Exact,
            mismatch_and_claim_limit: None,
        }
    }

    #[test]
    fn unknown_trial_is_not_a_success_alias() {
        let trial = TrialRecord {
            trial_id: valid!(ContractId, "trial-1"),
            plan_ref: valid!(ContractId, "plan-1"),
            arm_id: "control".to_owned(),
            request_id: None,
            status: TrialStatus::Unknown,
            outcome: TrialOutcome::Unknown {
                reason: "provider stopped".to_owned(),
            },
            receipt_ref: None,
            evidence_refs: vec![],
            budget_evidence: None,
            censoring: None,
            contamination_reason: None,
        };
        assert!(trial.validate().is_ok());
        assert!(trial.outcome.is_uncertain());
    }

    #[test]
    fn unknown_budget_requires_claim_limit() {
        let mut ledger = budget();
        ledger.equivalence = BudgetEquivalence::Unknown;
        assert!(ledger.validate().is_err());
        ledger.mismatch_and_claim_limit = Some("operating-point only".to_owned());
        assert!(ledger.validate().is_ok());
    }

    #[test]
    fn proof_ceiling_cannot_be_overclaimed() {
        let verifier = VerifierEvidenceRef {
            run_id: valid!(RequestId, "run-1"),
            verifier_id: valid!(ContractId, "verifier-1"),
            scope: "one task".to_owned(),
            execution: ExecutionStatus::Succeeded,
            outcome: VerificationOutcome::Pass,
            proof_ceiling: ProofCeiling::ScopedVerification,
            evidence_refs: vec![valid!(ArtifactId, "artifact-1")],
        };
        let brief = OperationalSpineProofBrief {
            exact_product_identity_and_contract_revisions: product_identity(),
            user_outcome_and_one_causal_property: "recovery".to_owned(),
            task_and_environment: "fixture".to_owned(),
            comparison_basis: ComparisonBasis::ExactPrechangeBehavior,
            comparison_reason: None,
            expected_observable_and_exact_verifier: verifier,
            counter_metrics_and_known_confounders: vec!["latency".to_owned()],
            budget_and_time_envelope: BudgetTimeEnvelope {
                max_wall_time_ms: 1,
                max_model_calls: 0,
                max_tool_calls: 0,
                max_human_attention_ms: 0,
            },
            stop_kill_rollback_and_claim_boundary: "no release claim".to_owned(),
            delayed_observation_or_recurrence_window: None,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        };
        assert_eq!(
            brief.validate(),
            Err(EvaluationContractError::ProofOverclaim)
        );
    }

    #[test]
    fn censoring_requires_reason() {
        let record = CensoringRecord {
            reason: " ".to_owned(),
            observed_until: None,
            exposure: "partial".to_owned(),
        };
        assert!(record.validate().is_err());
    }

    #[test]
    fn graph_evidence_requires_artifacts() {
        let evidence = GraphEvidenceRef {
            revision: match GraphRevision::new(1) {
                Ok(value) => value,
                Err(error) => panic!("invalid test revision: {error}"),
            },
            freshness: GraphFreshness::Current,
            scope: "crate".to_owned(),
            evidence_refs: vec![],
        };
        assert!(evidence.validate().is_err());
    }

    #[test]
    fn negative_fixtures_are_non_authoritative_data() {
        assert_eq!(
            negative_consumer_fixtures::explicit_unknown_outcome()["kind"],
            "UNKNOWN"
        );
        assert_eq!(
            negative_consumer_fixtures::censored_without_reason()["reason"],
            ""
        );
    }
}
