//! Evidence-bound product evaluation and comparison.
//!
//! This crate is deliberately a projection owner: it validates exact anchors,
//! compares already captured trials, and emits a reproducible report.  It does
//! not execute instruments, manufacture missing observations, or grant finish
//! or release authority.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, ClockReading, ContractId, ContractVersion};
use eliot_evaluation_contracts::{
    BudgetEquivalence, BudgetEquivalenceLedger, ComparisonBasis, EvaluationContractError,
    EvaluationReportInput, EvidenceScope, ProductEvaluationPlan, ProductEvidenceStatus,
    ProductIdentityRef, TrialOutcome, TrialRecord, TrialStatus,
};
use eliot_instrument_api::TaintState;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Stable identity of this implementation surface.
pub const CONTRACT_NAME: &str = "eliot.instrument.product-evaluation";
/// Wire revision of this implementation surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProductEvaluationError {
    #[error("evaluation contract rejected input: {0}")]
    Contract(#[from] EvaluationContractError),
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    #[error("duplicate identity in {field}: {identity}")]
    DuplicateIdentity {
        field: &'static str,
        identity: String,
    },
    #[error("trial {trial_id} refers to unknown plan {plan_id}")]
    WrongPlan {
        trial_id: ContractId,
        plan_id: ContractId,
    },
    #[error("trial {trial_id} refers to undeclared arm {arm_id}")]
    UnknownArm {
        trial_id: ContractId,
        arm_id: String,
    },
    #[error("comparison cannot be interpreted: {0}")]
    Comparison(String),
    #[error("canonical report serialization failed: {0}")]
    Serialization(String),
}

fn text(value: &str, field: &'static str) -> Result<(), ProductEvaluationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ProductEvaluationError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn unique<T: Ord + Clone + std::fmt::Debug>(
    values: &[T],
    field: &'static str,
) -> Result<(), ProductEvaluationError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(ProductEvaluationError::DuplicateIdentity {
                field,
                identity: format!("{value:?}"),
            });
        }
    }
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<String, ProductEvaluationError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ProductEvaluationError::Serialization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Exact source anchor for a load-bearing evaluation claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAtom {
    pub source_ref: ArtifactId,
    pub exact_anchor: String,
    pub line_range_or_byte_range: String,
    pub observed_at: ClockReading,
    pub scope: String,
    pub parser_or_tool: String,
    pub taint_status: TaintState,
}

impl EvidenceAtom {
    pub fn validate(&self) -> Result<(), ProductEvaluationError> {
        for (value, field) in [
            (&self.exact_anchor, "evidence_atom.exact_anchor"),
            (&self.line_range_or_byte_range, "evidence_atom.range"),
            (&self.scope, "evidence_atom.scope"),
            (&self.parser_or_tool, "evidence_atom.parser_or_tool"),
        ] {
            text(value, field)?;
        }
        self.observed_at
            .validate()
            .map_err(|_| ProductEvaluationError::Comparison("invalid evidence clock".into()))
    }
}

/// Aggregate for one comparison arm.  Unknown and censored trials remain visible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmComparison {
    pub arm_id: String,
    pub trial_count: u64,
    pub observed_count: u64,
    pub improved_count: u64,
    pub unchanged_count: u64,
    pub regressed_count: u64,
    pub uncertain_count: u64,
    pub censored_count: u64,
    pub total_wall_time_ms: u128,
    pub total_model_cost_micros: u128,
}

impl ArmComparison {
    fn new(arm_id: String) -> Self {
        Self {
            arm_id,
            trial_count: 0,
            observed_count: 0,
            improved_count: 0,
            unchanged_count: 0,
            regressed_count: 0,
            uncertain_count: 0,
            censored_count: 0,
            total_wall_time_ms: 0,
            total_model_cost_micros: 0,
        }
    }
}

/// Deterministic comparison result, including the explicit claim boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonResult {
    pub basis: ComparisonBasis,
    pub budget_equivalence: BudgetEquivalence,
    pub arms: Vec<ArmComparison>,
    pub included_trial_ids: Vec<ContractId>,
    pub excluded_trial_ids: Vec<ContractId>,
    pub uncertainty: String,
    pub claim_boundary: String,
    pub revision: String,
}

/// Evidence atom plus the immutable comparison projection consumed by renderers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductEvaluationReport {
    pub report_id: ContractId,
    pub product_identity: ProductIdentityRef,
    pub plan_ref: ContractId,
    pub claim_scope: EvidenceScope,
    pub status: ProductEvidenceStatus,
    pub comparison: ComparisonResult,
    pub evidence_atoms: Vec<EvidenceAtom>,
    pub evidence_refs: Vec<ArtifactId>,
    pub report_revision: String,
}

impl ProductEvaluationReport {
    pub fn validate(&self) -> Result<(), ProductEvaluationError> {
        self.product_identity.validate()?;
        if self.evidence_atoms.is_empty() && self.evidence_refs.is_empty() {
            return Err(ProductEvaluationError::EmptyCollection {
                field: "report.evidence",
            });
        }
        unique(
            &self.comparison.included_trial_ids,
            "report.included_trial_ids",
        )?;
        unique(
            &self.comparison.excluded_trial_ids,
            "report.excluded_trial_ids",
        )?;
        for atom in &self.evidence_atoms {
            atom.validate()?;
        }
        if self.comparison.uncertainty.trim().is_empty()
            || self.comparison.claim_boundary.trim().is_empty()
        {
            return Err(ProductEvaluationError::InvalidText {
                field: "report.claim_boundary",
            });
        }
        Ok(())
    }
}

/// Compare an already captured plan and trial set without treating missing data as success.
pub fn compare_trials(
    plan: &ProductEvaluationPlan,
    trials: &[TrialRecord],
) -> Result<ComparisonResult, ProductEvaluationError> {
    plan.validate()?;
    if trials.is_empty() {
        return Err(ProductEvaluationError::EmptyCollection { field: "trials" });
    }
    let declared: BTreeSet<String> = plan
        .comparison_arms_and_budget_equivalence
        .arm_ids_and_exact_product_route_profiles
        .iter()
        .cloned()
        .collect();
    let mut arms: BTreeMap<String, ArmComparison> = declared
        .iter()
        .cloned()
        .map(|id| (id.clone(), ArmComparison::new(id)))
        .collect();
    let mut ids = BTreeSet::new();
    let mut included = Vec::new();
    let mut excluded = Vec::new();
    for trial in trials {
        trial.validate()?;
        if trial.plan_ref != plan.plan_id {
            return Err(ProductEvaluationError::WrongPlan {
                trial_id: trial.trial_id.clone(),
                plan_id: trial.plan_ref.clone(),
            });
        }
        if !declared.contains(&trial.arm_id) {
            return Err(ProductEvaluationError::UnknownArm {
                trial_id: trial.trial_id.clone(),
                arm_id: trial.arm_id.clone(),
            });
        }
        if !ids.insert(trial.trial_id.clone()) {
            return Err(ProductEvaluationError::DuplicateIdentity {
                field: "trials",
                identity: format!("{:?}", trial.trial_id),
            });
        }
        let arm =
            arms.get_mut(&trial.arm_id)
                .ok_or_else(|| ProductEvaluationError::UnknownArm {
                    trial_id: trial.trial_id.clone(),
                    arm_id: trial.arm_id.clone(),
                })?;
        arm.trial_count += 1;
        let usable = !matches!(
            trial.status,
            TrialStatus::Excluded
                | TrialStatus::Censored
                | TrialStatus::Contaminated
                | TrialStatus::Unknown
        );
        if usable {
            included.push(trial.trial_id.clone());
            arm.observed_count += 1;
        } else {
            excluded.push(trial.trial_id.clone());
        }
        match &trial.outcome {
            TrialOutcome::Improved { .. } => arm.improved_count += 1,
            TrialOutcome::NoChange { .. } => arm.unchanged_count += 1,
            TrialOutcome::Regressed { .. } => arm.regressed_count += 1,
            TrialOutcome::Inconclusive { .. } | TrialOutcome::Unknown { .. } => {
                arm.uncertain_count += 1
            }
        }
        if matches!(trial.status, TrialStatus::Censored | TrialStatus::Excluded) {
            arm.censored_count += 1;
        }
        if let Some(budget) = &trial.budget_evidence {
            arm.total_wall_time_ms += u128::from(budget.wall_time_ms);
            arm.total_model_cost_micros += u128::from(budget.model_cost_micros);
        }
    }
    let mut arms: Vec<_> = arms.into_values().collect();
    arms.retain(|arm| arm.trial_count != 0);
    let ledger = &plan.comparison_arms_and_budget_equivalence;
    let uncertainty = comparison_uncertainty(ledger, &arms, excluded.len());
    let claim_boundary = claim_boundary(ledger.equivalence, excluded.len());
    let basis = plan.brief.comparison_basis;
    let revision = digest(&(
        basis,
        ledger,
        &arms,
        &included,
        &excluded,
        &uncertainty,
        &claim_boundary,
    ))?;
    Ok(ComparisonResult {
        basis,
        budget_equivalence: ledger.equivalence,
        arms,
        included_trial_ids: included,
        excluded_trial_ids: excluded,
        uncertainty,
        claim_boundary,
        revision,
    })
}

fn comparison_uncertainty(
    ledger: &BudgetEquivalenceLedger,
    arms: &[ArmComparison],
    excluded: usize,
) -> String {
    if excluded != 0 {
        return format!("{excluded} trial(s) excluded, censored, contaminated, or unknown");
    }
    if arms.iter().any(|arm| arm.uncertain_count != 0) {
        return "one or more observed outcomes are inconclusive or unknown".into();
    }
    match ledger.equivalence {
        BudgetEquivalence::Exact => "no unresolved uncertainty recorded".into(),
        _ => "budget equivalence is not exact; comparative claims are bounded".into(),
    }
}

fn claim_boundary(equivalence: BudgetEquivalence, excluded: usize) -> String {
    if excluded != 0 {
        return "operating-point evidence only; excluded or censored observations prevent population claims".into();
    }
    match equivalence {
        BudgetEquivalence::Exact => {
            "comparison is limited to the declared task, arms, route profiles, and observed scope"
                .into()
        }
        _ => "comparison cannot support an equal-budget claim; retain the declared mismatch limit"
            .into(),
    }
}

/// Build a validated report and bind its revision to every source input.
pub fn build_report(
    report_id: ContractId,
    product_identity: ProductIdentityRef,
    plan: &ProductEvaluationPlan,
    trials: &[TrialRecord],
    evidence_atoms: Vec<EvidenceAtom>,
    evidence_refs: Vec<ArtifactId>,
    status: ProductEvidenceStatus,
) -> Result<ProductEvaluationReport, ProductEvaluationError> {
    let comparison = compare_trials(plan, trials)?;
    for atom in &evidence_atoms {
        atom.validate()?;
    }
    if evidence_atoms.is_empty() && evidence_refs.is_empty() {
        return Err(ProductEvaluationError::EmptyCollection {
            field: "report.evidence",
        });
    }
    let mut report = ProductEvaluationReport {
        report_id,
        product_identity,
        plan_ref: plan.plan_id.clone(),
        claim_scope: EvidenceScope::ProductOutcome,
        status,
        comparison,
        evidence_atoms,
        evidence_refs,
        report_revision: String::new(),
    };
    report.report_revision = digest(&report)?;
    report.validate()?;
    Ok(report)
}

/// Adapt a report to the foundation report-input contract without raising its proof ceiling.
pub fn report_input(
    input_id: ContractId,
    objective_ref: ContractId,
    report: &ProductEvaluationReport,
    claimed_proof_ceiling: eliot_receipts::ProofCeiling,
    available_proof_ceiling: eliot_receipts::ProofCeiling,
) -> Result<EvaluationReportInput, ProductEvaluationError> {
    report.validate()?;
    let input = EvaluationReportInput {
        input_id,
        objective_ref,
        plan_ref: Some(report.plan_ref.clone()),
        product_identity: report.product_identity.clone(),
        claim_scope: report.claim_scope,
        claimed_proof_ceiling,
        available_proof_ceiling,
        trial_refs: report
            .comparison
            .included_trial_ids
            .iter()
            .chain(report.comparison.excluded_trial_ids.iter())
            .cloned()
            .collect(),
        evidence_refs: report.evidence_refs.clone(),
        uncertainty: report.comparison.uncertainty.clone(),
        status: report.status,
        outcome_window_ref: None,
    };
    input.validate()?;
    Ok(input)
}

/// Public projection for consumers that only need comparison types.
pub mod comparison {
    pub use super::{ArmComparison, ComparisonResult, EvidenceAtom, ProductEvaluationReport};
}
