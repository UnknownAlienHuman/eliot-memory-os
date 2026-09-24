//! Matched-budget promotion proof for replay-diagnostic-only delivery.
//!
//! I12.24:76 — "Replay-only evidence cannot promote... binds the single
//! canonical BudgetEquivalenceLedger and ComplexityEconomicsDelta contracts
//! of I18.47... unmatched ledger or inconclusive complexity delta cannot
//! promote". This module carries that gate: a [`BudgetProof`] binds the
//! single canonical budget-equivalence ledger reference plus the
//! complexity-economics delta, and only a matched ledger with a conclusive
//! delta and matched-budget live shadow or canary evidence supports
//! promotion. [`stamp_outcome_budget`] stamps a validated proof onto an
//! [`OutcomeEvidence`] after the gate passes.

use crate::{ImprovementError, OutcomeEvidence};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComplexityEconomicsDelta {
    pub delta_ref: String,
    pub conclusive: bool,
    pub detail: String,
}

impl ComplexityEconomicsDelta {
    pub fn validate(&self) -> Result<(), ImprovementError> {
        if self.delta_ref.trim().is_empty() {
            return Err(ImprovementError::MissingField("delta_ref"));
        }
        if self.detail.trim().is_empty() {
            return Err(ImprovementError::MissingField("detail"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BudgetProof {
    pub budget_ledger_ref: String,
    pub ledger_matched: bool,
    pub complexity_delta: ComplexityEconomicsDelta,
    pub affected_check_refs: Vec<String>,
    pub live_shadow_refs: Vec<String>,
    pub live_canary_refs: Vec<String>,
    pub delayed_harm_window_ref: String,
}

impl BudgetProof {
    pub fn validate(&self) -> Result<(), ImprovementError> {
        if self.budget_ledger_ref.trim().is_empty() {
            return Err(ImprovementError::MissingBudgetProof);
        }
        self.complexity_delta.validate()?;
        if self.affected_check_refs.is_empty()
            || self
                .affected_check_refs
                .iter()
                .any(|value| value.trim().is_empty())
        {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires affected checks under the matched budget",
            ));
        }
        if self.delayed_harm_window_ref.trim().is_empty() {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires delayed-harm visibility",
            ));
        }
        Ok(())
    }

    pub fn supports_promotion(&self) -> Result<(), ImprovementError> {
        self.validate()?;
        if !self.ledger_matched {
            return Err(ImprovementError::BudgetGateViolation(
                "unmatched budget-equivalence ledger cannot promote",
            ));
        }
        if !self.complexity_delta.conclusive {
            return Err(ImprovementError::BudgetGateViolation(
                "inconclusive complexity-economics delta cannot promote",
            ));
        }
        if self.live_shadow_refs.is_empty() && self.live_canary_refs.is_empty() {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires matched-budget live shadow or canary evidence",
            ));
        }
        Ok(())
    }
}

pub fn require_matched_budget_for_promotion(
    proof: Option<&BudgetProof>,
) -> Result<(), ImprovementError> {
    match proof {
        None => Err(ImprovementError::MissingBudgetProof),
        Some(p) => p.supports_promotion(),
    }
}

pub fn stamp_outcome_budget(
    outcome: &mut OutcomeEvidence,
    proof: &BudgetProof,
) -> Result<(), ImprovementError> {
    proof.supports_promotion()?;
    outcome.budget_ledger_ref = proof.budget_ledger_ref.clone();
    outcome.complexity_delta_ref = proof.complexity_delta.delta_ref.clone();
    outcome.economics_conclusive = true;
    outcome.affected_check_refs = proof.affected_check_refs.clone();
    outcome.live_shadow_refs = proof.live_shadow_refs.clone();
    outcome.live_canary_refs = proof.live_canary_refs.clone();
    outcome.delayed_harm_window_ref = proof.delayed_harm_window_ref.clone();
    Ok(())
}
