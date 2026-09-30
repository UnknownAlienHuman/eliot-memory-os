//! Matched-budget promotion proof for replay-diagnostic-only delivery.
//!
//! I12.24:76 — "Replay-only evidence cannot promote… The evaluation record
//! binds the single canonical `BudgetEquivalenceLedger` and
//! `ComplexityEconomicsDelta` contracts of I18.47… An unmatched ledger or
//! inconclusive complexity delta cannot promote the candidate merely because
//! replay or a local metric improved."
//!
//! I12.24:68 — "affected checks + matched-budget live shadow/canary on
//! untouched work", and I12.24:69 — "delayed outcome/rework/maintenance
//! window and rollback reconciliation", are the remaining legs of the same
//! pipeline step and are required here too.
//!
//! A [`BudgetProof`] therefore carries the ORIGINAL canonical
//! [`BudgetEquivalenceLedger`] value itself — not a free-text name for one —
//! and validates it with that contract's own `validate()`. Matchedness is
//! derived from the ledger's recorded `equivalence`, so no caller-set Boolean
//! can promote. The complexity-economics delta carries the six I18.47
//! [`ComplexityEconomicsDelta`] slots, and its conclusiveness is derived from
//! whether those slots are actually recorded. I18.47:25 makes both records
//! mandatory in every load-bearing evaluation; I18.47:87 ("Intentionally
//! unequal budgets may support an operating-point choice, not a causal
//! superiority claim") is why `NON_EQUIVALENT` and `UNKNOWN` are refused here
//! even though the canonical ledger accepts them as a recorded operating
//! point.
//!
//! [`stamp_outcome_budget`] stamps a validated proof onto an
//! [`OutcomeEvidence`], binding the outcome to the same canonical records the
//! gate just checked.

use eliot_evaluation_contracts::{
    BudgetEquivalence, BudgetEquivalenceLedger, EvaluationContractError,
};
use serde::{Deserialize, Serialize};

use crate::{ImprovementError, OutcomeEvidence};

/// The six I18.47:78-84 `ComplexityEconomicsDelta` slots, recorded verbatim.
///
/// The `delta_ref` is the identity of the recorded delta record; it is the
/// binding the outcome carries, not a substitute for the six slots. There is
/// no `conclusive` field: [`ComplexityEconomicsDelta::is_conclusive`] derives
/// the answer from the recorded slots, so a caller cannot assert it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComplexityEconomicsDelta {
    pub delta_ref: String,
    /// I18.47:79 — code, config, schema, process and contract surface.
    pub code_config_schema_process_and_contract_surface: String,
    /// I18.47:80 — operator and agent ceremony.
    pub operator_and_agent_ceremony: String,
    /// I18.47:81 — new failure, recovery, migration and rollback paths.
    pub new_failure_recovery_migration_and_rollback_paths: String,
    /// I18.47:82 — maintenance, security, privacy and observability burden.
    pub maintenance_security_privacy_and_observability_burden: String,
    /// I18.47:83 — measured latency, resource and product delta.
    pub measured_latency_resource_and_product_delta: String,
    /// I18.47:84 — validity scope and retirement condition.
    pub validity_scope_and_retirement_condition: String,
}

impl ComplexityEconomicsDelta {
    /// Refuses a delta record that names nothing. The six content slots are
    /// not checked here: an unrecorded slot is an INCONCLUSIVE delta
    /// (I12.24:76), which is a promotion refusal, not a malformed record.
    pub fn validate(&self) -> Result<(), ImprovementError> {
        if self.delta_ref.trim().is_empty() {
            return Err(ImprovementError::MissingField("delta_ref"));
        }
        Ok(())
    }

    /// I12.24:76 conclusiveness, derived from the recorded delta.
    ///
    /// A delta is conclusive exactly when every I18.47:79-84 dimension is
    /// actually recorded. A caller that leaves one dimension blank has not
    /// measured it, and an unmeasured dimension is not a favourable one.
    pub fn is_conclusive(&self) -> bool {
        [
            &self.code_config_schema_process_and_contract_surface,
            &self.operator_and_agent_ceremony,
            &self.new_failure_recovery_migration_and_rollback_paths,
            &self.maintenance_security_privacy_and_observability_burden,
            &self.measured_latency_resource_and_product_delta,
            &self.validity_scope_and_retirement_condition,
        ]
        .into_iter()
        .all(|slot| !slot.trim().is_empty())
    }
}

/// The bound canonical budget-equivalence record plus the remaining I12.24
/// promotion legs.
///
/// `budget_ledger` IS the `BudgetEquivalenceLedger` value. It is validated
/// with that contract's own `validate()` — its arm uniqueness, declared
/// profile coverage and explicit mismatch-and-claim-limit rules — so a name
/// that happens to look like a ledger proves nothing. `budget_ledger_ref` and
/// `ledger_matched` are gone: the reference is [`BudgetEquivalenceLedger::ledger_id`]
/// and the matchedness is [`BudgetEquivalenceLedger::equivalence`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BudgetProof {
    pub budget_ledger: BudgetEquivalenceLedger,
    pub complexity_delta: ComplexityEconomicsDelta,
    pub affected_check_refs: Vec<String>,
    pub live_shadow_refs: Vec<String>,
    pub live_canary_refs: Vec<String>,
    pub delayed_harm_window_ref: String,
}

impl BudgetProof {
    /// Structural validity of the bound records and the non-ledger legs.
    pub fn validate(&self) -> Result<(), ImprovementError> {
        self.budget_ledger
            .validate()
            .map_err(budget_ledger_contract_error)?;
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

    /// The I12.24:76 promotion gate.
    ///
    /// Every decision below is read from the bound records. There is no
    /// caller-set Boolean left to flip: matchedness is the ledger's own
    /// `equivalence` class and conclusiveness is the recorded content of the
    /// six I18.47 delta slots.
    pub fn supports_promotion(&self) -> Result<(), ImprovementError> {
        self.validate()?;
        if !matches!(
            self.budget_ledger.equivalence,
            BudgetEquivalence::Exact
                | BudgetEquivalence::TokenMatched
                | BudgetEquivalence::ComputeMatched
                | BudgetEquivalence::CostMatched
        ) {
            return Err(ImprovementError::BudgetGateViolation(
                "unmatched budget-equivalence ledger cannot promote",
            ));
        }
        if !self.complexity_delta.is_conclusive() {
            return Err(ImprovementError::BudgetGateViolation(
                "inconclusive complexity-economics delta cannot promote",
            ));
        }
        // I12.24:68 matched-budget live shadow/canary. A blank reference is
        // not evidence, so a present-but-blank list does not satisfy the leg.
        let live_shadow = self
            .live_shadow_refs
            .iter()
            .any(|value| !value.trim().is_empty());
        let live_canary = self
            .live_canary_refs
            .iter()
            .any(|value| !value.trim().is_empty());
        if !live_shadow && !live_canary {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires matched-budget live shadow or canary evidence",
            ));
        }
        Ok(())
    }
}

/// Carries a canonical `BudgetEquivalenceLedger` refusal across into
/// [`ImprovementError`] without discarding which field or rule refused.
///
/// A bound ledger that does not satisfy the canonical contract is not
/// promotable evidence, so the gate reports it as one.
fn budget_ledger_contract_error(error: EvaluationContractError) -> ImprovementError {
    match error {
        EvaluationContractError::InvalidText { field }
        | EvaluationContractError::EmptyCollection { field } => {
            ImprovementError::MissingField(field)
        }
        EvaluationContractError::EvidenceState { reason, .. }
        | EvaluationContractError::InvalidDependency { reason, .. } => {
            ImprovementError::BudgetGateViolation(reason)
        }
        EvaluationContractError::DuplicateIdentity { .. }
        | EvaluationContractError::InvalidInterval { .. }
        | EvaluationContractError::ReasonTooLong { .. }
        | EvaluationContractError::ProofOverclaim => ImprovementError::BudgetGateViolation(
            "the bound budget-equivalence ledger does not satisfy the I18.47 contract",
        ),
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
    // Both bindings are read out of the records the gate just validated; the
    // outcome never carries a name the gate did not check.
    outcome.budget_ledger_ref = proof.budget_ledger.ledger_id.to_string();
    outcome.complexity_delta_ref = proof.complexity_delta.delta_ref.clone();
    outcome.economics_conclusive = proof.complexity_delta.is_conclusive();
    outcome.affected_check_refs = proof.affected_check_refs.clone();
    outcome.live_shadow_refs = proof.live_shadow_refs.clone();
    outcome.live_canary_refs = proof.live_canary_refs.clone();
    outcome.delayed_harm_window_ref = proof.delayed_harm_window_ref.clone();
    Ok(())
}
