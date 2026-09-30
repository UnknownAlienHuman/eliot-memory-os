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
//! gate just checked, and refuses to SUBSTITUTE one canonical record for
//! another: an outcome already bound to a ledger, a delta or an evidence leg
//! cannot be re-bound to a different one, because the evaluation record must
//! not name a budget under which the outcome was never observed.
//!
//! ## What this module cannot discharge
//!
//! [`BudgetProof`] is a caller-constructed, `Deserialize`-able record, so a
//! caller that INVENTS a whole [`BudgetEquivalenceLedger`] — its own arms, its
//! own measurements, `Exact` equivalence — together with invented
//! live-shadow/canary references, and hands that to this gate, gets a passing
//! verdict. Matchedness is a field INSIDE the record rather than an
//! owner-issued attestation, and issuing one would be a different contract from
//! I18.47's canonical ledger, so this module does not pretend to close that.
//! It is the honest ceiling of a matched-budget gate over a caller-held record.
//!
//! What the crate root adds on top is the BINDING, which this file could not
//! reach: [`PromotionInput`](crate::PromotionInput) carries the bound
//! [`BudgetProof`] itself, and [`OutcomeEvidence`] carries the
//! `BudgetEquivalenceLedger` and `ComplexityEconomicsDelta` values that
//! [`stamp_outcome_budget`] stamps. The projection is therefore compared back
//! to the record it came from rather than to a name, and what this module does
//! discharge is that a projection is only ever written from records
//! [`BudgetProof::supports_promotion`] checked and is never silently replaced by
//! a different one — including by a second ledger that reuses the same
//! `ledger_id`.

use eliot_evaluation_contracts::{
    BudgetEquivalence, BudgetEquivalenceLedger, EvaluationContractError,
};
use serde::{Deserialize, Serialize};

use crate::{ImprovementError, OutcomeEvidence};

/// The six I18.47:78-84 `ComplexityEconomicsDelta` slots, recorded verbatim.
///
/// The `delta_ref` is the identity OF this record, not a substitute for the six
/// slots. The outcome carries the whole record (see [`stamp_outcome_budget`]),
/// so a different record reusing the same `delta_ref` is not the same binding.
/// There is no `conclusive` field: [`ComplexityEconomicsDelta::is_conclusive`]
/// derives the answer from the recorded slots, so a caller cannot assert it.
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
/// that happens to look like a ledger proves nothing. This struct carries no
/// `budget_ledger_ref` and no `ledger_matched`: the ledger's identity is
/// [`BudgetEquivalenceLedger::ledger_id`] and the matchedness is
/// [`BudgetEquivalenceLedger::equivalence`], both read out of the value
/// itself.
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

/// Binds a gate-checked proof onto a promotion-bound outcome.
///
/// Every value written here is read out of the records
/// [`BudgetProof::supports_promotion`] just validated, so the outcome never
/// carries a name, a Boolean or an evidence leg the gate did not check. The
/// proof is validated BEFORE any field is written, and the writes are
/// validate-then-commit: a refused proof leaves the outcome exactly as it was.
///
/// What is written is not only the names: the [`BudgetEquivalenceLedger`] and
/// [`ComplexityEconomicsDelta`] VALUES are stamped onto the outcome as well, so
/// the record itself is carried and can be compared back.
///
/// # The binding is not substitutable (I12.24:76)
///
/// I12.24:76 requires the evaluation record to bind THE canonical
/// `BudgetEquivalenceLedger` and `ComplexityEconomicsDelta`, so a record that
/// already carries a binding must not be re-pointed at a different one. An
/// outcome that already carries or names a ledger, a delta or any of the four
/// evidence legs therefore admits only the SAME proof:
///
/// - no binding recorded yet — the proof's records are written, as before;
/// - a binding that equals this proof's records — idempotent, `Ok(())`;
/// - a binding that differs in any way — refused with a typed
///   [`ImprovementError::BudgetGateViolation`] and nothing written.
///
/// A PARTIAL binding — one canonical record without the other, or an evidence
/// leg with no record at all — is refused by the same rule, never completed
/// here: completing it would silently discard whichever half the caller had
/// already recorded. An outcome that records nothing at all is unbound, and
/// takes the write path, so a replay-only outcome stays stampable.
///
/// Without that refusal a second promotable proof could silently overwrite the
/// first, and the record would name a budget the outcome was never evaluated
/// under while still reading as gate-checked. Refusal is per-field, so
/// dropping recorded live-canary evidence, affected checks or delayed-harm
/// visibility by re-stamping a weaker proof is refused too.
///
/// The comparison is over the ORIGINAL recorded records this function already
/// holds: the whole [`BudgetEquivalenceLedger`] value and the whole
/// [`ComplexityEconomicsDelta`] value, compared field by field through their own
/// derived `PartialEq`, with the two names checked as well. Comparing the names
/// alone would not be a binding: `ledger_id` is a caller-chosen string, so a
/// DIFFERENT ledger reusing the same one — other arms, other measurements —
/// would satisfy it and leave the record silently decoupled from the budget it
/// was evaluated under. No ledger is recomputed, re-derived or substituted, and
/// the canonical [`BudgetEquivalenceLedger::validate`] remains the only
/// admissible check on the ledger.
pub fn stamp_outcome_budget(
    outcome: &mut OutcomeEvidence,
    proof: &BudgetProof,
) -> Result<(), ImprovementError> {
    proof.supports_promotion()?;
    // The two canonical records, their names and the four evidence legs are read
    // out of the records the gate just validated; the outcome never carries a
    // name or a leg the gate did not check.
    let ledger_ref = proof.budget_ledger.ledger_id.to_string();
    let delta_ref = proof.complexity_delta.delta_ref.clone();
    let conclusive = proof.complexity_delta.is_conclusive();

    // A binding exists as soon as EITHER canonical record is carried or named,
    // OR as soon as ANY of the four evidence legs is recorded — the legs are
    // written by the same call, so an outcome holding a leg is bound just as
    // surely as one holding a record. The refusal below is therefore
    // PER-FIELD and fail-closed: a record that carries one canonical record
    // without the other, or that carries a leg without any record, is
    // PARTIALLY bound and is REFUSED, never repaired here. Repairing it would
    // silently drop the leg or the record the caller already recorded.
    //
    // An outcome that records nothing at all — every term below false, which is
    // the replay-only shape: no ledger, no delta, no leg — is UNBOUND and still
    // takes the write path, so the replay-only outcome stays stampable.
    let already_bound = !outcome.budget_ledger_ref.trim().is_empty()
        || !outcome.complexity_delta_ref.trim().is_empty()
        || outcome.budget_ledger.is_some()
        || outcome.complexity_delta.is_some()
        || !outcome.affected_check_refs.is_empty()
        || !outcome.live_shadow_refs.is_empty()
        || !outcome.live_canary_refs.is_empty()
        || !outcome.delayed_harm_window_ref.trim().is_empty();
    if already_bound {
        // The comparison is over the RECORD VALUES the outcome carries, not over
        // the names. `ledger_id` is a caller-chosen string, so a second ledger
        // that reuses the same one — different arms, different measurements —
        // would satisfy a name comparison while the record the outcome was
        // evaluated under changed underneath it. Both types derive
        // `PartialEq`, so the record itself is the witness.
        let same_binding = outcome.budget_ledger.as_ref() == Some(&proof.budget_ledger)
            && outcome.complexity_delta.as_ref() == Some(&proof.complexity_delta)
            && outcome.budget_ledger_ref == ledger_ref
            && outcome.complexity_delta_ref == delta_ref
            && outcome.economics_conclusive == conclusive
            && outcome.affected_check_refs == proof.affected_check_refs
            && outcome.live_shadow_refs == proof.live_shadow_refs
            && outcome.live_canary_refs == proof.live_canary_refs
            && outcome.delayed_harm_window_ref == proof.delayed_harm_window_ref;
        if !same_binding {
            return Err(ImprovementError::BudgetGateViolation(
                "the outcome is already bound to a different budget-equivalence ledger, \
                 complexity-economics delta or evidence leg; the I12.24:76 binding is not \
                 substitutable",
            ));
        }
        return Ok(());
    }

    outcome.budget_ledger_ref = ledger_ref;
    outcome.complexity_delta_ref = delta_ref;
    outcome.budget_ledger = Some(proof.budget_ledger.clone());
    outcome.complexity_delta = Some(proof.complexity_delta.clone());
    outcome.economics_conclusive = conclusive;
    outcome.affected_check_refs = proof.affected_check_refs.clone();
    outcome.live_shadow_refs = proof.live_shadow_refs.clone();
    outcome.live_canary_refs = proof.live_canary_refs.clone();
    outcome.delayed_harm_window_ref = proof.delayed_harm_window_ref.clone();
    Ok(())
}
