//! Unit-compatible capacity and headroom analysis.
//!
//! The capacity unit is explicit ([`MeasurementUnit`]) and never inferred:
//! byte payloads prove byte fit, tokenizer observations prove token fit,
//! and STU compares only against an STU capacity or through an explicitly
//! identified estimate-to-token decision policy. Unknown capacity stays
//! unknown: it is never zero and never unlimited. Reserves are retained
//! independently and summed exactly once with checked arithmetic.

use eliot_context_contracts::{ContextError, MeasurementUnit};
use eliot_contracts::ArtifactId;

use crate::envelope::validate_digest;

/// Explicitly identified estimate-to-token decision policy.
///
/// STU and tokens remain distinct units; a comparison is permitted only
/// through this accepted policy, never by relabelling the unit.
#[derive(Clone, Debug)]
pub struct StuToTokenPolicy {
    /// Stable decision-policy identity.
    pub policy_id: ArtifactId,
    /// Policy revision digest (lowercase SHA-256 hex).
    pub policy_digest: String,
    /// Tokens per STU numerator; must be nonzero.
    pub tokens_per_stu_numer: u64,
    /// Tokens per STU denominator; must be nonzero.
    pub tokens_per_stu_denom: u64,
}

impl StuToTokenPolicy {
    /// Validate policy identity, digest shape and nonzero rate.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_digest(&self.policy_digest, "capacity.policy_digest")?;
        if self.tokens_per_stu_denom == 0 {
            return Err(ContextError::InvalidField("capacity.stu_to_token_denom"));
        }
        if self.tokens_per_stu_numer == 0 {
            return Err(ContextError::InvalidField("capacity.stu_to_token_rate"));
        }
        Ok(())
    }

    /// Convert STU to tokens as `ceil(stu * numer / denom)`, fully checked.
    pub fn apply(&self, stu: u64) -> Result<u64, ContextError> {
        self.validate()?;
        let scaled = stu
            .checked_mul(self.tokens_per_stu_numer)
            .ok_or(ContextError::Overflow)?;
        scaled
            .checked_add(self.tokens_per_stu_denom - 1)
            .map(|plus| plus / self.tokens_per_stu_denom)
            .ok_or(ContextError::Overflow)
    }
}

/// Capacity and headroom plan for one measurement.
#[derive(Clone, Debug)]
pub struct CapacityPlan {
    /// Route capacity in [`CapacityPlan::unit`]; `None` means unknown,
    /// which is neither zero nor unlimited.
    pub route_capacity: Option<u64>,
    /// Explicit compatible unit for every cost compared here.
    pub unit: MeasurementUnit,
    /// Fixed serializer/protocol overhead (payload bytes already carry the
    /// serializer's own overhead, so this is never double counted).
    pub fixed_overhead: u64,
    /// Reserved output capacity.
    pub output_reserve: u64,
    /// Reserved review/reasoning capacity.
    pub review_reserve: u64,
    /// Reserved tool-result capacity.
    pub tool_reserve: u64,
    /// Reserved verifier capacity.
    pub verifier_reserve: u64,
    /// Reserved decision-tail capacity.
    pub decision_tail_reserve: u64,
    /// Accepted STU-to-token decision policy, required before STU-derived
    /// costs may meet a token capacity.
    pub stu_to_token: Option<StuToTokenPolicy>,
}

/// Capacity fit and headroom for the estimated and observed sides.
///
/// `None` fit/headroom means unknown, never zero and never unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityAnalysis {
    /// Exact sum of the six independent reserves, counted once each.
    pub total_reserves: u64,
    /// Estimated payload cost in the capacity unit, when compatible.
    pub estimated_cost: Option<u64>,
    /// Estimated payload cost plus reserves, when known.
    pub estimated_total: Option<u64>,
    /// Estimated fit, when the capacity and estimated total are known.
    pub fit: Option<bool>,
    /// Estimated remaining headroom, when fit is known true.
    pub headroom: Option<u64>,
    /// Observed payload cost in the capacity unit, when compatible.
    pub observed_cost: Option<u64>,
    /// Observed payload cost plus reserves, when known.
    pub observed_total: Option<u64>,
    /// Observed fit, when the capacity and observed total are known.
    pub observed_fit: Option<bool>,
    /// Observed remaining headroom, when observed fit is known true.
    pub observed_headroom: Option<u64>,
}

/// Canonical wire spelling of a capacity unit for the receipt.
pub(crate) fn unit_as_str(unit: MeasurementUnit) -> &'static str {
    match unit {
        MeasurementUnit::Utf8Bytes => "UTF8_BYTES",
        MeasurementUnit::Stu => "STU",
        MeasurementUnit::TokenizerTokens => "TOKENIZER_TOKENS",
    }
}

/// Fit and headroom for one known-or-unknown total against capacity.
///
/// A total above capacity is honestly unfit with unknown headroom; only
/// reserve-sum overflow is a typed arithmetic failure.
fn fit_headroom(capacity: Option<u64>, total: Option<u64>) -> (Option<bool>, Option<u64>) {
    match (capacity, total) {
        (Some(limit), Some(used)) => {
            if used <= limit {
                (Some(true), limit.checked_sub(used))
            } else {
                (Some(false), None)
            }
        }
        _ => (None, None),
    }
}

/// Analyze capacity: independent reserves, compatible costs, fit, headroom.
pub fn analyze_capacity(
    plan: &CapacityPlan,
    payload_bytes: u64,
    stu: u64,
    observed_tokens: Option<u64>,
) -> Result<CapacityAnalysis, ContextError> {
    let reserves = [
        plan.fixed_overhead,
        plan.output_reserve,
        plan.review_reserve,
        plan.tool_reserve,
        plan.verifier_reserve,
        plan.decision_tail_reserve,
    ];
    let mut total_reserves = 0_u64;
    for reserve in reserves {
        total_reserves = total_reserves
            .checked_add(reserve)
            .ok_or(ContextError::Overflow)?;
    }
    if let Some(policy) = &plan.stu_to_token {
        policy.validate()?;
    }
    let estimated_cost = match plan.unit {
        MeasurementUnit::Utf8Bytes => Some(payload_bytes),
        MeasurementUnit::Stu => Some(stu),
        MeasurementUnit::TokenizerTokens => match &plan.stu_to_token {
            Some(policy) => Some(policy.apply(stu)?),
            None => None,
        },
    };
    let estimated_total = estimated_cost
        .map(|cost| cost.checked_add(total_reserves).ok_or(ContextError::Overflow))
        .transpose()?;
    let (fit, headroom) = fit_headroom(plan.route_capacity, estimated_total);
    // Observed tokens compare only against a token capacity; relabelling
    // the unit to meet a byte or STU capacity is forbidden.
    let observed_cost = match (observed_tokens, plan.unit) {
        (Some(tokens), MeasurementUnit::TokenizerTokens) => Some(tokens),
        _ => None,
    };
    let observed_total = observed_cost
        .map(|cost| cost.checked_add(total_reserves).ok_or(ContextError::Overflow))
        .transpose()?;
    let (observed_fit, observed_headroom) = fit_headroom(plan.route_capacity, observed_total);
    Ok(CapacityAnalysis {
        total_reserves,
        estimated_cost,
        estimated_total,
        fit,
        headroom,
        observed_cost,
        observed_total,
        observed_fit,
        observed_headroom,
    })
}
