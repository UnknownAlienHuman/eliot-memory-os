//! Recheckable context capacity and displacement accounting.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, DecisionId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextBinding, ContextError, MeasurementRef, OmissionRecord, validate_digest};

/// Independent allocations used by capacity reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EconomyAllocations {
    pub fixed_overhead: u64,
    pub output_reserve: u64,
    pub review_reserve: u64,
    pub admitted_required: u64,
    pub admitted_optional: u64,
    pub remaining_headroom: u64,
    pub route_capacity: u64,
}

impl EconomyAllocations {
    /// Check exact independent arithmetic, rejecting overflow.
    pub fn reconcile(&self) -> Result<(), ContextError> {
        let used = self
            .fixed_overhead
            .checked_add(self.output_reserve)
            .and_then(|v| v.checked_add(self.review_reserve))
            .and_then(|v| v.checked_add(self.admitted_required))
            .and_then(|v| v.checked_add(self.admitted_optional))
            .ok_or(ContextError::Overflow)?;
        if used.checked_add(self.remaining_headroom) != Some(self.route_capacity) {
            return Err(ContextError::EconomyMismatch);
        }
        Ok(())
    }
}

/// Evidence receipt for requested/admitted/displaced material and applied rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextEconomyReceipt {
    pub binding: ContextBinding,
    pub decision_id: DecisionId,
    pub measurement: MeasurementRef,
    pub requested: Vec<ArtifactId>,
    pub admitted: Vec<ArtifactId>,
    pub displaced: Vec<ArtifactId>,
    pub omissions: Vec<OmissionRecord>,
    pub applied_rule: ArtifactId,
    pub allocations: EconomyAllocations,
    pub receipt_digest: String,
}

impl ContextEconomyReceipt {
    /// Validate material conservation and capacity evidence.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.measurement.validate()?;
        validate_digest(&self.receipt_digest, "economy.receipt_digest")?;
        if self.decision_id != self.binding.decision_id {
            return Err(ContextError::IdentityConflict);
        }
        let requested: BTreeSet<_> = self.requested.iter().cloned().collect();
        let admitted: BTreeSet<_> = self.admitted.iter().cloned().collect();
        let displaced: BTreeSet<_> = self.displaced.iter().cloned().collect();
        if requested.len() != self.requested.len()
            || admitted.len() != self.admitted.len()
            || displaced.len() != self.displaced.len()
        {
            return Err(ContextError::Duplicate("economy.membership"));
        }
        if requested.is_empty() {
            return Err(ContextError::EconomyMismatch);
        }
        if !admitted.is_disjoint(&displaced)
            || !admitted.is_subset(&requested)
            || !displaced.is_subset(&requested)
            || requested != admitted.union(&displaced).cloned().collect()
        {
            return Err(ContextError::EconomyMismatch);
        }
        if !displaced.is_empty()
            && (self.requested.is_empty()
                || self.admitted.is_empty()
                || self.applied_rule.as_str().is_empty())
        {
            return Err(ContextError::EconomyMismatch);
        }
        let omitted: BTreeSet<_> = self
            .omissions
            .iter()
            .map(|item| item.atom_id.clone())
            .collect();
        if omitted != displaced {
            return Err(ContextError::EconomyMismatch);
        }
        for omission in &self.omissions {
            omission.validate(&self.binding)?;
        }
        self.allocations.reconcile()
    }
}
