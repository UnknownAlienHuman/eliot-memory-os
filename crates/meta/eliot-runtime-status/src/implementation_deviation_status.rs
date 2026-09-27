//! Read-only operator projection of canonical implementation deviations.
//!
//! `ImplementationDeviation` is the Governor-owned source of truth for this
//! edge. This module projects the lifecycle dispositions an operator must be
//! able to see without inferring them: an `active` deviation whose review
//! condition has not been dispositioned yet, and an `expired` one that already
//! left `active`. It never derives disposition from prose, code history or the
//! absence of a promotion, and it never mutates the canonical record.

use eliot_problem::{DeviationState, ImplementationDeviation};

/// Stable name for the operator-facing projection returned by this module.
pub const IMPLEMENTATION_DEVIATION_STATUS_CONTRACT: &str =
    "eliot.runtime.implementation.deviation.status";
/// Version of the operator-facing projection shape.
pub const IMPLEMENTATION_DEVIATION_STATUS_VERSION: &str = "1.0.0";

/// Error returned when a canonical deviation cannot be projected.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ImplementationDeviationStatusError {
    /// The canonical deviation failed its own contract validation.
    #[error("implementation deviation failed validation: {0}")]
    InvalidDeviation(String),
}

/// One canonical deviation as the operator sees it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ImplementationDeviationStatusRow {
    pub deviation_id: String,
    pub scope: String,
    pub owner: String,
    pub review_condition: String,
    pub state: DeviationState,
    pub revision: u64,
    pub outcome_ref: Option<String>,
}

/// Operator-visible status of one canonical implementation deviation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ImplementationDeviationStatusProjection {
    pub contract: String,
    pub contract_version: String,
    pub active: Vec<ImplementationDeviationStatusRow>,
    pub expired: Vec<ImplementationDeviationStatusRow>,
}

impl ImplementationDeviationStatusProjection {
    /// Returns the named deviation row from either visible disposition.
    #[must_use]
    pub fn deviation(&self, deviation_id: &str) -> Option<&ImplementationDeviationStatusRow> {
        self.active
            .iter()
            .chain(self.expired.iter())
            .find(|row| row.deviation_id == deviation_id)
    }
}

/// Projects the operator-visible active and expired deviations.
///
/// Only the canonical `active` and `expired` dispositions are surfaced;
/// `promoted` and `rejected` are terminal and no longer need operator review.
pub fn project_implementation_deviation_status(
    deviations: &[ImplementationDeviation],
) -> Result<ImplementationDeviationStatusProjection, ImplementationDeviationStatusError> {
    let mut active = Vec::new();
    let mut expired = Vec::new();

    for deviation in deviations {
        deviation.validate().map_err(|error| {
            ImplementationDeviationStatusError::InvalidDeviation(error.to_string())
        })?;
        let row = ImplementationDeviationStatusRow {
            deviation_id: deviation.deviation_id.as_str().to_owned(),
            scope: deviation.scope.clone(),
            owner: deviation.owner.principal.clone(),
            review_condition: deviation.review_condition.clone(),
            state: deviation.state,
            revision: deviation.revision,
            outcome_ref: deviation.outcome_ref.clone(),
        };
        match deviation.state {
            DeviationState::Active => active.push(row),
            DeviationState::Expired => expired.push(row),
            DeviationState::Promoted | DeviationState::Rejected => {}
        }
    }

    Ok(ImplementationDeviationStatusProjection {
        contract: IMPLEMENTATION_DEVIATION_STATUS_CONTRACT.to_owned(),
        contract_version: IMPLEMENTATION_DEVIATION_STATUS_VERSION.to_owned(),
        active,
        expired,
    })
}
