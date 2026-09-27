//! Canonical State Fence and temporal validity record for memory decision
//! boundaries (issue #1906, A5.4).
//!
//! A5.4: load-bearing state preserves valid time, known time, transaction
//! time, resource generation, and task/policy/integration revisions. The
//! Governor assigns canonical causal order; external timestamps remain
//! observations. Lease expiry and local scheduling use monotonic-compatible
//! clocks; a clock anomaly creates a Problem State requiring revalidation,
//! never a silent authority extension. A State Fence contains only
//! dependencies capable of changing the decision; a change to an unrelated
//! resource does not invalidate the entire task.
//!
//! This module is the Governor-facing composition of the two existing
//! contract records ([`ClockReading`] and [`StateFence`]); it invents no
//! second clock, fence, or ordering mechanism. Decision boundaries build one
//! [`DecisionValidity`], validate it immediately before material use, and
//! refuse with an inspectable revalidation requirement on any anomaly.

use eliot_contracts::{ClockReading, ContractError, StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Temporal validity observations plus the minimal dependency fence for one
/// memory decision.
///
/// The pair is the "named minimal State Fence" a decision receipt carries:
/// [`ClockReading`] records valid/known/transaction time as observations
/// (never canonical causal order), and [`StateFence`] records only the
/// decision-relevant resource generation and task/policy/integration
/// revisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionValidity {
    /// valid/known/transaction time observations; never causal order.
    pub clock: ClockReading,
    /// Minimal dependency fence: only decision-relevant resources.
    pub fence: StateFence,
}

/// A lease/local-clock anomaly detected with monotonic-compatible timing.
///
/// Each variant is an explicit Problem State requiring revalidation: the
/// decision is refused and its lease/authorization is never silently
/// extended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockAnomaly {
    /// Observed known time is already past the request lease deadline; the
    /// decision must not extend its lease or authorization.
    LeaseExpired,
    /// Wall-clock interval is inverted (known before valid).
    InvalidInterval,
    /// Wall-clock fields are present but no monotonic reading is available,
    /// so the reading is observation-only and cannot order lease/scheduling.
    MonotonicUnavailable,
}

impl ClockAnomaly {
    /// Stable machine-readable revalidation requirement.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseExpired => "lease_expired_revalidate",
            Self::InvalidInterval => "invalid_clock_interval_revalidate",
            Self::MonotonicUnavailable => "monotonic_timing_unavailable_revalidate",
        }
    }
}

/// Fail-closed decision-validity errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DecisionValidityError {
    /// The temporal record or the minimal dependency fence failed validation.
    #[error("decision validity invalid: {0}")]
    Invalid(#[from] ContractError),
    /// A lease/local-clock anomaly requires revalidation before the decision
    /// may proceed; the lease/authorization is never silently extended.
    #[error("clock anomaly {}: revalidate the decision", .0.as_str())]
    ClockAnomaly(ClockAnomaly),
}

impl DecisionValidity {
    /// Composes the temporal record with the minimal dependency fence.
    #[must_use]
    pub const fn new(clock: ClockReading, fence: StateFence) -> Self {
        Self { clock, fence }
    }

    /// Validates the temporal record and the minimal dependency fence.
    pub fn validate(&self) -> Result<(), DecisionValidityError> {
        self.clock
            .validate()
            .map_err(DecisionValidityError::Invalid)?;
        self.fence
            .validate()
            .map_err(DecisionValidityError::Invalid)?;
        Ok(())
    }

    /// The minimal dependency set: only decision-relevant resources (A5.4).
    ///
    /// The [`StateFence`] itself is that set — it contains only dependencies
    /// capable of changing the decision, never the whole task.
    #[must_use]
    pub const fn minimal_dependencies(&self) -> &StateFence {
        &self.fence
    }

    /// Returns true when a decision-relevant dependency changed, so only the
    /// decisions bound to the affected fence require revalidation — never the
    /// whole task (A5.4).
    #[must_use]
    pub fn fence_dependency_changed(&self, current: &StateFence) -> bool {
        !fences_match_exact(&self.fence, current)
    }

    /// Detects lease/local-clock anomalies using monotonic-compatible timing.
    ///
    /// `lease_deadline_unix_ms` is the request lease; when supplied, an
    /// observed known time already past the deadline is a [`ClockAnomaly::
    /// LeaseExpired`]. Wall-clock fields without a monotonic reading are
    /// [`ClockAnomaly::MonotonicUnavailable`]: observation-only, never causal
    /// order. Returns `None` when the reading is anomaly-free.
    #[must_use]
    pub fn detect_clock_anomaly(
        &self,
        lease_deadline_unix_ms: Option<u64>,
    ) -> Option<ClockAnomaly> {
        if let (Some(valid), Some(known)) = (self.clock.valid_time_ms, self.clock.known_time_ms)
            && known < valid
        {
            return Some(ClockAnomaly::InvalidInterval);
        }
        if let (Some(known), Some(deadline)) = (self.clock.known_time_ms, lease_deadline_unix_ms)
            && known > i64::try_from(deadline).unwrap_or(i64::MAX)
        {
            return Some(ClockAnomaly::LeaseExpired);
        }
        if self.clock.monotonic_ns.is_none()
            && (self.clock.valid_time_ms.is_some() || self.clock.known_time_ms.is_some())
        {
            return Some(ClockAnomaly::MonotonicUnavailable);
        }
        None
    }

    /// Validates the record and refuses on any clock anomaly, returning the
    /// inspectable revalidation requirement instead of extending the lease.
    pub fn validate_for_decision(
        &self,
        lease_deadline_unix_ms: Option<u64>,
    ) -> Result<(), DecisionValidityError> {
        self.validate()?;
        if let Some(anomaly) = self.detect_clock_anomaly(lease_deadline_unix_ms) {
            return Err(DecisionValidityError::ClockAnomaly(anomaly));
        }
        Ok(())
    }
}
