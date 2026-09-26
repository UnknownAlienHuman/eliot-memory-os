//! Typed capacity outcomes for durable bridge-event admission and recovery.
//!
//! The capacity dimension is the resource whose admission check failed. The
//! recovery action names the existing-work operation that can make progress;
//! it does not claim that any particular row is eligible for retirement. The
//! local phase records only ORS acceptance, never receiver normalization or
//! application. `Durable` means the source event row is already locally
//! durable; it does not assert that its handoff intent or receiver work has
//! committed.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The bounded bridge-event resource that rejected an admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeEventCapacityDimension {
    /// Retained event rows for fresh event identities.
    EventRecords,
    /// Pending handoff rows that retain delivery obligations.
    PendingHandoffs,
    /// Scoped gap rows retained for one producer stream.
    ScopedGaps,
}

/// The authorized operation to use for the named exhausted resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeEventCapacityRecovery {
    /// Reconcile retained events and their exact stored dispositions.
    ReconcileStagedEvents,
    /// Reconcile the exact pending delivery obligation.
    ReconcilePendingDelivery,
    /// Reconcile retained scoped gap facts.
    ReconcileScopedGaps,
}

/// The local ORS acceptance phase at the capacity decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeEventLocalPhase {
    /// The rejecting ORS transaction did not commit the presented request.
    NotCommitted,
    /// The local source event is durably committed; receiver progress is not implied.
    Durable,
}

/// A loss-visible capacity refusal with its exact resource, recovery route,
/// and local event acceptance phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventCapacityPressure {
    /// Resource whose capacity check failed.
    pub dimension: BridgeEventCapacityDimension,
    /// Existing-work operation permitted to make progress on that resource.
    pub recovery: BridgeEventCapacityRecovery,
    /// ORS-local phase when admission was refused.
    pub local_phase: BridgeEventLocalPhase,
}

impl BridgeEventCapacityPressure {
    /// Builds pressure for the retained event-record budget.
    pub const fn event_records(local_phase: BridgeEventLocalPhase) -> Self {
        Self {
            dimension: BridgeEventCapacityDimension::EventRecords,
            recovery: BridgeEventCapacityRecovery::ReconcileStagedEvents,
            local_phase,
        }
    }

    /// Builds pressure for the pending-handoff budget.
    pub const fn pending_handoffs(local_phase: BridgeEventLocalPhase) -> Self {
        Self {
            dimension: BridgeEventCapacityDimension::PendingHandoffs,
            recovery: BridgeEventCapacityRecovery::ReconcilePendingDelivery,
            local_phase,
        }
    }

    /// Builds pressure for the scoped-gap budget.
    pub const fn scoped_gaps(local_phase: BridgeEventLocalPhase) -> Self {
        Self {
            dimension: BridgeEventCapacityDimension::ScopedGaps,
            recovery: BridgeEventCapacityRecovery::ReconcileScopedGaps,
            local_phase,
        }
    }

    /// Checks that a decoded report pairs each dimension with its named
    /// recovery action. This is required at untrusted wire boundaries.
    pub const fn is_consistent(self) -> bool {
        matches!(
            (self.dimension, self.recovery),
            (
                BridgeEventCapacityDimension::EventRecords,
                BridgeEventCapacityRecovery::ReconcileStagedEvents
            ) | (
                BridgeEventCapacityDimension::PendingHandoffs,
                BridgeEventCapacityRecovery::ReconcilePendingDelivery
            ) | (
                BridgeEventCapacityDimension::ScopedGaps,
                BridgeEventCapacityRecovery::ReconcileScopedGaps
            )
        )
    }
}
