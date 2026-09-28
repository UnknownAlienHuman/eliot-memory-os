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
    /// Canonical bytes of one durable event envelope.
    EnvelopeBytes,
    /// Pending handoff rows that retain delivery obligations.
    PendingHandoffs,
    /// Scoped gap rows retained for one producer stream.
    ScopedGaps,
    /// Live bridge position rows retained in one namespace window.
    PositionRows,
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

/// Closed wire dimension names emitted by the front door for transport
/// backpressure. These reports deliberately carry no local commit phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
pub enum BridgeTransportBackpressureDimension {
    #[serde(rename = "bridge-event-handoff-rows")]
    BridgeEventHandoffRows,
    #[serde(rename = "bridge-event-records")]
    BridgeEventRecords,
    #[serde(rename = "bridge-envelope-bytes")]
    BridgeEnvelopeBytes,
    #[serde(rename = "kernel-service-degraded")]
    KernelServiceDegraded,
    #[serde(rename = "transport-queue-items-or-bytes")]
    TransportQueueItemsOrBytes,
    #[serde(rename = "bridge-host-request-dispatch")]
    BridgeHostRequestDispatch,
    #[serde(rename = "bridge-recovery-windows")]
    BridgeRecoveryWindows,
    #[serde(rename = "bridge-recovery-cuts")]
    BridgeRecoveryCuts,
}

/// Closed recovery actions allowed for front-door transport backpressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
pub enum BridgeTransportBackpressureRecoveryAction {
    #[serde(
        rename = "reconcile consumed frontiers so eligible handoff charges retire, then resubmit"
    )]
    ReconcileHandoffChargesThenResubmit,
    #[serde(rename = "reconcile consumed frontiers so eligible charges retire, then resubmit")]
    ReconcileChargesThenResubmit,
    #[serde(
        rename = "shrink the envelope or carry a large payload by Blob/Resource handle, then resubmit"
    )]
    ShrinkOrExternalizeEnvelopeThenResubmit,
    #[serde(
        rename = "wait for Ready; run gap and reconcile recovery on the admitted session meanwhile"
    )]
    WaitReadyAndRecoverOnAdmittedSession,
    #[serde(
        rename = "retry the ordinary frame later, or cancel/stop through the reserved control lane"
    )]
    RetryOrUseReservedControlLane,
    #[serde(
        rename = "retain the admitted session; run gap/reconcile recovery, then resubmit duplicate-safe"
    )]
    RetainSessionRecoverThenResubmitDuplicateSafe,
    #[serde(
        rename = "reuse an exact live matching recovery window, or wait for expiry then reissue the authenticated open"
    )]
    ReuseExactLiveRecoveryWindowOrWaitForExpiry,
    #[serde(
        rename = "wait for expired recovery-window cut cleanup, then reissue the exact authenticated recovery selector"
    )]
    WaitForExpiredRecoveryWindowCutCleanupThenRetryAuthenticatedSelector,
}

/// Closed descriptions of work shed or deferred by the front door.
#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
pub enum BridgeTransportBackpressureShedWork {
    #[serde(
        rename = "this delivery frame shed and deferred; staged obligations retained, nothing evicted"
    )]
    DeferredStagedObligationsRetained,
    #[serde(rename = "this delivery frame shed; nothing staged, nothing retained")]
    ShedWithoutStaging,
    #[serde(rename = "this delivery frame shed and deferred; recovery legs stay admitted")]
    DeferredRecoveryLegsAdmitted,
    #[serde(
        rename = "this frame shed and deferred; control-lane capacity reserved, never consumed"
    )]
    DeferredControlLaneReserved,
    #[serde(
        rename = "this frame shed; its commit fate is unknown, never denied; the session is retained"
    )]
    UnknownCommitFateSessionRetained,
    #[serde(
        rename = "only the new recovery-window open shed and deferred; existing live windows and recovery retained"
    )]
    DeferredNewRecoveryWindowOpenExistingRecoveryRetained,
    #[serde(
        rename = "only the requested new recovery cut deferred; all existing recovery windows and cuts retained"
    )]
    DeferredNewRecoveryCutExistingRecoveryRetained,
}

/// The only generic transport outcome currently emitted by the front door.
#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeTransportBackpressureOutcome {
    Unknown,
}

/// Generic front-door backpressure. Since this is a transport disposition,
/// it intentionally does not claim that any local operation committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeTransportBackpressure {
    pub backpressure: bool,
    pub dimension: BridgeTransportBackpressureDimension,
    pub recovery_action: BridgeTransportBackpressureRecoveryAction,
    pub shed_work: BridgeTransportBackpressureShedWork,
    pub outcome: BridgeTransportBackpressureOutcome,
}

impl BridgeTransportBackpressure {
    /// Checks the closed dimension/recovery/shed-work combinations at an
    /// untrusted wire boundary.
    pub const fn is_consistent(self) -> bool {
        self.backpressure
            && matches!(self.outcome, BridgeTransportBackpressureOutcome::Unknown)
            && matches!(
                (
                    self.dimension,
                    self.recovery_action,
                    self.shed_work,
                ),
                (
                    BridgeTransportBackpressureDimension::BridgeEventHandoffRows,
                    BridgeTransportBackpressureRecoveryAction::ReconcileHandoffChargesThenResubmit,
                    BridgeTransportBackpressureShedWork::DeferredStagedObligationsRetained,
                ) | (
                    BridgeTransportBackpressureDimension::BridgeEventRecords,
                    BridgeTransportBackpressureRecoveryAction::ReconcileChargesThenResubmit,
                    BridgeTransportBackpressureShedWork::DeferredStagedObligationsRetained,
                ) | (
                    BridgeTransportBackpressureDimension::BridgeEnvelopeBytes,
                    BridgeTransportBackpressureRecoveryAction::ShrinkOrExternalizeEnvelopeThenResubmit,
                    BridgeTransportBackpressureShedWork::ShedWithoutStaging,
                ) | (
                    BridgeTransportBackpressureDimension::KernelServiceDegraded,
                    BridgeTransportBackpressureRecoveryAction::WaitReadyAndRecoverOnAdmittedSession,
                    BridgeTransportBackpressureShedWork::DeferredRecoveryLegsAdmitted,
                ) | (
                    BridgeTransportBackpressureDimension::TransportQueueItemsOrBytes,
                    BridgeTransportBackpressureRecoveryAction::RetryOrUseReservedControlLane,
                    BridgeTransportBackpressureShedWork::DeferredControlLaneReserved,
                ) | (
                    BridgeTransportBackpressureDimension::BridgeHostRequestDispatch,
                    BridgeTransportBackpressureRecoveryAction::RetainSessionRecoverThenResubmitDuplicateSafe,
                    BridgeTransportBackpressureShedWork::UnknownCommitFateSessionRetained,
                ) | (
                    BridgeTransportBackpressureDimension::BridgeRecoveryWindows,
                    BridgeTransportBackpressureRecoveryAction::ReuseExactLiveRecoveryWindowOrWaitForExpiry,
                    BridgeTransportBackpressureShedWork::DeferredNewRecoveryWindowOpenExistingRecoveryRetained,
                ) | (
                    BridgeTransportBackpressureDimension::BridgeRecoveryCuts,
                    BridgeTransportBackpressureRecoveryAction::WaitForExpiredRecoveryWindowCutCleanupThenRetryAuthenticatedSelector,
                    BridgeTransportBackpressureShedWork::DeferredNewRecoveryCutExistingRecoveryRetained,
                )
            )
    }
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

    /// Builds pressure for the canonical per-envelope byte ceiling.
    pub const fn envelope_bytes(local_phase: BridgeEventLocalPhase) -> Self {
        Self {
            dimension: BridgeEventCapacityDimension::EnvelopeBytes,
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

    /// Builds pressure for live position rows, recovered by staged-event
    /// reconciliation and its existing position-prefix compaction path.
    pub const fn position_rows(local_phase: BridgeEventLocalPhase) -> Self {
        Self {
            dimension: BridgeEventCapacityDimension::PositionRows,
            recovery: BridgeEventCapacityRecovery::ReconcileStagedEvents,
            local_phase,
        }
    }

    /// Checks that a decoded report pairs each dimension with its named
    /// recovery action. This is required at untrusted wire boundaries.
    pub const fn is_consistent(self) -> bool {
        matches!(
            (self.dimension, self.recovery),
            (
                BridgeEventCapacityDimension::EventRecords
                    | BridgeEventCapacityDimension::EnvelopeBytes
                    | BridgeEventCapacityDimension::PositionRows,
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
