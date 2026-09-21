//! Daemon-side reactive feed supplier (composition wiring).
//!
//! Projects the plan lane's [`LiveActivationBindings`] port from the
//! Governor's authenticated activation snapshot and drives sealed owner
//! projections through [`drive_live_feed`]. The settled outcome feeds A1's
//! `admit_producer_feed` transport call (bridge lane) with the live
//! Governor derivation; that admit call, the derivation retention, and the
//! transport replay window stay with the bridge lane.
//!
//! Authority boundaries (this module invents nothing):
//!
//! ```text
//! governor owns:  activation snapshot truth (coordination/session/task/
//!                 scope/canonical owners under the live fence), risk
//!                 derivation, attention/conflict/problem semantics,
//!                 context/evidence admission decisions.
//! cue lane owns:  observation minting, normalization, index sealing,
//!                 activation evaluation.
//! context assembly owns: admitted-set retention, recipe/quality/measurement,
//!                 active-view assembly.
//! bridge owns (A1): session ledger, delivery history, receipts, admission.
//! this module owns: snapshot-to-bindings projection, liveness-gated drive
//!                 composition. No retained state, no ledger, no minted
//!                 identities, no planning semantics.
//! ```
//!
//! Absent runtime suppliers (named exactly, never built here):
//!
//! ```text
//! - Admitted records: no live readable admitted set exists; the view
//!   arrives from its owner. Needed: a Governor context/evidence admission
//!   implementation of `read_current_admitted_set(&StateFence)`.
//! - Observed cues: no live minter of `ObservedCue`/`ActivationRequest`
//!   exists. Needed: a cue-lane mapping from authenticated tool/host
//!   observations (bridge tool-result records via A1's
//!   `record_tool_result_delivery`) into `ActivationRequest` seeds.
//! - Attention members: the Governor owns the semantics but retains no live
//!   member projection. Needed: a Governor coordination implementation of
//!   `read_open_attention(&StateFence)`.
//! - Coverage evidence: no live verified-coverage, watchdog, or trace
//!   suppliers exist. Needed: integration/supervision implementations
//!   feeding `IntegrationCoverageProfile::candidate`/`verify` and
//!   `GovernorCoverageDerivation::derive`.
//! - Delivery policy issuance: no live policy owner exists. Needed: a policy
//!   implementation issuing `ReactiveDeliveryPolicy` over the delivery
//!   profile, contract, and bounds.
//! - Live snapshot accessor: the daemon runtime holds the composition, not
//!   this module. Requested (A3-serialized tiny export, never taken here):
//!   a `DaemonComposition` accessor returning the live
//!   `GovernorActivationSnapshot`, plus this module's `mod`/`pub use`
//!   wiring in `bins/eliotd/src/lib.rs`.
//! ```

#![allow(clippy::result_large_err)]

use eliot_contracts::{ArtifactId, SessionId};
use eliot_governor::GovernorActivationSnapshot;
use eliot_reactive_context_plan::{
    LiveActivationBindings, SettledPlanFeedError, SettledPlanFeedInputs, SettledPlanFeedOutcome,
    drive_live_feed,
};
use eliot_receipts::WorkScopeId;

/// Fail-closed supplier errors. Projection defects abort the drive; feed
/// errors pass through untouched so the planner/producer vocabulary stays
/// exact across the composition boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveFeedSupplyError {
    /// A snapshot string was rejected by its validated identity
    /// constructor: the snapshot never becomes bindings, the planner never
    /// runs. `field` names the rejected snapshot field.
    InvalidSnapshotBinding { field: &'static str, reason: String },
    /// The liveness gate, planner, or producer reported; carried verbatim.
    Feed(SettledPlanFeedError),
}

impl std::fmt::Display for ReactiveFeedSupplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSnapshotBinding { field, reason } => write!(
                formatter,
                "reactive feed snapshot binding {field} rejected: {reason}"
            ),
            Self::Feed(error) => write!(formatter, "reactive feed: {error}"),
        }
    }
}

impl std::error::Error for ReactiveFeedSupplyError {}

fn invalid_binding(field: &'static str, error: impl std::fmt::Display) -> ReactiveFeedSupplyError {
    ReactiveFeedSupplyError::InvalidSnapshotBinding {
        field,
        reason: error.to_string(),
    }
}

/// Project the plan lane's live-activation port from the authenticated
/// snapshot, field for field through validated constructors.
///
/// The snapshot itself is authenticated by `read_unique_agent_activation`
/// (task/session/scope/fence cross-checked against the coordination,
/// session, task, scope, and canonical owners). This projection copies
/// those bindings into the plan lane's typed port: strings are validated,
/// never trusted as authority.
pub fn project_live_bindings(
    snapshot: &GovernorActivationSnapshot,
) -> Result<LiveActivationBindings, ReactiveFeedSupplyError> {
    Ok(LiveActivationBindings {
        task_id: snapshot.task_id.clone(),
        scope_id: WorkScopeId::new(snapshot.work_scope_id.clone())
            .map_err(|error| invalid_binding("snapshot.work_scope_id", error))?,
        session_id: SessionId::new(snapshot.session_id.clone())
            .map_err(|error| invalid_binding("snapshot.session_id", error))?,
        plan_id: ArtifactId::new(snapshot.plan_id.clone())
            .map_err(|error| invalid_binding("snapshot.plan_id", error))?,
        state_fence: snapshot.state_fence.clone(),
    })
}

/// Drive sealed owner projections under one live activation snapshot.
///
/// Projects the bindings, then runs the liveness-gated feed: rotated or
/// foreign projections fail closed as `StaleActivation` before planning;
/// current projections settle through the real planner and producer. Holds
/// no state across calls; retention lives with the derivation and transport
/// owners.
pub fn drive_daemon_feed(
    snapshot: &GovernorActivationSnapshot,
    inputs: SettledPlanFeedInputs<'_>,
) -> Result<SettledPlanFeedOutcome, ReactiveFeedSupplyError> {
    let bindings = project_live_bindings(snapshot)?;
    drive_live_feed(&bindings, inputs).map_err(ReactiveFeedSupplyError::Feed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use eliot_contracts::TaskId;

    fn snapshot() -> GovernorActivationSnapshot {
        GovernorActivationSnapshot {
            state_fence: eliot_contracts::StateFence::new(
                eliot_contracts::EpochId::new(
                    eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                        .expect("fixture lineage"),
                    std::num::NonZeroU64::new(1).expect("fixture sequence"),
                )
                .expect("fixture epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("fixture generation"),
            ),
            principal_id: "principal".to_owned(),
            session_id: "session".to_owned(),
            task_id: TaskId::new("task").expect("fixture task"),
            work_unit_id: "work-unit".to_owned(),
            work_scope_id: "scope".to_owned(),
            task_revision: 1,
            plan_id: "plan".to_owned(),
            plan_revision: "1".to_owned(),
        }
    }

    #[test]
    fn project_live_bindings_maps_snapshot_exactly() {
        let bindings = project_live_bindings(&snapshot()).expect("fixture snapshot projects");
        assert_eq!(bindings.task_id, TaskId::new("task").expect("fixture task"));
        assert_eq!(bindings.scope_id.as_str(), "scope");
        assert_eq!(bindings.session_id.as_str(), "session");
        assert_eq!(bindings.plan_id.as_str(), "plan");
        assert_eq!(bindings.state_fence, snapshot().state_fence);
    }

    #[test]
    fn project_live_bindings_rejects_control_characters() {
        let mut foreign = snapshot();
        foreign.session_id = "session\0".to_owned();
        match project_live_bindings(&foreign) {
            Err(ReactiveFeedSupplyError::InvalidSnapshotBinding { field, .. }) => {
                assert_eq!(field, "snapshot.session_id");
            }
            other => panic!("control characters must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn project_live_bindings_rejects_blank_scope() {
        let mut foreign = snapshot();
        foreign.work_scope_id = "   ".to_owned();
        match project_live_bindings(&foreign) {
            Err(ReactiveFeedSupplyError::InvalidSnapshotBinding { field, .. }) => {
                assert_eq!(field, "snapshot.work_scope_id");
            }
            other => panic!("blank scope must fail closed, got {other:?}"),
        }
    }
}
