//! Daemon-owned reactive projection feed (I7.19 plan step, #1942 lane D).
//!
//! The serving side fills one slot-complete [`ServedSnapshotDelivery`](eliot_reactive_context_plan::ServedSnapshotDelivery)
//! per live (session, fence) binding; this module ingests it into
//! process-scoped retention and drives one daemon-side feed evaluation over
//! the retained set through the existing settled-plan feed
//! ([`drive_live_feed`](eliot_reactive_context_plan::drive_live_feed)).
//! The resulting settled plan + batch crosses to the agent bridge, where the
//! A1 transport admits it (`admit_producer_feed`); delivery, receipts,
//! stickiness, and session dedup stay with the bridge ledger.
//!
//! Authority boundaries (the feed invents nothing):
//!
//! ```text
//! producers own:  the six immutable projections (assembled + validated);
//! feed owns:      one causal production call (projections → plan → batch)
//!                 gated on a ready Governor; it holds no state across calls;
//! plan owns:      item selection, cue binding, firing reference, relations,
//!                 scope/governance/fence passthrough, severity, delivery,
//!                 dedup keys, skip accounting;
//! bridge owns:    session binding, ledger mutation, receipts, stickiness,
//!                 normal dedup (A1 admission, not here);
//! governor owns:  per-item risk tier (live derivation at the bridge, never
//!                 produced here).
//! ```
//!
//! Absence is explicit: an unready Governor fails closed (`NotReady`) instead
//! of planning under no admission; stale projections fail closed (`Stale`)
//! instead of planning under a rotated activation. A missing owner stays
//! withheld upstream (no call happens) — never a fabricated projection set.
//!
//! Composition-root discipline (`bins/AGENTS.md`): this module performs
//! dependency wiring and typed outcome projection only. Deterministic
//! selection, validation, and digest logic live in the owner crates.

use eliot_contracts::{SessionId, StateFence};
use eliot_governor::CompositionReadiness;
use eliot_reactive_context_plan::{
    BridgeAdmissionError, LiveActivationBindings, NoInjectionDisposition, OwnerSupplyError,
    ReactiveContextPlanningError, ReactiveOwnerRetention, ServedSnapshotDelivery, SettledPlanFeed,
    SettledPlanFeedError, SettledPlanFeedInputs, SettledPlanFeedOutcome, drive_live_feed,
    ingest_served_snapshot_delivery,
};
use thiserror::Error;

/// Borrowed owner projections plus the live activation they must be current for.
///
/// The daemon central export threads one slot-complete served delivery
/// (slot contract on [`ServedSnapshotDelivery`](eliot_reactive_context_plan::ServedSnapshotDelivery))
/// into retention and evaluates from the retained set; this feed performs
/// exactly one evaluation over it. `Copy` because the struct is only
/// borrowed owner references.
///
/// Remaining serving-side implementation (Store/Kernel snapshot reads
/// filling each slot's URI-addressed legs) is outside lane-D scope; until
/// it exists, legs arrive via the restore path and any absent owner
/// withholds the feed.
#[derive(Clone, Copy, Debug)]
pub struct DaemonReactiveFeedInputs<'a> {
    /// Live activation the projections must be planned under, projected by
    /// the daemon from the Governor's authenticated activation snapshot.
    pub bindings: &'a LiveActivationBindings,
    /// Six owner-issued immutable projections for one feed evaluation.
    pub projections: SettledPlanFeedInputs<'a>,
}

/// Honest daemon feed outcome: either a settled plan + batch is ready for
/// the A1 transport, or the planner settled on no injection (with full
/// accounting, never a silent drop).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonReactiveFeedOutcome {
    /// Settled plan + batch ready for bridge `admit_settled_plan` /
    /// `admit_batch` via the A1 transport.
    Ready(SettledPlanFeed),
    /// Planner settled on no injection; the disposition carries the complete
    /// item ledger, accounting, and reason. Nothing is emitted.
    NoSettledPlan(NoInjectionDisposition),
}

/// Fail-closed daemon feed errors. An unready Governor, stale projections,
/// or a planning/producer defect surfaces here; the feed never downgrades
/// any of them into a batch.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaemonReactiveFeedError {
    /// The Governor is not admitted: planning without admission is refused.
    #[error("governor is not ready: reactive feed requires an admitted Governor")]
    NotReady,
    /// Supplied projections disagree with the live activation bindings.
    #[error("stale projections: {projection}.{field} disagrees with the live activation")]
    Stale {
        /// Projection whose binding disagreed.
        projection: &'static str,
        /// Exact binding field that disagreed.
        field: &'static str,
    },
    /// The planner rejected the projections (invalid, stale, or conflicted).
    #[error("planning rejected the projections: {0:?}")]
    Planning(ReactiveContextPlanningError),
    /// A settled plan item is unusable as a bridge instruction.
    #[error("settled plan defect: {0}")]
    Producer(BridgeAdmissionError),
    /// An owner snapshot could not be supplied (absent, oversize,
    /// undecodable, invalid, or fence/binding-mismatched). Nothing was
    /// planned or admitted.
    #[error("owner supply withheld: {0}")]
    Supply(OwnerSupplyError),
}

fn map_feed_error(error: SettledPlanFeedError) -> DaemonReactiveFeedError {
    match error {
        SettledPlanFeedError::StaleActivation { projection, field } => {
            DaemonReactiveFeedError::Stale { projection, field }
        }
        SettledPlanFeedError::Planning(error) => DaemonReactiveFeedError::Planning(error),
        SettledPlanFeedError::Producer(error) => DaemonReactiveFeedError::Producer(error),
    }
}

/// Drive one daemon-side reactive feed evaluation over live owner projections.
///
/// Requires a ready Governor (the daemon observes its own readiness and
/// passes it here; post-admission callers only). Runs the existing
/// liveness-gated settled-plan feed over the six projections and projects
/// the honest outcome for the A1 transport. Holds no state: repeated calls
/// over unchanged projections yield the same outcome; replay protection
/// stays with the A1 transport window and the bridge ledger, never here.
pub fn drive_daemon_reactive_feed(
    readiness: CompositionReadiness,
    inputs: DaemonReactiveFeedInputs<'_>,
) -> Result<DaemonReactiveFeedOutcome, DaemonReactiveFeedError> {
    if readiness != CompositionReadiness::Ready {
        return Err(DaemonReactiveFeedError::NotReady);
    }
    match drive_live_feed(inputs.bindings, inputs.projections).map_err(map_feed_error)? {
        SettledPlanFeedOutcome::Ready(feed) => Ok(DaemonReactiveFeedOutcome::Ready(feed)),
        SettledPlanFeedOutcome::NoSettledPlan(disposition) => {
            Ok(DaemonReactiveFeedOutcome::NoSettledPlan(disposition))
        }
    }
}

/// Drive one daemon-side feed evaluation from a slot-complete served delivery.
///
/// Ingestion edge: the set is validated, retained under the live
/// (session, fence) key, and re-read from retention before the
/// readiness-gated daemon feed runs — the drive below consumes retained
/// state, never fresh caller bytes. The served delivery (reply echo plus
/// exactly one leg per slot) comes from the serving restore leg; the live
/// session and fence are observed by the daemon central export, which
/// threads the owners' snapshots. Any incomplete, foreign-session,
/// oversize, undecodable, digest-mismatched, revision-diverged, invalid, or
/// mismatched leg withholds the whole evaluation.
pub fn drive_daemon_supplied_feed(
    readiness: CompositionReadiness,
    bindings: &LiveActivationBindings,
    retention: &mut ReactiveOwnerRetention,
    live_session: &str,
    fence: &StateFence,
    served: &ServedSnapshotDelivery<'_>,
) -> Result<DaemonReactiveFeedOutcome, DaemonReactiveFeedError> {
    if readiness != CompositionReadiness::Ready {
        return Err(DaemonReactiveFeedError::NotReady);
    }
    ingest_served_snapshot_delivery(retention, live_session, fence, served)
        .map_err(DaemonReactiveFeedError::Supply)?;
    let session_id = SessionId::new(live_session).map_err(|_| {
        DaemonReactiveFeedError::Supply(OwnerSupplyError::Invalid {
            projection: "retention",
            detail: "live session identity is invalid".to_owned(),
        })
    })?;
    let stored = retention
        .read(&session_id, fence)
        .map_err(DaemonReactiveFeedError::Supply)?;
    drive_daemon_reactive_feed(
        readiness,
        DaemonReactiveFeedInputs {
            bindings,
            projections: stored.feed_inputs(),
        },
    )
}

/// Drive one daemon-side feed evaluation from the retained projection set
/// for exactly the live (session, fence) key.
///
/// Pure read path: no bytes are decoded here. Unknown sessions or rotated
/// fences fail closed via the retention read.
pub fn drive_daemon_retained_feed(
    readiness: CompositionReadiness,
    bindings: &LiveActivationBindings,
    retention: &ReactiveOwnerRetention,
    session_id: &SessionId,
    fence: &StateFence,
) -> Result<DaemonReactiveFeedOutcome, DaemonReactiveFeedError> {
    if readiness != CompositionReadiness::Ready {
        return Err(DaemonReactiveFeedError::NotReady);
    }
    let stored = retention
        .read(session_id, fence)
        .map_err(DaemonReactiveFeedError::Supply)?;
    drive_daemon_reactive_feed(
        readiness,
        DaemonReactiveFeedInputs {
            bindings,
            projections: stored.feed_inputs(),
        },
    )
}
