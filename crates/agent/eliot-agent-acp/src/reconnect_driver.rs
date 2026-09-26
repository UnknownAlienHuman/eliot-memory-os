//! Reconnect driver for durable host-event ingest (issue #1934, I7.23).
//!
//! On reconnect the bridge must replay unacknowledged durable events by
//! stream cursor without minting second normalized events or second state
//! applications. [`drive_reconnect`] consumes
//! [`pending_for_reconnect`](crate::HostEventPersistenceOwner::pending_for_reconnect)
//! in ascending sequence order and, per event:
//!
//! ```text
//! staged-but-uncommitted → commit (commit recovery; advances durable cursor)
//! committed (or newly committed) → deliver via the transport replay callback
//! delivered → acknowledge through the delivered sequence.
//! ```
//!
//! The `deliver` callback models the transport replay to the downstream
//! consumer: it returns `true` exactly when the redelivered event was
//! accepted downstream. A `false` stops the driver at that sequence, leaving
//! it and everything after it pending for the next reconnect. The driver
//! never invents delivery: without a positive callback nothing is
//! acknowledged, and acknowledgement never passes the durable cursor.
//!
//! The driver depends only on [`HostEventPersistenceOwner`](crate::HostEventPersistenceOwner),
//! so the A/store physical-durability binding drives reconnect unchanged.

use crate::{
    BestEffortDropGap, DurableHostEventJournal, EventKey, HostEventPersistenceOwner, IngestError,
    ReplayItem,
};
use eliot_agent_api::CommittedHostEventIntake;

/// Outcome of one reconnect drive over a single stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnectOutcome {
    /// Sequences committed by this drive (commit recovery), ascending.
    pub committed: Vec<u64>,
    /// Sequences delivered downstream and acknowledged, ascending.
    pub delivered: Vec<u64>,
    /// Last acknowledged sequence after this drive.
    pub acked_through: u64,
    /// True when a refused delivery stopped the drive with items still
    /// pending for the next reconnect.
    pub stopped_early: bool,
}

/// Drives reconnect for one stream: commit every staged-but-uncommitted
/// pending event, redeliver each pending event through `deliver`, and
/// acknowledge each delivered sequence.
///
/// Items arrive in ascending order from
/// [`pending_for_reconnect`](crate::HostEventPersistenceOwner::pending_for_reconnect),
/// so commits stay contiguous and acknowledgements stay monotonic. A commit or
/// acknowledgement failure aborts the drive with the owner's error and moves
/// nothing past the failure point.
pub fn drive_reconnect<O: HostEventPersistenceOwner>(
    owner: &mut O,
    stream_id: &str,
    mut deliver: impl FnMut(&ReplayItem) -> bool,
) -> Result<ReconnectOutcome, IngestError> {
    let pending = owner.pending_for_reconnect(stream_id);
    let mut outcome = ReconnectOutcome {
        committed: Vec::new(),
        delivered: Vec::new(),
        acked_through: owner.cursor(stream_id).last_acked_sequence,
        stopped_early: false,
    };
    for item in &pending {
        if !item.committed {
            let key = EventKey {
                stream_id: stream_id.to_owned(),
                sequence: item.sequence,
            };
            owner.commit(&key)?;
            outcome.committed.push(item.sequence);
        }
        if deliver(item) {
            owner.acknowledge(stream_id, item.sequence)?;
            outcome.delivered.push(item.sequence);
            outcome.acked_through = item.sequence;
        } else {
            outcome.stopped_early = true;
            break;
        }
    }
    Ok(outcome)
}

/// Observed reconnect drive over the concrete journal (issue #371 W7/A28, I7.23).
///
/// [`drive_reconnect`] is generic over [`HostEventPersistenceOwner`] so the
/// A/store physical-durability binding can drive reconnect unchanged; this
/// wrapper runs the same drive against the in-memory [`DurableHostEventJournal`]
/// and then projects every delivered committed record through
/// `DurableHostEventJournal::to_coordinator_intake` while surfacing
/// `DurableHostEventJournal::drop_gaps` for the stream. The intake conversions
/// feed coordinator observation (`observe_committed_intake` over
/// [`CommittedHostEventIntake`]); the gaps keep best-effort drops as exact
/// coverage instead of fabricating observation or advancing
/// acknowledgement/cursor state.
#[derive(Clone, Debug, PartialEq)]
pub struct ObservedReconnectOutcome {
    /// The underlying reconnect drive outcome (commits, deliveries, acks).
    pub drive: ReconnectOutcome,
    /// Intake conversions for the delivered committed records, ascending.
    pub intakes: Vec<CommittedHostEventIntake>,
    /// Best-effort drop gaps recorded for the stream, in record order.
    pub gaps: Vec<BestEffortDropGap>,
}

/// Drives reconnect for one stream and projects the delivered committed
/// records to coordinator intake views plus the stream drop gaps.
///
/// Delivery/acknowledgement semantics are exactly [`drive_reconnect`]'s; after
/// a successful drive, each delivered sequence converts via
/// `DurableHostEventJournal::to_coordinator_intake` (the drive commits staged
/// items before delivery, so every delivered record is committed and converts)
/// and the stream's `DurableHostEventJournal::drop_gaps` are collected
/// unchanged.
pub fn drive_reconnect_observed(
    owner: &mut DurableHostEventJournal,
    stream_id: &str,
    deliver: impl FnMut(&ReplayItem) -> bool,
) -> Result<ObservedReconnectOutcome, IngestError> {
    let drive = drive_reconnect(owner, stream_id, deliver)?;
    let mut intakes = Vec::with_capacity(drive.delivered.len());
    for sequence in &drive.delivered {
        let key = EventKey {
            stream_id: stream_id.to_owned(),
            sequence: *sequence,
        };
        intakes.push(owner.to_coordinator_intake(&key)?);
    }
    let gaps = owner.drop_gaps(stream_id);
    Ok(ObservedReconnectOutcome {
        drive,
        intakes,
        gaps,
    })
}
