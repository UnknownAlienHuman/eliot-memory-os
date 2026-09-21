//! Pure event types: delivery faults, state outcomes, and the trace.
//!
//! The scheduler records how each envelope travelled ([`DeliveryFault`]);
//! the state machine records what each delivered command meant
//! ([`SimOutcome`]). Together, stamped with a logical [`Tick`], they form a
//! [`TracedEvent`]. The trace is the minimal failure evidence a run carries:
//! no wall clock, no thread ids, no pointers.

use crate::command::{OpId, StoreOutcome, SupervisionSource};
use crate::digest::{Canonical, SimDigest};

/// Logical simulation time. Advances only when the scheduler delivers the
/// next envelope; never reads a clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Tick(pub u64);

/// What the network did to one envelope before delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DeliveryFault {
    /// Delivered once, in order, on time.
    Clean,
    /// Delivered twice; the state machine must ignore the copy.
    Duplicated,
    /// Delayed past a later envelope so arrival order changed.
    Reordered,
    /// Held back by the scripted number of ticks.
    Delayed,
    /// Never delivered; recorded as dropped.
    Lost,
}

/// What one delivered command meant to the simulated state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimOutcome {
    /// A new operation entered the mailbox.
    Submitted {
        /// Operation identity.
        op: OpId,
    },
    /// The effect ran; counted once per operation for `ExactlyOnce` checks.
    EffectApplied {
        /// Operation identity.
        op: OpId,
    },
    /// A redelivered command changed nothing.
    DuplicateIgnored {
        /// Operation identity.
        op: OpId,
    },
    /// A stale fencing token was refused before any effect.
    StaleFenced {
        /// Operation identity.
        op: OpId,
    },
    /// Output from a superseded writer generation was refused.
    OldGenerationRejected {
        /// Operation identity.
        op: OpId,
    },
    /// A store response was recorded.
    StoreRecorded {
        /// Operation identity.
        op: OpId,
        /// Outcome now on record.
        outcome: StoreOutcome,
    },
    /// An acknowledgement for a committed operation was recorded.
    AckRecorded {
        /// Operation identity.
        op: OpId,
    },
    /// The effect committed, then its acknowledgement was lost in transit.
    /// The commit stands; completion stays unconfirmed. Exactly-once holds.
    AckLostAfterCommit {
        /// Operation identity.
        op: OpId,
    },
    /// An operation reached committed-then-confirmed completion.
    Completed {
        /// Operation identity.
        op: OpId,
    },
    /// An operation was cancelled before completion.
    Cancelled {
        /// Operation identity.
        op: OpId,
    },
    /// The loser of a cancel-versus-complete race was decided.
    CancelCompleteResolved {
        /// Operation identity.
        op: OpId,
        /// True when completion won, false when cancellation won.
        winner_is_complete: bool,
    },
    /// Pending operations were shed under overload.
    Shed {
        /// Requested shed count.
        requested: u32,
        /// Actually shed count.
        shed: u32,
    },
    /// The writer restarted: volatile pending work was discarded, durable
    /// commits survived, and a new generation became active.
    WriterRestarted,
    /// An epoch move was applied.
    EpochMoved {
        /// Resulting epoch.
        epoch: u64,
    },
    /// A supervisor went silent; its coverage is no longer full.
    SupervisionLost {
        /// Supervisor that went silent.
        source: SupervisionSource,
    },
    /// A supervisor heartbeat restored full coverage.
    SupervisionRestored {
        /// Supervisor that recovered.
        source: SupervisionSource,
    },
    /// A submission arrived while the mailbox was at capacity.
    MailboxOverloaded {
        /// Mailbox depth at arrival.
        depth: u32,
    },
    /// A lost envelope never reached the state machine.
    Dropped {
        /// Scheduler sequence of the lost envelope.
        seq: u64,
    },
}

/// One stamped fact in the run trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracedEvent {
    /// Logical tick of delivery.
    pub tick: Tick,
    /// Scheduler sequence of the causing envelope.
    pub seq: u64,
    /// Delivery fault applied to the envelope.
    pub fault: DeliveryFault,
    /// State outcome, or [`SimOutcome::Dropped`] for lost envelopes.
    pub outcome: SimOutcome,
}

impl SimOutcome {
    /// Returns the stable tag used in canonical encodings.
    #[must_use]
    pub const fn kind_tag(&self) -> &'static str {
        match self {
            Self::Submitted { .. } => "submitted",
            Self::EffectApplied { .. } => "effect-applied",
            Self::DuplicateIgnored { .. } => "duplicate-ignored",
            Self::StaleFenced { .. } => "stale-fenced",
            Self::OldGenerationRejected { .. } => "old-generation-rejected",
            Self::StoreRecorded { .. } => "store-recorded",
            Self::AckRecorded { .. } => "ack-recorded",
            Self::AckLostAfterCommit { .. } => "ack-lost-after-commit",
            Self::Completed { .. } => "completed",
            Self::Cancelled { .. } => "cancelled",
            Self::CancelCompleteResolved { .. } => "cancel-complete-resolved",
            Self::Shed { .. } => "shed",
            Self::WriterRestarted => "writer-restarted",
            Self::EpochMoved { .. } => "epoch-moved",
            Self::SupervisionLost { .. } => "supervision-lost",
            Self::SupervisionRestored { .. } => "supervision-restored",
            Self::MailboxOverloaded { .. } => "mailbox-overloaded",
            Self::Dropped { .. } => "dropped",
        }
    }
}

impl Canonical for DeliveryFault {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("delivery-fault");
        digest.feed_str(match self {
            Self::Clean => "clean",
            Self::Duplicated => "duplicated",
            Self::Reordered => "reordered",
            Self::Delayed => "delayed",
            Self::Lost => "lost",
        });
    }
}

impl Canonical for SimOutcome {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("sim-outcome");
        match self {
            Self::Submitted { op }
            | Self::EffectApplied { op }
            | Self::DuplicateIgnored { op }
            | Self::StaleFenced { op }
            | Self::OldGenerationRejected { op }
            | Self::AckRecorded { op }
            | Self::AckLostAfterCommit { op }
            | Self::Completed { op }
            | Self::Cancelled { op } => {
                digest.feed_str(self.kind_tag());
                digest.feed_u32(op.0);
            }
            Self::StoreRecorded { op, outcome } => {
                digest.feed_str("store-recorded");
                digest.feed_u32(op.0);
                digest.feed_str(match outcome {
                    StoreOutcome::Committed => "committed",
                    StoreOutcome::Rejected => "rejected",
                    StoreOutcome::Unknown => "unknown",
                });
            }
            Self::CancelCompleteResolved {
                op,
                winner_is_complete,
            } => {
                digest.feed_str("cancel-complete-resolved");
                digest.feed_u32(op.0);
                digest.feed_bool(*winner_is_complete);
            }
            Self::Shed { requested, shed } => {
                digest.feed_str("shed");
                digest.feed_u32(*requested);
                digest.feed_u32(*shed);
            }
            Self::WriterRestarted => {
                digest.feed_str("writer-restarted");
            }
            Self::EpochMoved { epoch } => {
                digest.feed_str("epoch-moved");
                digest.feed_u64(*epoch);
            }
            Self::SupervisionLost { source } => {
                digest.feed_str("supervision-lost");
                digest.feed_str(match source {
                    SupervisionSource::Watchdog => "watchdog",
                    SupervisionSource::Testd => "testd",
                });
            }
            Self::SupervisionRestored { source } => {
                digest.feed_str("supervision-restored");
                digest.feed_str(match source {
                    SupervisionSource::Watchdog => "watchdog",
                    SupervisionSource::Testd => "testd",
                });
            }
            Self::MailboxOverloaded { depth } => {
                digest.feed_str("mailbox-overloaded");
                digest.feed_u32(*depth);
            }
            Self::Dropped { seq } => {
                digest.feed_str("dropped");
                digest.feed_u64(*seq);
            }
        }
    }
}

impl Canonical for TracedEvent {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("traced-event");
        digest.feed_u64(self.tick.0);
        digest.feed_u64(self.seq);
        self.fault.feed(digest);
        self.outcome.feed(digest);
    }
}
