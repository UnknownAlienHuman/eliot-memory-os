//! Pure command types for the simulated control core.
//!
//! Commands are data only: they carry operation identity, fencing tokens,
//! store outcomes, supervision signals, epoch moves, and load directives.
//! They never touch a runtime. The [`Scheduler`](crate::scheduler::Scheduler)
//! decides when and how each command is delivered; [`SimState`](crate::state::SimState)
//! decides what each delivered command means.

use crate::digest::{Canonical, SimDigest};

/// Identity of one simulated operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct OpId(pub u32);

/// Fencing token carried by a submission: the epoch plus a monotonic
/// sequence within that epoch. A token below the accepted high-water mark
/// is stale and must never commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FencingToken {
    /// Fencing epoch.
    pub epoch: u64,
    /// Monotonic sequence within the epoch.
    pub seq: u64,
}

/// Effect class of a submitted operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EffectClass {
    /// Reapplying the effect is harmless.
    Idempotent,
    /// The effect must be applied at most once even under redelivery.
    ExactlyOnce,
}

/// Durable store response for one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StoreOutcome {
    /// The effect durably committed.
    Committed,
    /// The store refused the write.
    Rejected,
    /// The store outcome is unknown: torn write, timeout, or lost reply.
    /// Unknown is never promoted to committed by this crate.
    Unknown,
}

/// External supervisor that emits liveness heartbeats.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SupervisionSource {
    /// The external watchdog in its separate failure domain.
    Watchdog,
    /// The instrument test daemon.
    Testd,
}

/// Epoch move applied to the simulated writer generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PromotionAction {
    /// Elect a new epoch and generation.
    Promote,
    /// Cut traffic over to the named epoch and a new generation.
    Cutover,
    /// Roll back to the named epoch without minting a generation.
    Rollback,
}

/// One pure command submitted to the deterministic scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimCommand {
    /// Submit an operation guarded by a fencing token and generation.
    Submit {
        /// Operation identity.
        op: OpId,
        /// Fencing token proving lease ownership.
        fencing: FencingToken,
        /// Effect class for duplicate-safety checks.
        effect: EffectClass,
        /// Writer generation the submitter believes is active.
        generation: u64,
    },
    /// Request cancellation of an operation.
    Cancel {
        /// Operation identity.
        op: OpId,
    },
    /// Report completion from the generation that ran the operation.
    Complete {
        /// Operation identity.
        op: OpId,
        /// Writer generation reporting completion.
        generation: u64,
    },
    /// Deliver a durable store response.
    StoreRespond {
        /// Operation identity.
        op: OpId,
        /// Store outcome.
        outcome: StoreOutcome,
    },
    /// Deliver an acknowledgement for a committed operation.
    Ack {
        /// Operation identity.
        op: OpId,
    },
    /// Liveness heartbeat from an external supervisor.
    Heartbeat {
        /// Supervisor emitting the heartbeat.
        source: SupervisionSource,
    },
    /// Withdraw liveness for a supervisor: models supervisor loss.
    DropSupervision {
        /// Supervisor that went silent.
        source: SupervisionSource,
    },
    /// Move the epoch, optionally minting a new writer generation.
    EpochMove {
        /// Kind of move.
        action: PromotionAction,
        /// Target epoch.
        epoch: u64,
    },
    /// Shed load by cancelling oldest pending operations first.
    ShedLoad {
        /// Maximum number of pending operations to shed.
        count: u32,
    },
    /// Restart the writer: volatile pending work is lost, durable
    /// commits survive, and a new generation becomes active.
    RestartWriter,
}

/// Coarse command kind used for fault scripting and failpoint mapping.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum CommandKind {
    /// [`SimCommand::Submit`].
    Submit,
    /// [`SimCommand::Cancel`].
    Cancel,
    /// [`SimCommand::Complete`].
    Complete,
    /// [`SimCommand::StoreRespond`].
    StoreRespond,
    /// [`SimCommand::Ack`].
    Ack,
    /// [`SimCommand::Heartbeat`].
    Heartbeat,
    /// [`SimCommand::DropSupervision`].
    DropSupervision,
    /// [`SimCommand::EpochMove`].
    EpochMove,
    /// [`SimCommand::ShedLoad`].
    ShedLoad,
    /// [`SimCommand::RestartWriter`].
    RestartWriter,
}

impl SimCommand {
    /// Returns the coarse kind of this command.
    #[must_use]
    pub const fn kind(&self) -> CommandKind {
        match self {
            Self::Submit { .. } => CommandKind::Submit,
            Self::Cancel { .. } => CommandKind::Cancel,
            Self::Complete { .. } => CommandKind::Complete,
            Self::StoreRespond { .. } => CommandKind::StoreRespond,
            Self::Ack { .. } => CommandKind::Ack,
            Self::Heartbeat { .. } => CommandKind::Heartbeat,
            Self::DropSupervision { .. } => CommandKind::DropSupervision,
            Self::EpochMove { .. } => CommandKind::EpochMove,
            Self::ShedLoad { .. } => CommandKind::ShedLoad,
            Self::RestartWriter => CommandKind::RestartWriter,
        }
    }

    /// Returns the stable kind tag used in canonical encodings.
    #[must_use]
    pub const fn kind_tag(&self) -> &'static str {
        match self {
            Self::Submit { .. } => "submit",
            Self::Cancel { .. } => "cancel",
            Self::Complete { .. } => "complete",
            Self::StoreRespond { .. } => "store-respond",
            Self::Ack { .. } => "ack",
            Self::Heartbeat { .. } => "heartbeat",
            Self::DropSupervision { .. } => "drop-supervision",
            Self::EpochMove { .. } => "epoch-move",
            Self::ShedLoad { .. } => "shed-load",
            Self::RestartWriter => "restart-writer",
        }
    }
}

impl Canonical for FencingToken {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("fencing-token");
        digest.feed_u64(self.epoch);
        digest.feed_u64(self.seq);
    }
}

impl Canonical for SimCommand {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("sim-command");
        digest.feed_str(self.kind_tag());
        match self {
            Self::Submit {
                op,
                fencing,
                effect,
                generation,
            } => {
                digest.feed_u32(op.0);
                fencing.feed(digest);
                digest.feed_tag(match effect {
                    EffectClass::Idempotent => "idempotent",
                    EffectClass::ExactlyOnce => "exactly-once",
                });
                digest.feed_u64(*generation);
            }
            Self::Cancel { op } | Self::Ack { op } => {
                digest.feed_u32(op.0);
            }
            Self::Complete { op, generation } => {
                digest.feed_u32(op.0);
                digest.feed_u64(*generation);
            }
            Self::StoreRespond { op, outcome } => {
                digest.feed_u32(op.0);
                digest.feed_tag(match outcome {
                    StoreOutcome::Committed => "committed",
                    StoreOutcome::Rejected => "rejected",
                    StoreOutcome::Unknown => "unknown",
                });
            }
            Self::Heartbeat { source } | Self::DropSupervision { source } => {
                digest.feed_tag(match source {
                    SupervisionSource::Watchdog => "watchdog",
                    SupervisionSource::Testd => "testd",
                });
            }
            Self::EpochMove { action, epoch } => {
                digest.feed_tag(match action {
                    PromotionAction::Promote => "promote",
                    PromotionAction::Cutover => "cutover",
                    PromotionAction::Rollback => "rollback",
                });
                digest.feed_u64(*epoch);
            }
            Self::ShedLoad { count } => {
                digest.feed_u32(*count);
            }
            Self::RestartWriter => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EffectClass, FencingToken, OpId, SimCommand};
    use crate::digest::SimDigest;

    #[test]
    fn command_encoding_is_deterministic() {
        let command = SimCommand::Submit {
            op: OpId(3),
            fencing: FencingToken { epoch: 2, seq: 9 },
            effect: EffectClass::ExactlyOnce,
            generation: 1,
        };
        assert_eq!(SimDigest::of(&command), SimDigest::of(&command));
    }

    #[test]
    fn distinct_commands_digest_distinctly() {
        let submit = SimCommand::Submit {
            op: OpId(3),
            fencing: FencingToken { epoch: 2, seq: 9 },
            effect: EffectClass::ExactlyOnce,
            generation: 1,
        };
        let cancel = SimCommand::Cancel { op: OpId(3) };
        assert_ne!(SimDigest::of(&submit), SimDigest::of(&cancel));
    }
}
