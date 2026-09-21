//! Pure simulated control state and its transition function.
//!
//! [`SimState`] owns fencing high-water, per-operation records, mailbox
//! load, supervision coverage, and the active writer generation. [`SimState::apply`]
//! is a total, deterministic function from one delivered [`SimCommand`] to a
//! list of [`SimOutcome`]s. It allocates only through `BTreeMap` and `Vec`,
//! reads no clock, spawns nothing, and performs no I/O.
//!
//! Transition rules, in one place:
//!
//! ```text
//! fencing below high-water ............ StaleFenced, never commits
//! generation mismatch ................. OldGenerationRejected
//! redelivered command ................. DuplicateIgnored, applies nothing twice
//! full mailbox on new submit .......... MailboxOverloaded + Shed
//! store Unknown ........................ Unknown status, never Completed
//! torn commit reconciled .............. Unknown + Committed upgrades
//! ack for committed ................... AckRecorded, idempotent afterwards
//! cancel before commit .................. Cancelled, one terminal wins
//! complete after cancel (or reverse) .. CancelCompleteResolved, one terminal wins
//! cancel after a durable commit ........ commit stands, complete wins
//! writer restart ...................... pending work Unknown, commits survive
//! shed / overload ..................... bounded mailbox, counted sheds
//! supervision loss .................... coverage downgraded, never silent success
//! ```

use crate::command::{
    EffectClass, FencingToken, OpId, PromotionAction, SimCommand, StoreOutcome, SupervisionSource,
};
use crate::digest::{Canonical, SimDigest};
use crate::event::{SimOutcome, Tick};

/// Terminal and non-terminal status of one simulated operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OpStatus {
    /// Accepted, awaiting a store response.
    Pending,
    /// Durably committed, awaiting acknowledgement or completion.
    Committed,
    /// Committed and confirmed complete.
    Completed,
    /// Cancelled before completion.
    Cancelled,
    /// Refused for a stale fencing token or rejected store write.
    Fenced,
    /// Shed under overload.
    Shed,
    /// Store outcome unknown: volatile loss or torn commit not reconciled.
    Unknown,
    /// Output arrived from a superseded writer generation.
    OldGeneration,
}

impl OpStatus {
    /// Returns true for statuses no further command may leave.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::Fenced | Self::Shed | Self::OldGeneration
        )
    }
}

/// Durable record of one simulated operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpRecord {
    /// Current status.
    pub status: OpStatus,
    /// Accepted fencing token.
    pub fencing: FencingToken,
    /// Generation that submitted the operation.
    pub generation: u64,
    /// Effect class.
    pub effect: EffectClass,
    /// Submit deliveries seen, including duplicates.
    pub seen_submit: u32,
    /// Times the effect ran.
    pub applied: u32,
    /// Whether an acknowledgement was recorded.
    pub acked: bool,
    /// Last store outcome on record.
    pub store: Option<StoreOutcome>,
}

impl OpRecord {
    fn fresh(fencing: FencingToken, generation: u64, effect: EffectClass) -> Self {
        Self {
            status: OpStatus::Pending,
            fencing,
            generation,
            effect,
            seen_submit: 1,
            applied: 1,
            acked: false,
            store: None,
        }
    }
}

/// Supervision coverage for one external supervisor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Coverage {
    /// Heartbeats current; claims may cite supervision.
    Full,
    /// Degraded but present; observed overload.
    Partial,
    /// Silent; terminal claims must not cite supervision.
    Unknown,
}

/// The full simulated control state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimState {
    /// Active fencing epoch.
    pub epoch: u64,
    /// Active writer generation.
    pub generation: u64,
    /// Highest accepted fencing token; anything below is stale.
    pub fencing_high_water: FencingToken,
    /// Operation records keyed by operation id, in stable order.
    pub ops: std::collections::BTreeMap<u32, OpRecord>,
    /// Current mailbox depth: pending plus committed operations.
    pub mailbox_depth: u32,
    /// Mailbox capacity; submissions at capacity shed.
    pub mailbox_capacity: u32,
    /// Total operations shed so far.
    pub shed_total: u32,
    /// Watchdog coverage.
    pub watchdog: Coverage,
    /// Test daemon coverage.
    pub testd: Coverage,
    /// Writer restarts applied so far.
    pub writer_restarts: u32,
}

impl SimState {
    /// Builds the initial state with the given mailbox capacity.
    #[must_use]
    pub const fn new(mailbox_capacity: u32) -> Self {
        Self {
            epoch: 1,
            generation: 1,
            fencing_high_water: FencingToken { epoch: 0, seq: 0 },
            ops: std::collections::BTreeMap::new(),
            mailbox_depth: 0,
            mailbox_capacity,
            shed_total: 0,
            watchdog: Coverage::Full,
            testd: Coverage::Full,
            writer_restarts: 0,
        }
    }

    /// Returns true when `token` is below the accepted high-water mark.
    #[must_use]
    pub fn is_stale(&self, token: FencingToken) -> bool {
        (token.epoch, token.seq) < (self.fencing_high_water.epoch, self.fencing_high_water.seq)
    }

    /// Applies one delivered command and returns the resulting outcomes.
    pub fn apply(&mut self, command: &SimCommand, _tick: Tick) -> Vec<SimOutcome> {
        match command {
            SimCommand::Submit {
                op,
                fencing,
                effect,
                generation,
            } => self.submit(*op, *fencing, *effect, *generation),
            SimCommand::Cancel { op } => self.cancel(*op),
            SimCommand::Complete { op, generation } => self.complete(*op, *generation),
            SimCommand::StoreRespond { op, outcome } => self.store_respond(*op, *outcome),
            SimCommand::Ack { op } => self.ack(*op),
            SimCommand::Heartbeat { source } => self.heartbeat(*source),
            SimCommand::DropSupervision { source } => self.drop_supervision(*source),
            SimCommand::EpochMove { action, epoch } => self.epoch_move(*action, *epoch),
            SimCommand::ShedLoad { count } => self.shed_load(*count),
            SimCommand::RestartWriter => self.restart_writer(),
        }
    }

    fn submit(
        &mut self,
        op: OpId,
        fencing: FencingToken,
        effect: EffectClass,
        generation: u64,
    ) -> Vec<SimOutcome> {
        if self.is_stale(fencing) {
            self.ops.entry(op.0).or_insert_with(|| OpRecord {
                status: OpStatus::Fenced,
                fencing,
                generation,
                effect,
                seen_submit: 0,
                applied: 0,
                acked: false,
                store: None,
            });
            if let Some(record) = self.ops.get_mut(&op.0) {
                record.seen_submit = record.seen_submit.saturating_add(1);
            }
            return vec![SimOutcome::StaleFenced { op }];
        }
        if generation != self.generation {
            self.ops.entry(op.0).or_insert_with(|| OpRecord {
                status: OpStatus::OldGeneration,
                fencing,
                generation,
                effect,
                seen_submit: 0,
                applied: 0,
                acked: false,
                store: None,
            });
            if let Some(record) = self.ops.get_mut(&op.0) {
                record.seen_submit = record.seen_submit.saturating_add(1);
            }
            return vec![SimOutcome::OldGenerationRejected { op }];
        }
        if let Some(record) = self.ops.get_mut(&op.0) {
            record.seen_submit = record.seen_submit.saturating_add(1);
            return vec![SimOutcome::DuplicateIgnored { op }];
        }
        if self.fencing_high_water.epoch < fencing.epoch
            || (self.fencing_high_water.epoch == fencing.epoch
                && self.fencing_high_water.seq < fencing.seq)
        {
            self.fencing_high_water = fencing;
        }
        if self.mailbox_depth >= self.mailbox_capacity {
            self.shed_total = self.shed_total.saturating_add(1);
            self.ops.insert(
                op.0,
                OpRecord {
                    status: OpStatus::Shed,
                    fencing,
                    generation,
                    effect,
                    seen_submit: 1,
                    applied: 0,
                    acked: false,
                    store: None,
                },
            );
            return vec![
                SimOutcome::MailboxOverloaded {
                    depth: self.mailbox_depth,
                },
                SimOutcome::Shed {
                    requested: 1,
                    shed: 1,
                },
            ];
        }
        self.mailbox_depth = self.mailbox_depth.saturating_add(1);
        self.ops
            .insert(op.0, OpRecord::fresh(fencing, generation, effect));
        vec![
            SimOutcome::Submitted { op },
            SimOutcome::EffectApplied { op },
        ]
    }

    fn cancel(&mut self, op: OpId) -> Vec<SimOutcome> {
        let Some(record) = self.ops.get_mut(&op.0) else {
            return vec![SimOutcome::DuplicateIgnored { op }];
        };
        match record.status {
            // A durable commit is never voided by a late cancel: the commit
            // stands and completion wins. Only a pre-commit operation can be
            // cancelled, which the `commit-survives-cancel` invariant enforces.
            OpStatus::Completed | OpStatus::Committed => {
                vec![SimOutcome::CancelCompleteResolved {
                    op,
                    winner_is_complete: true,
                }]
            }
            OpStatus::Pending | OpStatus::Unknown => {
                if record.status == OpStatus::Pending {
                    self.mailbox_depth = self.mailbox_depth.saturating_sub(1);
                }
                record.status = OpStatus::Cancelled;
                vec![SimOutcome::Cancelled { op }]
            }
            OpStatus::Cancelled | OpStatus::Fenced | OpStatus::Shed | OpStatus::OldGeneration => {
                vec![SimOutcome::DuplicateIgnored { op }]
            }
        }
    }

    fn complete(&mut self, op: OpId, generation: u64) -> Vec<SimOutcome> {
        if generation != self.generation {
            return vec![SimOutcome::OldGenerationRejected { op }];
        }
        let Some(record) = self.ops.get_mut(&op.0) else {
            return vec![SimOutcome::DuplicateIgnored { op }];
        };
        match record.status {
            // A `Committed` record always carries a committed store outcome:
            // `store_respond` is the only transition that mints it, and no
            // later transition rewrites the store field of a committed op.
            OpStatus::Committed => {
                self.mailbox_depth = self.mailbox_depth.saturating_sub(1);
                record.status = OpStatus::Completed;
                vec![SimOutcome::Completed { op }]
            }
            OpStatus::Cancelled => vec![SimOutcome::CancelCompleteResolved {
                op,
                winner_is_complete: false,
            }],
            OpStatus::Completed
            | OpStatus::Pending
            | OpStatus::Fenced
            | OpStatus::Shed
            | OpStatus::Unknown
            | OpStatus::OldGeneration => {
                vec![SimOutcome::DuplicateIgnored { op }]
            }
        }
    }

    fn store_respond(&mut self, op: OpId, outcome: StoreOutcome) -> Vec<SimOutcome> {
        let Some(record) = self.ops.get_mut(&op.0) else {
            return vec![SimOutcome::DuplicateIgnored { op }];
        };
        match (record.status, outcome) {
            (OpStatus::Pending, StoreOutcome::Committed) => {
                record.status = OpStatus::Committed;
                record.store = Some(StoreOutcome::Committed);
                vec![SimOutcome::StoreRecorded { op, outcome }]
            }
            (OpStatus::Pending, StoreOutcome::Unknown) => {
                self.mailbox_depth = self.mailbox_depth.saturating_sub(1);
                record.status = OpStatus::Unknown;
                record.store = Some(StoreOutcome::Unknown);
                vec![SimOutcome::StoreRecorded { op, outcome }]
            }
            (OpStatus::Pending, StoreOutcome::Rejected) => {
                self.mailbox_depth = self.mailbox_depth.saturating_sub(1);
                record.status = OpStatus::Fenced;
                record.store = Some(StoreOutcome::Rejected);
                vec![SimOutcome::StoreRecorded { op, outcome }]
            }
            (OpStatus::Unknown, StoreOutcome::Committed) => {
                self.mailbox_depth = self.mailbox_depth.saturating_add(1);
                record.status = OpStatus::Committed;
                record.store = Some(StoreOutcome::Committed);
                vec![SimOutcome::StoreRecorded { op, outcome }]
            }
            (OpStatus::Unknown | OpStatus::Committed, _) => {
                vec![SimOutcome::DuplicateIgnored { op }]
            }
            _ => vec![SimOutcome::DuplicateIgnored { op }],
        }
    }

    fn ack(&mut self, op: OpId) -> Vec<SimOutcome> {
        let Some(record) = self.ops.get_mut(&op.0) else {
            return vec![SimOutcome::DuplicateIgnored { op }];
        };
        if record.status == OpStatus::Committed && !record.acked {
            record.acked = true;
            vec![SimOutcome::AckRecorded { op }]
        } else {
            vec![SimOutcome::DuplicateIgnored { op }]
        }
    }

    fn coverage_mut(&mut self, source: SupervisionSource) -> &mut Coverage {
        match source {
            SupervisionSource::Watchdog => &mut self.watchdog,
            SupervisionSource::Testd => &mut self.testd,
        }
    }

    fn heartbeat(&mut self, source: SupervisionSource) -> Vec<SimOutcome> {
        let coverage = self.coverage_mut(source);
        if *coverage == Coverage::Full {
            Vec::new()
        } else {
            *coverage = Coverage::Full;
            vec![SimOutcome::SupervisionRestored { source }]
        }
    }

    fn drop_supervision(&mut self, source: SupervisionSource) -> Vec<SimOutcome> {
        let coverage = self.coverage_mut(source);
        if *coverage == Coverage::Unknown {
            Vec::new()
        } else {
            *coverage = Coverage::Unknown;
            vec![SimOutcome::SupervisionLost { source }]
        }
    }

    fn epoch_move(&mut self, action: PromotionAction, epoch: u64) -> Vec<SimOutcome> {
        self.epoch = epoch;
        match action {
            PromotionAction::Promote | PromotionAction::Cutover => {
                self.generation = self.generation.saturating_add(1);
            }
            PromotionAction::Rollback => {}
        }
        vec![SimOutcome::EpochMoved { epoch }]
    }

    fn shed_load(&mut self, count: u32) -> Vec<SimOutcome> {
        let mut shed = 0_u32;
        let pending: Vec<u32> = self
            .ops
            .iter()
            .filter(|(_, record)| record.status == OpStatus::Pending)
            .map(|(id, _)| *id)
            .collect();
        for id in pending {
            if shed >= count {
                break;
            }
            if let Some(record) = self.ops.get_mut(&id) {
                record.status = OpStatus::Shed;
                shed = shed.saturating_add(1);
            }
        }
        self.mailbox_depth = self.mailbox_depth.saturating_sub(shed);
        self.shed_total = self.shed_total.saturating_add(shed);
        if self.testd == Coverage::Full && shed > 0 {
            self.testd = Coverage::Partial;
        }
        vec![SimOutcome::Shed {
            requested: count,
            shed,
        }]
    }

    fn restart_writer(&mut self) -> Vec<SimOutcome> {
        self.writer_restarts = self.writer_restarts.saturating_add(1);
        self.generation = self.generation.saturating_add(1);
        for record in self.ops.values_mut() {
            if record.status == OpStatus::Pending {
                record.status = OpStatus::Unknown;
            }
        }
        self.mailbox_depth = self.depth_check();
        vec![SimOutcome::WriterRestarted]
    }

    /// Recomputes mailbox depth from operation records.
    #[must_use]
    pub fn depth_check(&self) -> u32 {
        let mut depth = 0_u32;
        for record in self.ops.values() {
            if record.status == OpStatus::Pending || record.status == OpStatus::Committed {
                depth = depth.saturating_add(1);
            }
        }
        depth
    }
}

impl Canonical for OpRecord {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("op-record");
        digest.feed_str(match self.status {
            OpStatus::Pending => "pending",
            OpStatus::Committed => "committed",
            OpStatus::Completed => "completed",
            OpStatus::Cancelled => "cancelled",
            OpStatus::Fenced => "fenced",
            OpStatus::Shed => "shed",
            OpStatus::Unknown => "unknown",
            OpStatus::OldGeneration => "old-generation",
        });
        self.fencing.feed(digest);
        digest.feed_u64(self.generation);
        digest.feed_str(match self.effect {
            EffectClass::Idempotent => "idempotent",
            EffectClass::ExactlyOnce => "exactly-once",
        });
        digest.feed_u32(self.seen_submit);
        digest.feed_u32(self.applied);
        digest.feed_bool(self.acked);
        digest.feed_str(match self.store {
            None => "no-store-record",
            Some(StoreOutcome::Committed) => "committed",
            Some(StoreOutcome::Rejected) => "rejected",
            Some(StoreOutcome::Unknown) => "unknown",
        });
    }
}

impl Canonical for SimState {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("sim-state");
        digest.feed_u64(self.epoch);
        digest.feed_u64(self.generation);
        self.fencing_high_water.feed(digest);
        digest.feed_u64(u64::try_from(self.ops.len()).unwrap_or(u64::MAX));
        for (id, record) in &self.ops {
            digest.feed_u32(*id);
            record.feed(digest);
        }
        digest.feed_u32(self.mailbox_depth);
        digest.feed_u32(self.mailbox_capacity);
        digest.feed_u32(self.shed_total);
        digest.feed_str(match self.watchdog {
            Coverage::Full => "full",
            Coverage::Partial => "partial",
            Coverage::Unknown => "unknown",
        });
        digest.feed_str(match self.testd {
            Coverage::Full => "full",
            Coverage::Partial => "partial",
            Coverage::Unknown => "unknown",
        });
        digest.feed_u32(self.writer_restarts);
    }
}
