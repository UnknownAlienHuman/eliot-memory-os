//! Deterministic scheduler with duplicate, reorder, delay, and loss faults.
//!
//! The [`Scheduler`] owns the logical clock, the seeded [`SimRng`], and one
//! priority queue keyed by delivery tick then sequence. [`Scheduler::submit`]
//! assigns each command a sequence and nonce, applies the first matching
//! [`ScriptedFault`](crate::fault::ScriptedFault), then optionally adds seeded
//! background jitter. [`Scheduler::pop`] delivers entries in tick order and
//! records every delivery, including drops, in the schedule log. Nothing here
//! reads a clock, spawns a task, or touches I/O: the same seed always builds
//! the same schedule.

use std::collections::BTreeMap;

use crate::command::{CommandKind, SimCommand};
use crate::digest::{Canonical, SimDigest};
use crate::event::{DeliveryFault, Tick};
use crate::fault::{FaultPlan, kind_tag};
use crate::rng::SimRng;

/// One envelope in flight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// Submission sequence.
    pub seq: u64,
    /// Per-envelope nonce drawn from the seeded stream. Duplicated copies
    /// share the nonce of their original.
    pub nonce: u64,
    /// Tick at which the envelope becomes deliverable.
    pub deliver_at: Tick,
    /// Command carried.
    pub command: SimCommand,
}

/// One schedule-log entry in delivery order, drops included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
    /// Submission sequence.
    pub seq: u64,
    /// Envelope nonce.
    pub nonce: u64,
    /// Tick of delivery, or of the drop decision for lost envelopes.
    pub tick: Tick,
    /// Fault applied.
    pub fault: DeliveryFault,
    /// Command kind tag.
    pub command_tag: &'static str,
    /// Command carried, for schedule equality checks.
    pub command: SimCommand,
    /// True when the envelope never reached the state machine.
    pub dropped: bool,
}

/// One delivery from [`Scheduler::pop`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    /// Envelope to apply, or to record as dropped.
    pub envelope: Envelope,
    /// Fault applied to this envelope.
    pub fault: DeliveryFault,
    /// True when the envelope never reaches the state machine.
    pub dropped: bool,
}

/// Queued entry: the envelope plus its precomputed fault.
#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedEntry {
    envelope: Envelope,
    fault: DeliveryFault,
}

/// Deterministic delivery scheduler.
#[derive(Clone, Debug)]
pub struct Scheduler {
    now: Tick,
    next_seq: u64,
    queue: BTreeMap<(u64, u64), QueuedEntry>,
    rng: SimRng,
    plan: FaultPlan,
    per_kind_count: BTreeMap<CommandKind, u32>,
    consumed: Vec<bool>,
    log: Vec<DeliveryRecord>,
}

impl Scheduler {
    /// Builds a scheduler for `seed` and `plan`.
    #[must_use]
    pub fn new(seed: u64, plan: FaultPlan) -> Self {
        let consumed = plan.script.iter().map(|_| false).collect();
        Self {
            now: Tick(0),
            next_seq: 0,
            queue: BTreeMap::new(),
            rng: SimRng::new(seed),
            plan,
            per_kind_count: BTreeMap::new(),
            consumed,
            log: Vec::new(),
        }
    }

    /// Returns the current logical tick.
    #[must_use]
    pub const fn now(&self) -> Tick {
        self.now
    }

    /// Returns true when no envelope is in flight.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Returns the schedule log in delivery order.
    #[must_use]
    pub fn log(&self) -> &[DeliveryRecord] {
        &self.log
    }

    /// Submits one command: assigns sequence and nonce, applies the first
    /// matching unconsumed script entry for its kind and occurrence, then
    /// adds seeded background jitter when the plan enables it.
    pub fn submit(&mut self, command: SimCommand) {
        let kind = command.kind();
        let occurrence = self.per_kind_count.get(&kind).copied().unwrap_or(0);
        self.per_kind_count
            .insert(kind, occurrence.saturating_add(1));

        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let nonce = self.rng.next_u64();

        let mut fault = DeliveryFault::Clean;
        let mut delay = 0_u64;
        for (index, entry) in self.plan.script.iter().enumerate() {
            let used = self.consumed.get(index).copied().unwrap_or(true);
            if !used && entry.kind == kind && entry.occurrence == occurrence {
                if let Some(slot) = self.consumed.get_mut(index) {
                    *slot = true;
                }
                fault = entry.fault;
                delay = entry.delay_ticks;
                break;
            }
        }

        let jitter = if self.plan.background_jitter_max_ticks == 0 {
            0
        } else {
            self.rng
                .below(self.plan.background_jitter_max_ticks.saturating_add(1))
        };
        let base = self.now.0.saturating_add(delay).saturating_add(jitter);
        let deliver_at = match fault {
            DeliveryFault::Reordered => Tick(base.saturating_add(delay.max(1))),
            DeliveryFault::Delayed
            | DeliveryFault::Clean
            | DeliveryFault::Duplicated
            | DeliveryFault::Lost => Tick(base),
        };
        let envelope = Envelope {
            seq,
            nonce,
            deliver_at,
            command: command.clone(),
        };
        let tag = kind_tag(kind);
        if fault == DeliveryFault::Lost {
            self.log.push(DeliveryRecord {
                seq,
                nonce,
                tick: self.now,
                fault,
                command_tag: tag,
                command,
                dropped: true,
            });
            return;
        }
        self.queue
            .insert((deliver_at.0, seq), QueuedEntry { envelope, fault });
        if fault == DeliveryFault::Duplicated {
            let copy_seq = self.next_seq;
            self.next_seq = self.next_seq.saturating_add(1);
            self.queue.insert(
                (deliver_at.0, copy_seq),
                QueuedEntry {
                    envelope: Envelope {
                        seq: copy_seq,
                        nonce,
                        deliver_at,
                        command,
                    },
                    fault,
                },
            );
        }
    }

    /// Delivers the next envelope in tick order, advancing the logical
    /// clock. Returns `None` when the queue is drained.
    pub fn pop(&mut self) -> Option<Delivery> {
        let ((tick, _), entry) = self.queue.pop_first()?;
        if tick > self.now.0 {
            self.now = Tick(tick);
        }
        let QueuedEntry { envelope, fault } = entry;
        self.log.push(DeliveryRecord {
            seq: envelope.seq,
            nonce: envelope.nonce,
            tick: self.now,
            fault,
            command_tag: envelope.command.kind_tag(),
            command: envelope.command.clone(),
            dropped: false,
        });
        Some(Delivery {
            envelope,
            fault,
            dropped: false,
        })
    }

    /// Folds the schedule log into `digest` in delivery order.
    pub fn feed_schedule(&self, digest: &mut SimDigest) {
        digest.feed_tag("schedule");
        digest.feed_u64(u64::try_from(self.log.len()).unwrap_or(u64::MAX));
        for record in &self.log {
            record.feed(digest);
        }
    }
}

impl Canonical for DeliveryRecord {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("delivery-record");
        digest.feed_u64(self.seq);
        digest.feed_u64(self.nonce);
        digest.feed_u64(self.tick.0);
        self.fault.feed(digest);
        digest.feed_str(self.command_tag);
        digest.feed_bool(self.dropped);
        self.command.feed(digest);
    }
}

#[cfg(test)]
mod tests {
    use super::Scheduler;
    use crate::command::CommandKind;
    use crate::command::{EffectClass, FencingToken, OpId, SimCommand};
    use crate::event::DeliveryFault;
    use crate::fault::{FaultPlan, ScriptedFault};

    fn submit(op: u32) -> SimCommand {
        SimCommand::Submit {
            op: OpId(op),
            fencing: FencingToken {
                epoch: 1,
                seq: u64::from(op),
            },
            effect: EffectClass::ExactlyOnce,
            generation: 1,
        }
    }

    #[test]
    fn same_seed_builds_same_schedule_with_jitter() {
        let plan = FaultPlan {
            armed: Vec::new(),
            script: Vec::new(),
            background_jitter_max_ticks: 7,
        };
        let mut left = Scheduler::new(1916, plan.clone());
        let mut right = Scheduler::new(1916, plan);
        for op in 0..6 {
            left.submit(submit(op));
            right.submit(submit(op));
        }
        let mut left_ticks = Vec::new();
        while left.pop().is_some() {
            left_ticks.push(left.now());
        }
        let mut right_ticks = Vec::new();
        while right.pop().is_some() {
            right_ticks.push(right.now());
        }
        assert_eq!(left_ticks, right_ticks);
        assert_eq!(left.log(), right.log());
    }

    #[test]
    fn scripted_duplicate_delivers_twice() {
        let plan = FaultPlan {
            armed: vec![crate::fault::Failpoint::SubmitPath],
            script: vec![ScriptedFault {
                kind: CommandKind::Submit,
                occurrence: 0,
                fault: DeliveryFault::Duplicated,
                delay_ticks: 0,
            }],
            background_jitter_max_ticks: 0,
        };
        let mut scheduler = Scheduler::new(1, plan);
        scheduler.submit(submit(9));
        let mut count = 0_u32;
        while scheduler.pop().is_some() {
            count = count.saturating_add(1);
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn scripted_loss_never_reaches_pop() {
        let plan = FaultPlan {
            armed: vec![crate::fault::Failpoint::AckPath],
            script: vec![ScriptedFault {
                kind: CommandKind::Ack,
                occurrence: 0,
                fault: DeliveryFault::Lost,
                delay_ticks: 0,
            }],
            background_jitter_max_ticks: 0,
        };
        let mut scheduler = Scheduler::new(1, plan);
        scheduler.submit(SimCommand::Ack { op: OpId(9) });
        assert!(scheduler.pop().is_none());
        assert_eq!(scheduler.log().len(), 1);
        assert!(scheduler.log()[0].dropped);
    }
}
